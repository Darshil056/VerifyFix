"""
Phase 4 Unit Tests: Critic Agent & Sandbox Execution
=====================================================

Tests use unittest.mock to avoid real Gemini API calls and Docker/subprocess
execution during CI/CD.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from agents.critic import run_triage_pruning, run_fixture_generation, FALLBACK_FIXTURES
from sandbox.runner import (
    run_fixture,
    _parse_verdict,
    _is_docker_available,
    detect_runtime,
    DOCKER_TIMEOUT_SECONDS,
    PROCESS_TIMEOUT_SECONDS,
)


# ---------------------------------------------------------------------------
# Sample test data
# ---------------------------------------------------------------------------

SAMPLE_VULN = {
    "cwe_id": "CWE-89",
    "vulnerability_name": "SQL Injection",
    "file_path": "routes/auth.py",
    "line_start": 42,
    "line_end": 48,
    "suspect_code": "query = f\"SELECT id FROM users WHERE username='{username}'\"",
    "reasoning": "Unsanitized user variable concatenated into raw SQL string.",
}

SAMPLE_CANDIDATES = [SAMPLE_VULN]

SAMPLE_RAG_CONTEXT = {
    "CWE-89": "SQL Injection is a code injection technique that exploits security vulnerabilities..."
}

SAMPLE_DIFF = (
    "--- a/routes/auth.py\n"
    "+++ b/routes/auth.py\n"
    "+ query = f\"SELECT id FROM users WHERE username='{username}'\"\n"
)


# ===========================================================================
# Critic Triage Tests
# ===========================================================================

class TestTriagePruning:
    """Tests for run_triage_pruning()."""

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"})
    @patch("agents.critic.genai")
    def test_triage_calls_gemini(self, mock_genai):
        """Triage should call Gemini and return parsed JSON."""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        mock_response = MagicMock()
        mock_response.text = json.dumps(SAMPLE_CANDIDATES)
        mock_model.generate_content.return_value = mock_response

        result = run_triage_pruning(SAMPLE_CANDIDATES, SAMPLE_RAG_CONTEXT, SAMPLE_DIFF)

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["cwe_id"] == "CWE-89"
        mock_model.generate_content.assert_called_once()

    @patch.dict("os.environ", {}, clear=True)
    def test_triage_fallback_no_api_key(self):
        """Without API key, triage should return all candidates unmodified."""
        result = run_triage_pruning(SAMPLE_CANDIDATES, SAMPLE_RAG_CONTEXT, SAMPLE_DIFF)
        assert result == SAMPLE_CANDIDATES

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"})
    @patch("agents.critic.genai")
    def test_triage_handles_gemini_error(self, mock_genai):
        """On Gemini API error, triage should return all candidates."""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        mock_model.generate_content.side_effect = Exception("API Error")

        result = run_triage_pruning(SAMPLE_CANDIDATES, SAMPLE_RAG_CONTEXT, SAMPLE_DIFF)
        assert result == SAMPLE_CANDIDATES

    def test_triage_empty_candidates(self):
        """Empty candidates should return empty list."""
        result = run_triage_pruning([], SAMPLE_RAG_CONTEXT, SAMPLE_DIFF)
        assert result == []


# ===========================================================================
# Fixture Generation Tests
# ===========================================================================

class TestFixtureGeneration:
    """Tests for run_fixture_generation()."""

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"})
    @patch("agents.critic.genai")
    def test_generates_fixture_code(self, mock_genai):
        """Fixture generation should return Python code string."""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        mock_response = MagicMock()
        mock_response.text = 'import sqlite3\nprint("[VULNERABILITY_CONFIRMED]")'
        mock_model.generate_content.return_value = mock_response

        result = run_fixture_generation(SAMPLE_VULN, SAMPLE_RAG_CONTEXT, SAMPLE_DIFF)

        assert isinstance(result, str)
        assert len(result) > 0
        mock_model.generate_content.assert_called_once()

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"})
    @patch("agents.critic.genai")
    def test_self_healing_includes_error_traces(self, mock_genai):
        """On retry, error traces should be included in the system prompt."""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        mock_response = MagicMock()
        mock_response.text = 'print("[VULNERABILITY_CONFIRMED]")'
        mock_model.generate_content.return_value = mock_response

        error_trace = "AssertionError: Expected 1 row, got 0"
        result = run_fixture_generation(
            SAMPLE_VULN, SAMPLE_RAG_CONTEXT, SAMPLE_DIFF,
            error_traces=error_trace,
        )

        assert isinstance(result, str)
        # Verify the system instruction included the error trace
        call_args = mock_genai.GenerativeModel.call_args
        system_instruction = call_args[1]["system_instruction"]
        assert error_trace in system_instruction

    @patch.dict("os.environ", {}, clear=True)
    def test_fallback_fixture_for_known_cwe(self):
        """Without API key, should return fallback fixture for CWE-89."""
        result = run_fixture_generation(SAMPLE_VULN, SAMPLE_RAG_CONTEXT, SAMPLE_DIFF)
        assert isinstance(result, str)
        assert "sqlite3" in result
        assert "[VULNERABILITY_CONFIRMED]" in result

    @patch.dict("os.environ", {}, clear=True)
    def test_fallback_fixture_for_unknown_cwe(self):
        """Unknown CWE should get a generic fallback fixture."""
        unknown_vuln = {**SAMPLE_VULN, "cwe_id": "CWE-9999", "vulnerability_name": "Unknown"}
        result = run_fixture_generation(unknown_vuln, SAMPLE_RAG_CONTEXT, SAMPLE_DIFF)
        assert isinstance(result, str)
        assert "CWE-9999" in result

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"})
    @patch("agents.critic.genai")
    def test_strips_markdown_fences(self, mock_genai):
        """Should strip markdown code fences from Gemini output."""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        mock_response = MagicMock()
        mock_response.text = '```python\nprint("[VULNERABILITY_CONFIRMED]")\n```'
        mock_model.generate_content.return_value = mock_response

        result = run_fixture_generation(SAMPLE_VULN, SAMPLE_RAG_CONTEXT, SAMPLE_DIFF)
        assert not result.startswith("```")
        assert not result.endswith("```")


# ===========================================================================
# Sandbox Runner: Verdict Parsing Tests
# ===========================================================================

class TestVerdictParsing:
    """Tests for _parse_verdict()."""

    def test_vulnerability_confirmed(self):
        """Exit 0 with VULNERABILITY_CONFIRMED marker."""
        result = _parse_verdict(
            stdout="[VULNERABILITY_CONFIRMED] SQL injection successful",
            stderr="",
            exit_code=0,
            timed_out=False,
        )
        assert result["verdict"] == "VULNERABILITY_CONFIRMED"
        assert result["timed_out"] is False

    def test_secure(self):
        """Exit 0 with SECURE marker."""
        result = _parse_verdict(
            stdout="[SECURE] Attack was blocked",
            stderr="",
            exit_code=0,
            timed_out=False,
        )
        assert result["verdict"] == "SECURE"

    def test_harness_error_on_crash(self):
        """Non-zero exit code should return HARNESS_ERROR."""
        result = _parse_verdict(
            stdout="",
            stderr="Traceback: SyntaxError line 5",
            exit_code=1,
            timed_out=False,
        )
        assert result["verdict"] == "HARNESS_ERROR"
        assert result["timed_out"] is False
        assert "SyntaxError" in result["stderr"]

    def test_harness_error_on_timeout(self):
        """Timeout should return HARNESS_ERROR (not a separate verdict)."""
        result = _parse_verdict(
            stdout="",
            stderr="",
            exit_code=-1,
            timed_out=True,
        )
        assert result["verdict"] == "HARNESS_ERROR"
        assert result["timed_out"] is True
        assert "timed out" in result["stderr"].lower()

    def test_harness_error_no_verdict_marker(self):
        """Exit 0 but no verdict marker should return HARNESS_ERROR."""
        result = _parse_verdict(
            stdout="Some random output without markers",
            stderr="",
            exit_code=0,
            timed_out=False,
        )
        assert result["verdict"] == "HARNESS_ERROR"


# ===========================================================================
# Sandbox Runner: Execution Tests
# ===========================================================================

class TestSandboxExecution:
    """Tests for run_fixture() with mocked subprocess."""

    @patch("sandbox.runner._is_docker_available", return_value=False)
    @patch("sandbox.runner.subprocess.run")
    def test_process_sandbox_vulnerability_confirmed(self, mock_run, mock_docker):
        """Process sandbox should parse VULNERABILITY_CONFIRMED from stdout."""
        mock_run.return_value = MagicMock(
            stdout="[VULNERABILITY_CONFIRMED] Payload returned 2 rows",
            stderr="",
            returncode=0,
        )

        result = run_fixture("CWE-89_test", 'print("[VULNERABILITY_CONFIRMED] test")')
        assert result["verdict"] == "VULNERABILITY_CONFIRMED"

    @patch("sandbox.runner._is_docker_available", return_value=False)
    @patch("sandbox.runner.subprocess.run")
    def test_process_sandbox_harness_error(self, mock_run, mock_docker):
        """Process sandbox should return HARNESS_ERROR on non-zero exit."""
        mock_run.return_value = MagicMock(
            stdout="",
            stderr="SyntaxError: invalid syntax",
            returncode=1,
        )

        result = run_fixture("CWE-89_test", "invalid python code !!!")
        assert result["verdict"] == "HARNESS_ERROR"
        assert "SyntaxError" in result["stderr"]

    @patch("sandbox.runner._is_docker_available", return_value=False)
    @patch("sandbox.runner.subprocess.run")
    def test_process_sandbox_timeout(self, mock_run, mock_docker):
        """Process sandbox timeout should return HARNESS_ERROR."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="python", timeout=30)

        result = run_fixture("CWE-89_test", "import time; time.sleep(999)")
        assert result["verdict"] == "HARNESS_ERROR"
        assert result["timed_out"] is True

    @patch("sandbox.runner._is_docker_available", return_value=False)
    @patch("sandbox.runner.subprocess.run")
    def test_process_sandbox_secure(self, mock_run, mock_docker):
        """Process sandbox should parse SECURE from stdout."""
        mock_run.return_value = MagicMock(
            stdout="[SECURE] Attack was neutralized",
            stderr="",
            returncode=0,
        )

        result = run_fixture("CWE-89_test", 'print("[SECURE]")')
        assert result["verdict"] == "SECURE"

    def test_detect_runtime_python(self):
        """Should detect python runtime by default."""
        py_res = detect_runtime(file_path="src/views.py")
        assert py_res["language"] == "python"
        assert py_res["fixture_file"] == "fixture.py"

    # =============================================================================
    # [FUTURE EXTENSION: JAVASCRIPT RUNTIME UNIT TESTS]
    # Commented out while JavaScript runtime is staged for future multi-language release.
    # To re-enable when developing JS support, uncomment the tests below:
    #
    # def test_detect_runtime_python_and_js(self):
    #     """Should detect python vs javascript based on extension or code."""
    #     py_res = detect_runtime(file_path="src/views.py")
    #     assert py_res["language"] == "python"
    #     assert py_res["fixture_file"] == "fixture.py"
    #
    #     js_res = detect_runtime(file_path="controllers/auth.js")
    #     assert js_res["language"] == "javascript"
    #     assert js_res["fixture_file"] == "fixture.js"
    #
    # @patch("sandbox.runner._is_docker_available", return_value=False)
    # @patch("sandbox.runner.subprocess.run")
    # def test_process_sandbox_javascript_execution(self, mock_run, mock_docker):
    #     """Should run javascript fixture and parse confirmed vulnerability."""
    #     mock_run.return_value = MagicMock(
    #         stdout="[VULNERABILITY_CONFIRMED] SQLi in Express",
    #         stderr="",
    #         returncode=0,
    #     )
    #
    #     js_code = "console.log('[VULNERABILITY_CONFIRMED] SQLi in Express'); process.exit(0);"
    #     result = run_fixture("CWE-89_js", js_code, language="javascript")
    #     assert result["verdict"] == "VULNERABILITY_CONFIRMED"
    # =============================================================================

    def test_stage_workspace_files(self):
        """Should stage multiple repository files into temporary directory."""
        from sandbox.runner import stage_workspace_files
        import tempfile
        import shutil
        import os

        temp_dir = tempfile.mkdtemp()
        try:
            files = {
                "models/user.py": "class User: pass\n",
                "utils/db.py": "def get_db(): return None\n",
            }
            count = stage_workspace_files(temp_dir, files)
            assert count == 2
            assert os.path.exists(os.path.join(temp_dir, "models", "user.py"))
            assert os.path.exists(os.path.join(temp_dir, "utils", "db.py"))
        finally:
            shutil.rmtree(temp_dir)

    def test_auto_mock_exception_and_types(self):
        """Should allow catching missing exceptions and checking isinstance without TypeError."""
        from sandbox.auto_mock import create_hybrid_mock

        # 1. Catching dynamic exception in try/except
        CustomError = create_hybrid_mock("MissingCustomError")
        caught = False
        try:
            raise CustomError("test error")
        except CustomError:
            caught = True
        assert caught is True

        # 2. isinstance check against dynamic type
        ClientType = create_hybrid_mock("MissingClientType")
        inst = ClientType()
        assert isinstance(inst, ClientType)

        # 3. Decorator passthrough
        dec = create_hybrid_mock("missing_decorator")
        @dec(param="test")
        def sample_func():
            return 42

        assert sample_func() == 42


# ===========================================================================
# Integration: Retry Logic Tests
# ===========================================================================

class TestRetryLogic:
    """Tests verifying the retry loop behavior with sandbox results."""

    def test_harness_error_triggers_retry(self):
        """HARNESS_ERROR in docker_status should trigger retry in should_retry()."""
        from agents.graph import should_retry
        state = {
            "docker_status": {"CWE-89_sql_injection": "HARNESS_ERROR"},
            "retry_count": 0,
        }
        assert should_retry(state) == "retry_critic"

    def test_vulnerability_confirmed_proceeds(self):
        """VULNERABILITY_CONFIRMED should proceed to remediation."""
        from agents.graph import should_retry
        state = {
            "docker_status": {"CWE-89_sql_injection": "VULNERABILITY_CONFIRMED"},
            "retry_count": 0,
        }
        assert should_retry(state) == "proceed_to_remediation"

    def test_max_retries_exceeded(self):
        """After 5 retries, should proceed even with HARNESS_ERROR."""
        from agents.graph import should_retry, MAX_RETRIES
        state = {
            "docker_status": {"CWE-89_sql_injection": "HARNESS_ERROR"},
            "retry_count": MAX_RETRIES,
        }
        assert should_retry(state) == "proceed_to_remediation"

    def test_timeout_triggers_retry(self):
        """Timeout (stored as HARNESS_ERROR) should also trigger retry."""
        from agents.graph import should_retry
        state = {
            "docker_status": {"CWE-89_sql_injection": "HARNESS_ERROR"},
            "retry_count": 1,
        }
        assert should_retry(state) == "retry_critic"
