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
        """After 3 retries, should proceed even with HARNESS_ERROR."""
        from agents.graph import should_retry
        state = {
            "docker_status": {"CWE-89_sql_injection": "HARNESS_ERROR"},
            "retry_count": 3,
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
