"""
Phase 5 Unit Tests: Report Generator and API Endpoint
=====================================================
"""
import pytest
import io
from docx import Document
from unittest.mock import patch, MagicMock
from services.report_generator import generate_docx_report
from agents.remediation import run_remediation_analysis

# --- Test Data ---

MOCK_VULN = {
    "cwe_id": "CWE-89",
    "vulnerability_name": "SQL Injection",
    "file_path": "routes/auth.py",
    "line_start": 42,
    "line_end": 48
}

MOCK_STATE = {
    "scan_id": "test-123",
    "repo_owner": "test-org",
    "repo_name": "test-repo",
    "completed_at": "2026-09-06T12:00:00Z",
    "candidate_vulns": [MOCK_VULN, {"cwe_id": "CWE-99"}],
    "pruned_vulns_count": 1,
    "docker_status": {"CWE-89_sql_injection": "VULNERABILITY_CONFIRMED"},
    "summary": {
        "confirmed_vulnerabilities": 1,
        "secure_findings": 0,
        "retry_count": 0
    },
    "final_remediations": [
        {
            "cwe_id": "CWE-89",
            "vulnerability_name": "SQL Injection",
            "severity": "CRITICAL (CVSS 9.8)",
            "file_path": "routes/auth.py",
            "line_range": "42-48",
            "root_cause": "Direct interpolation of untrusted input.",
            "execution_proof": "[VULNERABILITY_CONFIRMED] Exploit successful",
            "patch_diff": "--- a\n+++ b\n+ secure_code()",
            "defense_in_depth": ["Use ORM", "Validate input"]
        }
    ]
}

# --- Tests ---

class TestReportGenerator:
    """Tests for generate_docx_report()."""

    def test_generates_valid_docx(self):
        """Should generate a valid docx file that can be read by python-docx."""
        stream = generate_docx_report(MOCK_STATE)
        
        assert isinstance(stream, io.BytesIO)
        assert stream.getbuffer().nbytes > 0
        
        # Read it back
        doc = Document(stream)
        
        # Verify it has paragraphs and tables
        assert len(doc.paragraphs) > 0
        assert len(doc.tables) > 0
        
        # Verify specific content
        full_text = "\n".join([p.text for p in doc.paragraphs])
        assert "VerifyFix AI Vulnerability Validation Report" in full_text
        assert "test-org/test-repo" in full_text
        assert "CWE-89" in full_text
        assert "Direct interpolation of untrusted input." in full_text
        assert "Use ORM" in full_text

    def test_handles_empty_remediations(self):
        """Should handle states with no remediations."""
        empty_state = {**MOCK_STATE, "final_remediations": []}
        stream = generate_docx_report(empty_state)
        
        doc = Document(stream)
        full_text = "\n".join([p.text for p in doc.paragraphs])
        assert "No confirmed vulnerabilities requiring remediation were found." in full_text


class TestRemediationAgent:
    """Tests for run_remediation_analysis()."""

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"})
    @patch("agents.remediation.genai")
    def test_remediation_calls_gemini(self, mock_genai):
        """Should call Gemini and return parsed JSON."""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        mock_response = MagicMock()
        mock_response.text = '```json\n{"cwe_id": "CWE-89", "patch_diff": "test"}\n```'
        mock_model.generate_content.return_value = mock_response

        result = run_remediation_analysis(
            MOCK_VULN,
            rag_context={"CWE-89": "test"},
            diff_text="diff",
            execution_proof="proof"
        )

        assert isinstance(result, dict)
        assert result["cwe_id"] == "CWE-89"
        assert result["patch_diff"] == "test"
        mock_model.generate_content.assert_called_once()

    @patch.dict("os.environ", {}, clear=True)
    def test_remediation_fallback_no_api_key(self):
        """Without API key, should return fallback remediation."""
        result = run_remediation_analysis(
            MOCK_VULN,
            rag_context={},
            diff_text="",
            execution_proof="test-proof"
        )
        assert result["cwe_id"] == "CWE-89"
        assert result["severity"] == "CRITICAL (CVSS 9.8)"
        assert "test-proof" in result["execution_proof"]
