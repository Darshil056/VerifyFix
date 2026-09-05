# Phase 5 Implementation Plan: Senior Analyst Remediation & Word Report (.docx)

## 1. Overview & Objectives
Phase 5 turns verified vulnerabilities into remediation artifacts:
1. **Agent 4 (Senior Remediation Analyst):** Ingests only `VULNERABILITY_CONFIRMED` findings and execution traces to produce root-cause explanations, targeted git diff patches, and defense-in-depth advice (`temperature=0.4`).
2. **Report Generation Service (`python-docx`):** Compiles an executive-level Microsoft Word (.docx) security audit document containing scan metrics, execution proof, and patch diffs.
3. **Download Endpoint:** Serves the generated `.docx` document to the frontend via `GET /api/report/download?scan_id=<ID>`.

---

## 2. Technical Specifications

### 2.1 Senior Remediation Analyst (`backend/agents/remediation.py`)
- **Input:** Filtered list of verified items from `state["docker_status"]` where status == `VULNERABILITY_CONFIRMED`.
- **Output Schema**:
```python
{
    "cwe_id": "CWE-89",
    "vulnerability_name": "SQL Injection in User Authentication",
    "severity": "CRITICAL (CVSS 9.8)",
    "file_path": "routes/auth.py",
    "line_range": "42-48",
    "root_cause": "Direct string interpolation of untrusted input 'username' into raw SQL statement without parameterized escaping.",
    "execution_proof": "[VULNERABILITY_CONFIRMED] Injected \"' OR 1=1 --\" bypassed credentials check and fetched admin record id=1.",
    "patch_diff": """--- a/routes/auth.py\n+++ b/routes/auth.py\n@@ -42,3 +42,3 @@\n-    cursor.execute(f"SELECT * FROM users WHERE user='{user}'")\n+    cursor.execute("SELECT * FROM users WHERE user=?", (user,))""",
    "defense_in_depth": [
        "Migrate raw cursor calls to an ORM like SQLAlchemy.",
        "Enforce strict input length and character allowlisting at the API route validation layer.",
        "Apply the principle of least privilege to the database user account."
    ]
}
```

### 2.2 Word Document Generator (`backend/services/report_generator.py`)
Utilizes `python-docx` to format a structured document:
- **Header & Cover Section**:
  - Title: **VerifyFix AI Vulnerability Validation Report**
  - Scanned Target: Repository name, branch, scan timestamp.
  - Authors: **Darshil Mendapara & Dhruv Parsana**
- **Executive Summary Callout Box**:
  - Total Candidates Flagged
  - False Alarms Pruned by Critic
  - Verified Confirmed Exploits
  - Self-Healing Cycles Triggered
- **Detailed Findings Table**:
  - Columns: `#`, `CWE ID`, `Vulnerability`, `Severity`, `Affected File & Lines`, `Exploit Status`.
- **Execution Proof Details**:
  - Exact test payload utilized.
  - Execution runtime output from Docker/sandbox harness.
- **Senior Remediation & Git Diffs**:
  - High-contrast formatted code blocks displaying git diffs and code patch instructions.
  - Defense-in-depth recommendations.

### 2.3 Download Endpoint (`backend/app.py`)
- Endpoint: `GET /api/report/download?scan_id=<ID>`
- Response:
  - Header: `Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document`
  - Header: `Content-Disposition: attachment; filename="VerifyFix_Audit_Report_<ID>.docx"`

---

## 3. Implementation Steps

1. **Implement Remediation Agent (`backend/agents/remediation.py`)**:
   - Construct prompt for Gemini 2.5 Flash / fallback synthesizer.
   - Format diff patches and structured remediation recommendations.
2. **Implement Report Generator (`backend/services/report_generator.py`)**:
   - Create document layout, table styling, headings, and code block formatting.
   - Embed scan metadata and author credits.
3. **Register Download Route (`backend/app.py`)**:
   - Stream document bytes using Flask `send_file`.
4. **Create Test Suite (`backend/tests/test_report.py`)**:
   - Test `.docx` document generation and verify all required sections and tables exist.

---

## 4. Verification & Testing

```bash
# Run report generator test suite
cd backend
python -m pytest tests/test_report.py -v

# Generate sample document directly
python -c "from services.report_generator import generate_docx_report; generate_docx_report({'scan_id': 'test'}, 'test_report.docx'); print('Generated test_report.docx')"
```
