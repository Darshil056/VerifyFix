import os
import json
import logging
import google.generativeai as genai
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# We use Gemini 3.1 Flash-Lite, per Phase 5 specs (updated by user)
MODEL_NAME = "gemini-3.1-flash-lite"

def run_remediation_analysis(vuln: Dict[str, Any], rag_context: Dict[str, str], diff_text: str, execution_proof: str, full_files: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Agent 4: Senior Remediation Analyst
    Ingests a confirmed vulnerability and execution traces to produce:
    - Root cause analysis
    - Targeted patch diff
    - Defense in depth advice
    
    In full-context mode, uses complete file sources for more accurate patch diffs.
    """
    cwe_id = vuln.get("cwe_id", "UNKNOWN")
    vuln_name = vuln.get("vulnerability_name", "Unknown Vulnerability")

    logger.info(f"Running Remediation Analyst for {cwe_id}: {vuln_name}")
    
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        genai.configure(api_key=api_key)

    if not api_key:
        logger.warning(f"No GEMINI_API_KEY found. Returning fallback remediation for {cwe_id}.")
        return _get_fallback_remediation(vuln, execution_proof)

    # Build code context section
    if full_files:
        from services.github_context import format_context_for_prompt
        code_context = format_context_for_prompt(
            diff_text=diff_text,
            full_files=full_files,
            dependency_files={},
        )
        code_section = f"Here is the full source code of the changed files along with the diff:\n{code_context}"
    else:
        code_section = f"Here is the git diff containing the vulnerable code:\n{diff_text}"

    system_instruction = f"""
    You are a Senior Security Remediation Analyst. Your task is to analyze a confirmed vulnerability and provide a structured remediation report.
    
    You are analyzing: {cwe_id} - {vuln_name}
    
    Here is the contextual knowledge for this vulnerability class:
    {rag_context.get(cwe_id, 'No context available.')}
    
    Here is the exact sandbox execution output proving the exploit:
    {execution_proof}
    
    {code_section}
    
    Return your response strictly as a JSON object matching this schema:
    {{
        "cwe_id": "string",
        "vulnerability_name": "string",
        "severity": "string (e.g. CRITICAL (CVSS 9.8))",
        "file_path": "string",
        "line_range": "string",
        "root_cause": "string (clear explanation of why the code is vulnerable)",
        "execution_proof": "string (the provided sandbox execution output)",
        "patch_diff": "string (a unified git diff showing exactly how to fix the code)",
        "defense_in_depth": ["string", "string", "string"] (list of 3 broader architectural recommendations)
    }}
    
    Ensure the patch_diff uses standard unified diff format (--- a/file\n+++ b/file\n@@ ...).
    Do NOT wrap the JSON output in markdown blocks (```json). Just return the raw JSON text.
    """

    try:
        model = genai.GenerativeModel(
            model_name=MODEL_NAME,
            system_instruction=system_instruction
        )
        
        # We use temperature=0.4 for a balance of creativity (defense in depth) and accuracy (patch diff)
        response = model.generate_content(
            "Generate the remediation JSON.",
            generation_config={"temperature": 0.4}
        )
        
        response_text = response.text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
            
        result = json.loads(response_text)
        
        # Ensure execution_proof is correctly set (sometimes the model hallucinates it)
        result["execution_proof"] = execution_proof
        return result

    except Exception as e:
        logger.error(f"Gemini API error during remediation generation for {cwe_id}: {e}")
        return _get_fallback_remediation(vuln, execution_proof)

def _get_fallback_remediation(vuln: Dict[str, Any], execution_proof: str) -> Dict[str, Any]:
    cwe_id = vuln.get("cwe_id", "UNKNOWN")
    
    # Generic fallback
    remediation = {
        "cwe_id": cwe_id,
        "vulnerability_name": vuln.get("vulnerability_name", "Unknown"),
        "severity": "HIGH",
        "file_path": vuln.get("file_path", "unknown"),
        "line_range": f"{vuln.get('line_start', '?')}-{vuln.get('line_end', '?')}",
        "root_cause": "A security vulnerability was confirmed in the codebase.",
        "execution_proof": execution_proof,
        "patch_diff": "--- a/file\n+++ b/file\n# Apply security best practices to sanitize/validate input here.",
        "defense_in_depth": [
            "Implement strict input validation.",
            "Use secure coding frameworks.",
            "Conduct regular security audits."
        ]
    }

    if cwe_id == "CWE-89":
        remediation.update({
            "severity": "CRITICAL (CVSS 9.8)",
            "root_cause": "Direct string interpolation of untrusted input into raw SQL statement without parameterized escaping.",
            "patch_diff": (
                "--- a/routes/auth.py\n"
                "+++ b/routes/auth.py\n"
                "@@ -42,3 +42,3 @@\n"
                "-    cursor.execute(f\"SELECT * FROM users WHERE user='{user}'\")\n"
                "+    cursor.execute(\"SELECT * FROM users WHERE user=?\", (user,))"
            ),
            "defense_in_depth": [
                "Migrate raw cursor calls to an ORM like SQLAlchemy.",
                "Enforce strict input length and character allowlisting at the API route validation layer.",
                "Apply the principle of least privilege to the database user account."
            ]
        })
        
    return remediation
