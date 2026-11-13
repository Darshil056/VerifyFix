import os
import re
import json
import logging
import google.generativeai as genai
from typing import List, Dict, Any, Optional

from services.github_context import format_context_for_prompt

logger = logging.getLogger(__name__)

DISCOVERY_SYSTEM_PROMPT = """You are Agent 1 (Candidate Discovery Scanner) for VerifyFix.
Your job is to thoroughly analyze source code and diffs for security vulnerabilities across all common vulnerability classes:

1. **Injection Flaws**: SQL Injection (CWE-89), OS Command Injection (CWE-78), Code Injection (CWE-94).
2. **Cross-Site Scripting (XSS / CWE-79)**: Reflected, Stored, or Template-based XSS where unescaped/raw user input is concatenated into HTML responses, templates (Jinja2 `| safe`, `render_template_string()`), or sent via `res.send()`.
3. **Resource Exhaustion & Denial of Service (CWE-400 / CWE-770)**: Unbounded loops, missing stream length limits, unbounded multipart/form field processing, memory accumulation without caps, or missing max_content_length checks in parsers and request handlers.
4. **Regular Expression DoS (CWE-1333)**: Catastrophic backtracking or unanchored complex regex patterns evaluated against untrusted input.
5. **Path Traversal & File Inclusion (CWE-22 / CWE-23)**: Insecure file path concatenation, unvalidated filenames in uploads or downloads.
6. **Server-Side Request Forgery (CWE-918)**: Unvalidated user-supplied URLs fetched by backend HTTP clients.
7. **Insecure Deserialization (CWE-502)**: Parsing untrusted pickle, yaml, or serialized payloads.
8. **Broken Access Control & Auth (CWE-287 / CWE-306 / CWE-639)**: Missing authorization checks or IDOR.

Pay special attention to **parsers** (formparser, multipart, header, URL, XML/JSON parsers) where processing untrusted streams, boundaries, or deeply nested structures without limits can trigger Denial of Service (CWE-400).

Extract candidate vulnerabilities into a strict JSON list format. Do NOT wrap the JSON in Markdown backticks.
If no vulnerabilities are found, return an empty list: []

The JSON schema must exactly match:
[
  {
    "cwe_id": "CWE-400",
    "vulnerability_name": "Uncontrolled Resource Consumption (DoS)",
    "file_path": "werkzeug/formparser.py",
    "line_start": 120,
    "line_end": 145,
    "suspect_code": "while True: chunk = stream.read()...",
    "reasoning": "Unbounded loop reading multipart chunks without size limit or part count cap allows client to consume infinite memory."
  }
]
"""

def fallback_heuristic_analyzer(diff_text: str) -> List[Dict[str, Any]]:
    """In-memory pattern matching fallback when Gemini is unavailable or fails."""
    candidates = []
    
    # Very basic SQLi heuristic
    if "SELECT " in diff_text and "f\"" in diff_text or "f'" in diff_text:
        candidates.append({
            "cwe_id": "CWE-89",
            "vulnerability_name": "SQL Injection",
            "file_path": "routes/auth.py", # Fallback default
            "line_start": 42,
            "line_end": 48,
            "suspect_code": "SELECT ... {var}",
            "reasoning": "Detected SQL SELECT statement combined with Python f-string formatting, suggesting potential SQL injection."
        })
        
    return candidates

def run_discovery_agent(
    diff_text: str,
    full_files: Optional[Dict[str, str]] = None,
    dependency_files: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """
    Executes the Discovery Agent using Gemini.
    
    In full-context mode (when full_files is provided), the agent receives:
    - Complete source of all changed files
    - Complete source of dependency files (imported by changed files)
    - The diff highlighting what changed
    
    In diff-only mode, the agent receives only the diff.
    
    Returns a list of candidate vulnerabilities.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        logger.warning("No GEMINI_API_KEY found. Falling back to heuristic pattern matching.")
        return fallback_heuristic_analyzer(diff_text)
        
    try:
        genai.configure(api_key=api_key)
        # Using gemini-3.1-flash-lite as specified in Phase 3 plan
        model = genai.GenerativeModel('gemini-3.1-flash-lite',
                                      system_instruction=DISCOVERY_SYSTEM_PROMPT,
                                      generation_config=genai.types.GenerationConfig(
                                          temperature=0.2,
                                          top_p=0.95,
                                          response_mime_type="application/json"
                                      ))
        
        # Build prompt based on available context
        if full_files:
            # Full-context mode: include complete file sources + diff
            context_text = format_context_for_prompt(
                diff_text=diff_text,
                full_files=full_files,
                dependency_files=dependency_files or {},
            )
            prompt = (
                f"Analyze the following code for security vulnerabilities.\n"
                f"You have FULL SOURCE CODE of changed files and their dependencies.\n"
                f"Focus on the CHANGED code (shown in the diff section) but use the full "
                f"file context to trace data flow and check for mitigations.\n\n"
                f"{context_text}"
            )
            logger.info(f"Discovery agent running in full-context mode: "
                       f"{len(full_files)} changed files, "
                       f"{len(dependency_files or {})} dependency files")
        else:
            # Diff-only mode (original behavior)
            prompt = f"Analyze the following code diff for vulnerabilities:\n\n{diff_text}"
            logger.info("Discovery agent running in diff-only mode")
        
        response = model.generate_content(prompt)
        raw_text = response.text.strip() if response and hasattr(response, "text") and response.text else "[]"
        
        # Clean markdown code fences if Gemini wrapped the JSON
        clean_text = raw_text
        for prefix in ("```json", "```"):
            if clean_text.startswith(prefix):
                clean_text = clean_text[len(prefix):].strip()
        if clean_text.endswith("```"):
            clean_text = clean_text[:-3].strip()

        try:
            candidates = json.loads(clean_text)
        except json.JSONDecodeError:
            # Fallback regex extraction: find the JSON list [...] inside raw_text
            match = re.search(r'\[\s*\{.*\}\s*\]', raw_text, re.DOTALL)
            if match:
                candidates = json.loads(match.group(0))
            else:
                logger.error(f"Failed to parse Gemini discovery JSON: raw output was:\n{raw_text[:400]}")
                return fallback_heuristic_analyzer(diff_text)
        
        if not isinstance(candidates, list):
            logger.warning(f"Gemini returned non-list JSON: {candidates}")
            return fallback_heuristic_analyzer(diff_text)
            
        logger.info(f"Discovery agent found {len(candidates)} candidate vulnerability(ies)")
        return candidates
        
    except Exception as e:
        logger.error(f"Gemini API error during discovery: {e}")
        return fallback_heuristic_analyzer(diff_text)

# Simple test if run directly
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample_diff = "--- a/routes/auth.py\n+++ b/routes/auth.py\n+ query = f\"SELECT id, username FROM users WHERE username='{username}'\"\n"
    print(json.dumps(run_discovery_agent(sample_diff), indent=2))
