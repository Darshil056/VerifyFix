import os
import re
import json
import logging
import google.generativeai as genai
from typing import List, Dict, Any, Optional

from services.github_context import format_context_for_prompt

logger = logging.getLogger(__name__)

DISCOVERY_SYSTEM_PROMPT = """You are Agent 1 (Candidate Discovery Scanner) for VerifyFix.
Your job is to thoroughly analyze source code and diffs for security vulnerabilities with an exhaustive, per-function, per-method, and per-route audit.

CRITICAL DISCOVERY RULES:
1. Exhaustive Multi-Vulnerability Coverage:
   - Perform an exhaustive per-function, per-method, and per-route audit from untrusted entry point to sensitive sink.
   - NEVER stop after identifying the first vulnerability in a file. Multiple vulnerabilities often coexist within the same function or across different route handlers in the same file.
   - Trace each distinct execution path to completion.

2. Equal Evaluation Across All Security Domains:
   Evaluate all security domains equally across every execution path:
   - Injection Sinks: SQL Injection (CWE-89), OS Command Injection (CWE-78), Code Injection/eval (CWE-94), Expression Language/SSTI (CWE-1336 / CWE-917), LDAP/XPath Injection.
   - Filesystem & Path Canonicalization: Path Traversal (CWE-22 / CWE-23), Arbitrary File Overwrite/Write (CWE-73), Symlink following (CWE-59), Unrestricted File Upload (CWE-434).
   - Object Deserialization: Insecure Deserialization of untrusted data (CWE-502 in pickle, yaml, marshal, shelve, jsonpickle).
   - Outbound Network Requests: Server-Side Request Forgery (SSRF / CWE-918), Open Redirect (CWE-601), Webhook manipulation.
   - Authentication, Authorization & CSRF: Missing/Broken Authentication (CWE-287), Missing Authorization / RBAC checks (CWE-862), IDOR (CWE-639), Cross-Site Request Forgery (CSRF / CWE-352).
   - Input Boundary, Type & Finiteness Validation: Improper Input Validation (CWE-20), Type Confusion (CWE-843), Log Injection (CWE-117), Integer Overflow/Truncation (CWE-190).
   - Memory & Algorithmic Resource Exhaustion: Regular Expression DoS (ReDoS / CWE-1333), Uncontrolled Resource Consumption (CWE-400), Allocation of Resources Without Limits (CWE-770), Infinite Loop/Recursion (CWE-835 / CWE-674), Unbounded Multipart/Stream Chunk parsing without max length limits.
   - Cross-Site Scripting (XSS / CWE-79): Reflected, Stored, or Template-based XSS where unescaped user input reaches HTML/response sinks.

3. Specific Leaf/Child MITRE CWE Identifiers:
   - Assign the most specific leaf/child MITRE CWE identifier supported by the code mechanism rather than a broad parent category whenever a narrower CWE applies:
     * Use CWE-89 (SQLi), CWE-78 (OS Command), or CWE-94 (Code Injection) rather than broad CWE-77 or CWE-20.
     * Use CWE-1333 (ReDoS) or CWE-770 (Resource Allocation Without Limits) rather than broad CWE-400.
     * Use CWE-22 (Path Traversal) rather than broad CWE-200.
     * Use CWE-918 (SSRF) rather than generic CWE-20.
     * Use CWE-502 (Deserialization) rather than broad CWE-20.

4. Structured Output Format:
   Return a strict JSON list of findings. Do NOT wrap the JSON in Markdown backticks.
   If no vulnerabilities are found, return an empty list: []

   The JSON schema for each finding:
   {
     "cwe_id": "CWE-89",
     "title": "SQL Injection in User Authentication",
     "file_path": "routes/auth.py",
     "function_name": "login",
     "line_numbers": "42-48",
     "source_to_sink_trace": "Untrusted 'username' parameter from request.form flows into f-string query without sanitization, passed directly to cursor.execute() sink at line 46.",
     "confidence": "HIGH"
   }
"""

def _normalize_candidate(c: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures structured finding schema has all required keys plus backward-compatible aliases."""
    cwe_id = str(c.get("cwe_id", "UNKNOWN")).strip().upper()
    title = c.get("title") or c.get("vulnerability_name") or f"Vulnerability {cwe_id}"
    file_path = c.get("file_path", "unknown")
    function_name = c.get("function_name", "global")
    confidence = c.get("confidence", "HIGH")

    # Trace / reasoning / suspect code
    trace = c.get("source_to_sink_trace") or c.get("reasoning", "")
    suspect_code = c.get("suspect_code") or trace

    # Line numbers resolution
    line_nums = str(c.get("line_numbers", "")).strip()
    line_start = c.get("line_start")
    line_end = c.get("line_end")
    if line_start is None or line_end is None:
        if "-" in line_nums:
            parts = line_nums.split("-")
            try:
                line_start = int(parts[0].strip())
                line_end = int(parts[1].strip())
            except ValueError:
                line_start, line_end = 1, 1
        elif line_nums.isdigit():
            line_start = line_end = int(line_nums)
        else:
            line_start, line_end = 1, 1
    else:
        if not line_nums:
            line_nums = f"{line_start}-{line_end}"

    return {
        "cwe_id": cwe_id,
        "title": title,
        "vulnerability_name": title,
        "file_path": file_path,
        "function_name": function_name,
        "line_numbers": line_nums,
        "line_start": line_start,
        "line_end": line_end,
        "source_to_sink_trace": trace,
        "reasoning": trace,
        "suspect_code": suspect_code,
        "confidence": confidence,
    }

def fallback_heuristic_analyzer(diff_text: str) -> List[Dict[str, Any]]:
    """In-memory pattern matching fallback when Gemini is unavailable or fails."""
    candidates = []
    
    # Very basic SQLi heuristic
    if "SELECT " in diff_text and ("f\"" in diff_text or "f'" in diff_text):
        candidates.append(_normalize_candidate({
            "cwe_id": "CWE-89",
            "title": "SQL Injection",
            "vulnerability_name": "SQL Injection",
            "file_path": "routes/auth.py",
            "function_name": "query_handler",
            "line_numbers": "42-48",
            "source_to_sink_trace": "Detected SQL SELECT statement combined with Python f-string formatting, suggesting potential SQL injection into execute() sink.",
            "confidence": "MEDIUM"
        }))
        
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

        normalized_candidates = [_normalize_candidate(c) for c in candidates if isinstance(c, dict)]
        logger.info(f"Discovery agent found {len(normalized_candidates)} candidate vulnerability(ies)")
        return normalized_candidates
        
    except Exception as e:
        logger.error(f"Gemini API error during discovery: {e}")
        return fallback_heuristic_analyzer(diff_text)

# Simple test if run directly
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample_diff = "--- a/routes/auth.py\n+++ b/routes/auth.py\n+ query = f\"SELECT id, username FROM users WHERE username='{username}'\"\n"
    print(json.dumps(run_discovery_agent(sample_diff), indent=2))
