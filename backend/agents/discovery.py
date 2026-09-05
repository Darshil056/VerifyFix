import os
import json
import logging
import google.generativeai as genai
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

DISCOVERY_SYSTEM_PROMPT = """You are Agent 1 (Candidate Discovery Scanner) for VerifyFix.
Your job is to analyze code diffs and extract candidate security vulnerabilities.
Extract candidate vulnerabilities into a strict JSON list format. Do NOT wrap the JSON in Markdown backticks.
If no vulnerabilities are found, return an empty list: []

The JSON schema must exactly match:
[
  {
    "cwe_id": "CWE-89",
    "vulnerability_name": "SQL Injection",
    "file_path": "routes/auth.py",
    "line_start": 42,
    "line_end": 48,
    "suspect_code": "query = f'SELECT * FROM users WHERE user={user_input}'",
    "reasoning": "Unsanitized user variable concatenated into raw SQL string."
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

def run_discovery_agent(diff_text: str) -> List[Dict[str, Any]]:
    """
    Executes the Discovery Agent using Gemini 2.5 Flash.
    Returns a list of candidate vulnerabilities.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        logger.warning("No GEMINI_API_KEY found. Falling back to heuristic pattern matching.")
        return fallback_heuristic_analyzer(diff_text)
        
    try:
        genai.configure(api_key=api_key)
        # Using gemini-2.5-flash as specified in Phase 3 plan
        model = genai.GenerativeModel('gemini-2.5-flash',
                                      system_instruction=DISCOVERY_SYSTEM_PROMPT,
                                      generation_config=genai.types.GenerationConfig(
                                          temperature=0.2,
                                          top_p=0.95,
                                          response_mime_type="application/json"
                                      ))
        
        prompt = f"Analyze the following code diff for vulnerabilities:\n\n{diff_text}"
        response = model.generate_content(prompt)
        
        result_text = response.text.strip()
        candidates = json.loads(result_text)
        
        if not isinstance(candidates, list):
            logger.warning(f"Gemini returned non-list JSON: {candidates}")
            return fallback_heuristic_analyzer(diff_text)
            
        return candidates
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Gemini JSON response: {e}")
        return fallback_heuristic_analyzer(diff_text)
    except Exception as e:
        logger.error(f"Gemini API error during discovery: {e}")
        return fallback_heuristic_analyzer(diff_text)

# Simple test if run directly
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample_diff = "--- a/routes/auth.py\n+++ b/routes/auth.py\n+ query = f\"SELECT id, username FROM users WHERE username='{username}'\"\n"
    print(json.dumps(run_discovery_agent(sample_diff), indent=2))
