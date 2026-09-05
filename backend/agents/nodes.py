"""
VerifyFix DAG Node Handlers
============================

Each function in this module represents a single node in the VerifyFix
execution graph.  Every node:

    1. Receives the current ``VerifyFixState``
    2. Performs its work (stub/simulation in Phase 2; real logic in later phases)
    3. Returns the mutated state
    4. Yields SSE-compatible event dicts for real-time streaming

Phase 2 provides realistic *stub* implementations that simulate timing and
produce representative output so the SSE streaming pipeline and DAG executor
can be tested end-to-end.  Later phases will swap in the real LLM / RAG /
Docker integrations without changing the node contract.
"""

import time
import logging
from datetime import datetime, timezone
from typing import Generator, Dict, Any

from agents.state import VerifyFixState
from agents.discovery import run_discovery_agent
from rag.chroma_service import ChromaService

logger = logging.getLogger("verifyfix.nodes")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    """Current UTC ISO timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _emit_node_update(step: str, status: str) -> Dict[str, Any]:
    """Create a ``node_update`` SSE event payload."""
    return {
        "event": "node_update",
        "data": {"step": step, "status": status, "timestamp": _ts()},
    }


def _emit_log(message: str) -> Dict[str, Any]:
    """Create a ``log`` SSE event payload."""
    return {
        "event": "log",
        "data": {"message": message, "timestamp": _ts()},
    }


def _emit_state_delta(delta: Dict[str, Any]) -> Dict[str, Any]:
    """Create a ``state_delta`` SSE event payload."""
    return {
        "event": "state_delta",
        "data": delta,
    }


# ---------------------------------------------------------------------------
# Node 1: GitHub Ingest
# ---------------------------------------------------------------------------

def node_github_ingest(state: VerifyFixState) -> Generator[Dict[str, Any], None, VerifyFixState]:
    """
    Validates and ingests the repository context.
    In future phases this will fetch the actual diff from GitHub API.
    """
    step = "GITHUB_INGEST"
    state["execution_step"] = step
    state["logs"].append(f"[GitHub Ingest] Starting ingest for {state['repo_owner']}/{state['repo_name']}@{state['branch_name']}")

    yield _emit_node_update(step, "running")
    yield _emit_log(f"[GitHub Ingest] Fetching diff for {state['repo_owner']}/{state['repo_name']} branch: {state['branch_name']}")

    # Simulate network latency for diff retrieval
    time.sleep(0.5)

    # If no diff was provided, use a demo diff
    if not state.get("target_diff"):
        state["target_diff"] = (
            "diff --git a/routes/auth.py b/routes/auth.py\n"
            "index e69de29..b234567 100644\n"
            "--- a/routes/auth.py\n"
            "+++ b/routes/auth.py\n"
            "@@ -40,9 +40,11 @@ def login_user():\n"
            "     username = request.json.get(\"username\")\n"
            "     password = request.json.get(\"password\")\n"
            "\n"
            "+    # Vulnerable direct SQL concatenation without parameterized queries\n"
            "+    query = f\"SELECT id, username, role FROM users WHERE username='{username}'\"\n"
            "     cursor = db.cursor()\n"
            "-    cursor.execute(\"SELECT id, username FROM users WHERE username=?\", (username,))\n"
            "+    cursor.execute(query)\n"
            "     user = cursor.fetchone()\n"
            "     if user:\n"
            "         return jsonify({\"status\": \"success\", \"user\": user[1]})\n"
            "     return jsonify({\"status\": \"unauthorized\"}), 401\n"
        )
        state["logs"].append("[GitHub Ingest] No diff provided — loaded demo vulnerable diff")
        yield _emit_log("[GitHub Ingest] No diff provided — loaded demo vulnerable diff (SQL injection in auth.py)")

    diff_lines = len(state["target_diff"].splitlines())
    state["logs"].append(f"[GitHub Ingest] Diff loaded: {diff_lines} lines")

    yield _emit_log(f"[GitHub Ingest] Diff loaded successfully: {diff_lines} lines")
    yield _emit_state_delta({"execution_step": step, "target_diff_lines": diff_lines})
    yield _emit_node_update(step, "completed")

    return state


# ---------------------------------------------------------------------------
# Node 2: Discovery Agent (Agent 1)
# ---------------------------------------------------------------------------

def node_discovery(state: VerifyFixState) -> Generator[Dict[str, Any], None, VerifyFixState]:
    """
    Agent 1: Candidate vulnerability discovery scanner.
    Uses Gemini 2.5 Flash with temperature=0.2.
    Phase 2 stub returns representative candidate vulnerabilities.
    """
    step = "DISCOVERY"
    state["execution_step"] = step
    state["logs"].append("[Discovery Agent] Scanning diff for candidate vulnerabilities...")

    yield _emit_node_update(step, "running")
    yield _emit_log("[Discovery Agent] Initializing Gemini 2.5 Flash candidate scanner (temperature=0.2)")

    # Simulate LLM inference time
    time.sleep(1.0)

    yield _emit_log("[Discovery Agent] Analysing code patterns against CWE taxonomy...")
    time.sleep(0.5)

    # Call real Gemini agent
    state["candidate_vulns"] = run_discovery_agent(state["target_diff"])

    vuln_count = len(state["candidate_vulns"])
    cwe_ids = [v["cwe_id"] for v in state["candidate_vulns"]]
    state["logs"].append(f"[Discovery Agent] Found {vuln_count} candidate vulnerabilities: {', '.join(cwe_ids)}")

    yield _emit_log(f"[Discovery Agent] Identified {vuln_count} candidate vulnerabilities: {', '.join(cwe_ids)}")
    yield _emit_state_delta({
        "execution_step": step,
        "candidate_vulns": state["candidate_vulns"],
    })
    yield _emit_node_update(step, "completed")

    return state


# ---------------------------------------------------------------------------
# Node 3: RAG Context Enrichment (Layer 2)
# ---------------------------------------------------------------------------

def node_rag(state: VerifyFixState) -> Generator[Dict[str, Any], None, VerifyFixState]:
    """
    Layer 2: ChromaDB-based RAG context enrichment.
    Queries ChromaDB with MITRE CWE vectors using Gemini 2.5 Flash embeddings.
    Phase 2 stub provides representative threat intelligence context.
    """
    step = "RAG"
    state["execution_step"] = step
    state["logs"].append("[RAG Engine] Enriching candidate vulnerabilities with threat intelligence...")

    yield _emit_node_update(step, "running")
    yield _emit_log("[RAG Engine] Querying ChromaDB vector store for CWE documentation (temperature=0.1)")

    time.sleep(0.8)

    # Initialize RAG and fetch context for each CWE
    chroma = ChromaService()
    state["rag_context"] = {}
    
    unique_cwes = list(set([v["cwe_id"] for v in state.get("candidate_vulns", [])]))
    
    for cwe_id in unique_cwes:
        # Index it if not present (this scrapes MITRE on demand)
        chroma.index_cwe(cwe_id)
        
        # Query it
        results = chroma.query_cwe(cwe_id, n_results=1)
        if results:
            state["rag_context"][cwe_id] = results[0]["context"]
        else:
            state["rag_context"][cwe_id] = f"No threat intelligence found for {cwe_id}"

    rag_keys = list(state["rag_context"].keys())
    state["logs"].append(f"[RAG Engine] Retrieved context for: {', '.join(rag_keys)}")

    yield _emit_log(f"[RAG Engine] Retrieved MITRE threat intelligence for: {', '.join(rag_keys)}")
    yield _emit_state_delta({
        "execution_step": step,
        "rag_context_keys": rag_keys,
    })
    yield _emit_node_update(step, "completed")

    return state


# ---------------------------------------------------------------------------
# Node 4: Critic Agent (Triage & Fixture Generation)
# ---------------------------------------------------------------------------

def node_critic(state: VerifyFixState) -> Generator[Dict[str, Any], None, VerifyFixState]:
    """
    Agent 3: Critic triage and test fixture generator.
    Phase I: Prune false positives based on framework context.
    Phase II: Generate isolated test harness code via Gemini 2.5 Flash (temperature=0.0).
    Phase 2 stub simulates both phases.
    """
    step = "CRITIC"
    state["execution_step"] = step
    is_retry = state.get("retry_count", 0) > 0
    retry_label = f" (retry #{state['retry_count']})" if is_retry else ""
    state["logs"].append(f"[Critic Agent] Starting triage and fixture generation{retry_label}...")

    yield _emit_node_update(step, "running")
    yield _emit_log(f"[Critic Agent] Phase I: Triage pruning{retry_label} — cross-referencing with framework context")

    time.sleep(0.6)

    # Phase I: Prune — keep only the SQL injection, mark CWE-200 as contextual/low
    if not is_retry:
        state["pruned_vulns"] = [
            v for v in state.get("candidate_vulns", [])
            if v.get("cwe_id") == "CWE-89"
        ]
        pruned_count = len(state["candidate_vulns"]) - len(state["pruned_vulns"])
        state["logs"].append(f"[Critic Agent] Pruned {pruned_count} low-confidence candidates")
        yield _emit_log(f"[Critic Agent] Pruned {pruned_count} low-confidence/contextual findings (kept {len(state['pruned_vulns'])} for testing)")

    time.sleep(0.5)

    # Phase II: Generate test fixtures
    yield _emit_log("[Critic Agent] Phase II: Generating isolated test fixtures (temperature=0.0)")

    if is_retry and state.get("harness_error_traces"):
        yield _emit_log(f"[Critic Agent] Incorporating error traces from previous run into fixture regeneration")
        time.sleep(0.4)

    # Stub: generate a realistic test fixture for the SQL injection
    fixture_code = '''"""
Auto-generated test fixture for CWE-89: SQL Injection
Target: routes/auth.py (lines 42-48)
Generated by VerifyFix Critic Agent (temperature=0.0)
"""
import sqlite3

def create_test_db():
    """Create an in-memory SQLite database with test data."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    cursor.execute(
        "INSERT INTO users (username, role, password_hash) VALUES (?, ?, ?)",
        ("admin", "superadmin", "hashed_pw_placeholder")
    )
    cursor.execute(
        "INSERT INTO users (username, role, password_hash) VALUES (?, ?, ?)",
        ("testuser", "viewer", "hashed_pw_placeholder")
    )
    conn.commit()
    return conn


def vulnerable_login(conn, username_input: str):
    """Reproduce the vulnerable code path from routes/auth.py:42-48."""
    cursor = conn.cursor()
    query = f"SELECT id, username, role FROM users WHERE username='{username_input}'"
    cursor.execute(query)
    return cursor.fetchall()


def test_sql_injection():
    """Attempt SQL injection payload against the vulnerable function."""
    conn = create_test_db()

    # Benign input — should return single user
    benign_result = vulnerable_login(conn, "testuser")
    assert len(benign_result) == 1, f"Expected 1 row, got {len(benign_result)}"

    # Malicious payload — UNION-based injection to dump all users
    payload = "' OR '1'='1"
    malicious_result = vulnerable_login(conn, payload)

    if len(malicious_result) > 1:
        print(f"VULNERABILITY_CONFIRMED: Payload returned {len(malicious_result)} rows (expected 0-1)")
        conn.close()
        return "VULNERABILITY_CONFIRMED"
    else:
        print("SECURE: Payload was neutralized")
        conn.close()
        return "SECURE"


if __name__ == "__main__":
    result = test_sql_injection()
    print(f"Final verdict: {result}")
    exit(0 if result == "SECURE" else 1)
'''

    state["generated_fixtures"] = {"CWE-89_sql_injection": fixture_code}
    state["logs"].append(f"[Critic Agent] Generated {len(state['generated_fixtures'])} test fixture(s)")

    yield _emit_log(f"[Critic Agent] Generated {len(state['generated_fixtures'])} test fixture(s) for sandbox execution")
    yield _emit_state_delta({
        "execution_step": step,
        "pruned_vulns_count": len(state.get("pruned_vulns", [])),
        "generated_fixtures_count": len(state["generated_fixtures"]),
    })
    yield _emit_node_update(step, "completed")

    return state


# ---------------------------------------------------------------------------
# Node 5: Sandbox Execution
# ---------------------------------------------------------------------------

def node_sandbox(state: VerifyFixState) -> Generator[Dict[str, Any], None, VerifyFixState]:
    """
    Docker sandbox execution harness.
    In Phase 4+ this will run fixtures inside isolated containers.
    Phase 2 stub simulates execution with realistic verdict cycling.
    """
    step = "SANDBOX"
    state["execution_step"] = step
    state["logs"].append("[Sandbox] Initializing isolated execution environment...")

    yield _emit_node_update(step, "running")
    yield _emit_log("[Sandbox] Spinning up isolated execution harness")

    time.sleep(0.8)

    # Simulate fixture execution
    for fixture_name, fixture_code in state.get("generated_fixtures", {}).items():
        yield _emit_log(f"[Sandbox] Executing fixture: {fixture_name}")
        time.sleep(0.6)

        # On first run with retry_count 0, simulate a HARNESS_ERROR to test the retry loop.
        # On retries, simulate VULNERABILITY_CONFIRMED.
        current_retry = state.get("retry_count", 0)
        if current_retry == 0:
            # First attempt: simulate a harness error to exercise the retry loop
            state["docker_status"][fixture_name] = "HARNESS_ERROR"
            state["harness_error_traces"][fixture_name] = (
                "Traceback (most recent call last):\n"
                "  File \"fixture_CWE-89.py\", line 55, in test_sql_injection\n"
                "    assert len(benign_result) == 1\n"
                "AssertionError: Expected 1 row, got 0\n"
                "Note: Database was not properly seeded before test execution."
            )
            verdict = "HARNESS_ERROR"
        else:
            # Retry succeeds: vulnerability confirmed
            state["docker_status"][fixture_name] = "VULNERABILITY_CONFIRMED"
            state["harness_error_traces"].pop(fixture_name, None)
            verdict = "VULNERABILITY_CONFIRMED"

        yield _emit_log(f"[Sandbox] Fixture '{fixture_name}' verdict: {verdict}")

    state["logs"].append(f"[Sandbox] Execution complete — verdicts: {dict(state['docker_status'])}")

    yield _emit_state_delta({
        "execution_step": step,
        "docker_status": state["docker_status"],
    })
    yield _emit_node_update(step, "completed")

    return state


# ---------------------------------------------------------------------------
# Node 6: Remediation (Senior Analyst — Agent 4)
# ---------------------------------------------------------------------------

def node_remediation(state: VerifyFixState) -> Generator[Dict[str, Any], None, VerifyFixState]:
    """
    Agent 4: Senior analyst remediation compiler.
    Uses Gemini 2.5 Flash with temperature=0.4 for root-cause analysis.
    Phase 2 stub produces representative remediation output.
    """
    step = "REMEDIATION"
    state["execution_step"] = step
    state["logs"].append("[Senior Analyst] Compiling verified remediation report...")

    yield _emit_node_update(step, "running")
    yield _emit_log("[Senior Analyst] Ingesting VULNERABILITY_CONFIRMED entries for root-cause analysis (temperature=0.4)")

    time.sleep(1.0)

    confirmed = [
        name for name, status in state.get("docker_status", {}).items()
        if status == "VULNERABILITY_CONFIRMED"
    ]

    yield _emit_log(f"[Senior Analyst] Processing {len(confirmed)} confirmed vulnerabilities")
    time.sleep(0.5)

    state["final_remediations"] = [
        {
            "cwe_id": "CWE-89",
            "vulnerability_name": "SQL Injection",
            "severity": "CRITICAL",
            "root_cause": (
                "User-supplied 'username' parameter is directly interpolated into an SQL query "
                "string using Python f-string formatting (line 42). This allows an attacker to "
                "inject arbitrary SQL commands, bypassing authentication and potentially "
                "extracting or modifying database contents."
            ),
            "patch_diff": (
                "--- a/routes/auth.py\n"
                "+++ b/routes/auth.py\n"
                "@@ -42,3 +42,3 @@ def login_user():\n"
                "-    query = f\"SELECT id, username, role FROM users WHERE username='{username}'\"\n"
                "-    cursor.execute(query)\n"
                "+    cursor.execute(\"SELECT id, username FROM users WHERE username=?\", (username,))\n"
            ),
            "defense_in_depth": (
                "1. Use parameterized queries exclusively — never concatenate user input into SQL.\n"
                "2. Implement input validation (whitelist allowed characters for usernames).\n"
                "3. Apply least-privilege database permissions (read-only user for auth queries).\n"
                "4. Deploy a Web Application Firewall (WAF) with SQL injection rule sets.\n"
                "5. Enable SQL query logging and anomaly detection monitoring."
            ),
            "affected_file": "routes/auth.py",
            "line_range": "42-48",
        }
    ]

    state["logs"].append(f"[Senior Analyst] Generated {len(state['final_remediations'])} remediation item(s)")

    yield _emit_log(f"[Senior Analyst] Generated {len(state['final_remediations'])} remediation(s) with patch diffs and defence-in-depth guidance")
    yield _emit_state_delta({
        "execution_step": step,
        "final_remediations": state["final_remediations"],
    })
    yield _emit_node_update(step, "completed")

    return state


# ---------------------------------------------------------------------------
# Node 7: Complete
# ---------------------------------------------------------------------------

def node_complete(state: VerifyFixState) -> Generator[Dict[str, Any], None, VerifyFixState]:
    """
    Terminal node — marks the scan as completed and emits final summary.
    """
    step = "COMPLETED"
    state["execution_step"] = step
    state["completed_at"] = _ts()

    confirmed_count = sum(
        1 for s in state.get("docker_status", {}).values()
        if s == "VULNERABILITY_CONFIRMED"
    )
    secure_count = sum(
        1 for s in state.get("docker_status", {}).values()
        if s == "SECURE"
    )
    remediation_count = len(state.get("final_remediations", []))

    summary = (
        f"[Complete] Scan {state['scan_id']} finished. "
        f"Confirmed: {confirmed_count}, Secure: {secure_count}, "
        f"Remediations: {remediation_count}"
    )
    state["logs"].append(summary)

    yield _emit_node_update(step, "completed")
    yield _emit_log(summary)
    yield _emit_state_delta({
        "execution_step": step,
        "completed_at": state["completed_at"],
        "summary": {
            "confirmed_vulnerabilities": confirmed_count,
            "secure_findings": secure_count,
            "remediations_generated": remediation_count,
            "retry_count": state.get("retry_count", 0),
        },
    })

    return state
