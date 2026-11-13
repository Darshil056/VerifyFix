# Phase 4 Implementation Plan: Critic Agent & Sandbox Execution Harness

## 1. Overview & Objectives
Phase 4 provides the core differentiator of VerifyFix: **execution grounding**.
1. **Critic Agent (Phase I: Triage Pruning):** Evaluates if internal framework mitigations (e.g., ORM, parameterized queries, middleware sanitizers) neutralize the issue. If safe, prunes the alert.
2. **Critic Agent (Phase II: Fixture Synthesis):** Generates self-contained, executable test harnesses (`temperature=0.0`) targeting the suspect function with an exploit payload.
3. **Sandbox Runner & Self-Healing Loop:** Executes the fixture in an isolated environment (Docker or restricted subprocess). If execution crashes due to syntax/import errors (`HARNESS_ERROR`), the DAG loops back to Critic Agent with captured `harness_error_traces` to correct the script (max 3 retries).

---

## 2. Technical Specifications

### 2.1 Critic Agent Architecture (`backend/agents/critic.py`)

#### Phase I: Triage Pruning
Inspects candidate against framework context:
- If sanitized: Marks status as `SECURE`, adds to `pruned_vulns`, and halts execution for this item.
- If unhandled: Proceeds to fixture synthesis.

#### Phase II: Test Harness Synthesis (`temperature=0.0`)
Produces a standalone Python test script containing:
- In-memory database fixture (e.g., `sqlite3.connect(':memory:')`).
- Mock request / input payload designed to trigger the specific CWE.
- Verification assertion:
  - If exploit succeeds: prints `[VULNERABILITY_CONFIRMED] Exploit executed successfully: <evidence>` and exits `0`.
  - If exploit blocked: prints `[SECURE] Attack safely neutralized` and exits `0`.
  - If syntax error: exits non-zero with stderr trace.

### 2.2 Dual-Mode Sandbox Execution Harness (`backend/sandbox/runner.py`)
To ensure high portability and reliability:
1. **Docker Mode**: Runs fixture in an isolated, network-restricted container:
   ```bash
   docker run --rm --network none --memory 256m --cpus 0.5 -v /tmp/fixtures:/app:ro python:3.11-slim python /app/fixture.py
   ```
2. **Process Sandboxing Mode (Zero-Config Fallback)**:
   Runs fixture in an ephemeral Python subprocess with:
   - Strict 5.0-second timeout.
   - Isolated temporary directory (`tempfile.TemporaryDirectory()`).
   - Cleaned environment variables.
   - Stdout / stderr capture.

### 2.3 Self-Healing Feedback Loop Logic

```
   Critic Agent Generates Fixture
                 │
                 ▼
          Sandbox Runner
                 │
      ┌──────────┴──────────┐
      ▼                     ▼
Exit Code 0             Exit Code != 0
(Outputs Proof)      (Syntax / Import Error)
      │                     │
      ├─ VULNERABILITY      │
      │  CONFIRMED          ▼
      │              `HARNESS_ERROR`
      ▼                     │
Proceed to                  ▼
Senior Remediation   Retry Count < 3?
                       ├── Yes: Loop back to Critic with stderr trace
                       └── No:  Mark as UNRESOLVED_ERROR & proceed
```

---

## 3. Implementation Steps

1. **Implement Triage & Generator in `backend/agents/critic.py`**:
   - Triage filter logic.
   - LLM fixture generation prompt with deterministic syntax templates.
   - Self-healing prompt taking `harness_error_traces` as input.
2. **Implement Sandbox Runner in `backend/sandbox/runner.py`**:
   - Subprocess sandbox with timeout and stdout/stderr stream parsing.
   - Docker container execution dispatcher.
3. **Connect to LangGraph in `backend/agents/graph.py`**:
   - Hook `node_critic` and `node_sandbox`.
   - Implement `should_retry` conditional edge.
4. **Create Test Suite (`backend/tests/test_sandbox.py`)**:
   - Test execution of confirmed vulnerable fixtures.
   - Test execution of secured fixtures.
   - Test self-healing retry recovery from an intentional syntax bug.

---

## 4. Verification & Testing

```bash
# Run sandbox execution and self-healing tests
cd backend
python -m pytest tests/test_sandbox.py -v
```
