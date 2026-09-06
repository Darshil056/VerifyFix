# Phase 2 Gothrough: LangGraph State Machine & Flask SSE Streaming Engine

## Completed: September 2026
## Authors: Darshil Mendapara & Dhruv Parsana

---

## 1. What Was Built in Phase 2

Phase 2 establishes the **core orchestration engine** of VerifyFix — the typed state machine, the directed acyclic graph (DAG) executor with a conditional retry loop, and the real-time Server-Sent Events (SSE) streaming engine.

### Summary of Deliverables

| # | Component | File(s) | Description |
|---|-----------|---------|-------------|
| 1 | **Typed State Definition** | `backend/agents/state.py` | `VerifyFixState` TypedDict with 17 fields, sub-types `VulnerabilityCandidate` and `RemediationItem`, factory function `create_initial_state()` |
| 2 | **Node Handlers** | `backend/agents/nodes.py` | 7 individual node functions (GitHub Ingest, Discovery, RAG, Critic, Sandbox, Remediation, Complete) — each yields SSE events |
| 3 | **DAG Executor** | `backend/agents/graph.py` | `VerifyFixDAG` class with generator-based `execute()`, conditional retry edge `should_retry()`, bounded retry loop (max 3) |
| 4 | **SSE Streaming Engine** | `backend/app.py` | `GET /api/scan/stream` SSE endpoint with heartbeat, `POST /api/scan/start`, `GET /api/scan/status`, `GET /api/scan/list`, `GET /api/scan/result` |
| 5 | **Thread-Safe Scan Registry** | `backend/app.py` | `ScanRegistry` class with `threading.RLock()` for concurrent scan management |
| 6 | **DAG Unit Tests** | `backend/tests/test_dag.py` | 17 tests covering state creation, individual nodes, conditional edges, full pipeline execution, retry loop, and SSE event format |
| 7 | **API Integration Tests** | `backend/tests/test_api.py` | 13 tests covering Phase 1 endpoints + Phase 2 scan lifecycle |
| 8 | **CI Pipeline** | `.github/workflows/ci.yml` | Converted from CI/CD to CI-only — separate backend and frontend jobs |

---

## 2. Architecture

### 2.1 DAG Topology

```
[Start]
   │
   ▼
[node_github_ingest]    ← Validates repo context, loads diff
   │
   ▼
[node_discovery]         ← Agent 1: Candidate vulnerability scanner (Gemini stub)
   │
   ▼
[node_rag]              ← Layer 2: ChromaDB RAG context enrichment (stub)
   │
   ▼
[node_critic]           ← Agent 3: Triage + fixture generator ◄────────┐
   │                                                                    │
   ▼                                                                    │
[node_sandbox]          ← Docker sandbox execution harness ─────────────┘
   │                     (loops back on HARNESS_ERROR, retry_count < 3)
   ├──► VULNERABILITY_CONFIRMED / SECURE
   │
   ▼
[node_remediation]      ← Agent 4: Senior analyst remediation compiler
   │
   ▼
[node_complete]         ← Terminal node — marks scan complete
```

### 2.2 SSE Event Types

| Event | Purpose | Example |
|-------|---------|---------|
| `pipeline_start` | Signals DAG execution has begun | `{"scan_id": "...", "repo": "owner/name"}` |
| `node_update` | Node status change (running/completed) | `{"step": "DISCOVERY", "status": "running"}` |
| `log` | Human-readable execution log | `{"message": "[Discovery Agent] Found 2 candidates"}` |
| `state_delta` | Partial state update for frontend | `{"candidate_vulns": [...]}` |
| `error` | Fatal pipeline error | `{"message": "...", "step": "CRITIC"}` |
| `pipeline_end` | Signals DAG execution has finished | `{"scan_id": "...", "final_step": "COMPLETED"}` |
| `stream_end` | SSE connection can be closed | `{"scan_id": "...", "message": "Scan completed"}` |

### 2.3 Retry Loop Mechanics

The sandbox node simulates execution of generated test fixtures. On the **first run** (retry_count=0), it intentionally returns `HARNESS_ERROR` to exercise the retry loop. The DAG detects this via the `should_retry()` conditional edge:

```python
def should_retry(state: VerifyFixState) -> str:
    statuses = state.get("docker_status", {}).values()
    if "HARNESS_ERROR" in statuses and state.get("retry_count", 0) < 3:
        return "retry_critic"
    return "proceed_to_remediation"
```

This loops back to `node_critic` which regenerates the fixture incorporating the error traces, then `node_sandbox` runs again. On retry, the sandbox confirms the vulnerability.

---

## 3. API Endpoints (Phase 2)

### `POST /api/scan/start`
Start a new vulnerability scan.

**Request body:**
```json
{
    "repo_owner": "verifyfix-demo",
    "repo_name": "vulnerable-flask-auth",
    "branch_name": "main",
    "target_diff": "(optional) pre-fetched diff content"
}
```

**Response (201):**
```json
{
    "success": true,
    "scan_id": "a1b2c3d4-...",
    "stream_url": "/api/scan/stream?scan_id=a1b2c3d4-...",
    "status_url": "/api/scan/status?scan_id=a1b2c3d4-...",
    "message": "Scan initiated for verifyfix-demo/vulnerable-flask-auth@main"
}
```

### `GET /api/scan/stream?scan_id=<ID>`
SSE streaming endpoint. Connect with `EventSource` or `curl -N`.

### `GET /api/scan/status?scan_id=<ID>`
Returns current state snapshot (execution step, counts, logs).

### `GET /api/scan/result?scan_id=<ID>`
Returns the full final result after completion (remediations, verdicts, logs).

### `GET /api/scan/list`
Returns a summary of all registered scans.

---

## 4. How to Test Locally

### 4.1 Backend Setup

```bash
cd VerifyFix/backend

# Step 1: Create virtual environment (first time only)
python -m venv venv

# Step 2: Activate the virtual environment
# Windows (PowerShell):
.\venv\Scripts\activate.ps1
# Windows (CMD):
venv\Scripts\activate.bat
# macOS / Linux:
# source venv/bin/activate

# Step 3: Install dependencies inside the venv
pip install -r requirements.txt

# Step 4: Run the server
python app.py
```

The server starts on `http://localhost:5000`.

> **Note:** Always activate the venv before running the server or tests. Your prompt should show `(venv)` when the environment is active.

### 4.2 Verify Health

```bash
curl http://localhost:5000/health
```

Expected:
```json
{"status":"healthy","service":"verifyfix-backend","version":"2.0.0-phase2","environment":"development"}
```

### 4.3 Start a Scan

```bash
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"repo_owner":"verifyfix-demo","repo_name":"vulnerable-flask-auth","branch_name":"main"}'
```

Copy the `scan_id` from the response.

### 4.4 Stream SSE Events

```bash
curl -N http://localhost:5000/api/scan/stream?scan_id=<YOUR_SCAN_ID>
```

You'll see real-time events like:
```
event: pipeline_start
data: {"scan_id":"...","repo":"verifyfix-demo/vulnerable-flask-auth","branch":"main","timestamp":"..."}

event: node_update
data: {"step":"GITHUB_INGEST","status":"running","timestamp":"..."}

event: log
data: {"message":"[GitHub Ingest] Fetching diff for verifyfix-demo/vulnerable-flask-auth branch: main","timestamp":"..."}

event: node_update
data: {"step":"DISCOVERY","status":"running","timestamp":"..."}

...

event: stream_end
data: {"scan_id":"...","message":"Scan completed"}
```

### 4.5 Check Status / Result

```bash
# Status (works during or after scan)
curl http://localhost:5000/api/scan/status?scan_id=<YOUR_SCAN_ID>

# Full result (only after completion)
curl http://localhost:5000/api/scan/result?scan_id=<YOUR_SCAN_ID>
```

### 4.6 Run Tests

```bash
cd backend
python -m pytest tests/ -v
```

Expected: All 30 tests pass.

---

## 5. CI Pipeline Changes

The CI/CD pipeline (`.github/workflows/ci-cd.yml`) has been **replaced** with a CI-only pipeline (`.github/workflows/ci.yml`):

| Old (CI/CD) | New (CI-only) |
|-------------|---------------|
| Job 1: Lint & Test (combined) | Job 1: Backend — Lint & Test (includes DAG tests) |
| Job 2: Deploy Frontend (Vercel) | **Removed** |
| Job 3: Deploy Backend (Render) | **Removed** |
| — | Job 2: Frontend — Lint & Build |

CD (deployment) will be added back in a later phase when deployment targets are configured.

---

## 6. File Tree After Phase 2

```
VerifyFix/
├── .github/
│   └── workflows/
│       └── ci.yml                          # CI-only pipeline
├── backend/
│   ├── agents/
│   │   ├── __init__.py                     # [NEW] Package init
│   │   ├── state.py                        # [NEW] VerifyFixState definition
│   │   ├── nodes.py                        # [NEW] 7 node handler functions
│   │   └── graph.py                        # [NEW] DAG executor with retry edge
│   ├── tests/
│   │   ├── test_api.py                     # [UPDATED] +7 scan API tests
│   │   └── test_dag.py                     # [NEW] 17 DAG unit tests
│   ├── app.py                              # [UPDATED] +SSE engine, scan registry
│   ├── config.py
│   ├── requirements.txt                    # [UPDATED] +langgraph, langchain-core
│   └── .env.example
├── frontend/
│   └── ...                                 # (Unchanged in Phase 2)
├── Phase_2_Gothrough.md                    # [NEW] This document
├── Phase_2_LangGraph_State_Machine_and_SSE_Plan.md
├── VerifyFix_Implementation_Plan.md
└── README.md
```

---

## 7. What's Next (Phase 3 Preview)

Phase 3 will replace the stub node implementations with real integrations:
- **Agent 1 (Discovery):** Connect to Google Gemini 3.1 Flash-Lite API with structured JSON schema prompts
- **Layer 2 (RAG):** Initialize ChromaDB with `sentence-transformers/all-MiniLM-L6-v2`, build on-demand MITRE CWE scraper & ingestor
- **Context Injection:** Retrieve top-3 relevant CWE sections per candidate vulnerability

The DAG executor, SSE streaming engine, and state machine built in Phase 2 will be used without modification — only the node internals change.
