# VerifyFix: Remaining Phases Master Roadmap (Phases 2 - 6)

This document provides the high-level roadmap and cross-reference index for all remaining phases of the **VerifyFix** project. Each phase has its own dedicated, detailed engineering implementation plan file:

---

## 📑 Dedicated Implementation Plan Files

| Phase | Title & Scope | Implementation Plan Document |
| :--- | :--- | :--- |
| **Phase 2** | **LangGraph State Machine & Flask Streaming Engine (SSE)**<br>State definition (`VerifyFixState`), DAG assembly, retry conditional edges, and SSE streaming. | [Phase_2_LangGraph_State_Machine_and_SSE_Plan.md](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/Phase_2_LangGraph_State_Machine_and_SSE_Plan.md) |
| **Phase 3** | **Online ChromaDB RAG & Gemini 2.5 Flash Discovery Scanner**<br>Agent 1 structured JSON scanner (`temperature=0.2`), MITRE CWE vector store, and context enrichment. | [Phase_3_ChromaDB_RAG_and_Discovery_Agent_Plan.md](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/Phase_3_ChromaDB_RAG_and_Discovery_Agent_Plan.md) |
| **Phase 4** | **Critic Agent & Sandbox Execution Harness (Self-Healing Loop)**<br>Critic Agent triage pruning & test generator (`temperature=0.0`), Docker/subprocess runner, and 3x self-healing feedback loop. | [Phase_4_Critic_Agent_and_Sandbox_Harness_Plan.md](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/Phase_4_Critic_Agent_and_Sandbox_Harness_Plan.md) |
| **Phase 5** | **Senior Analyst Remediation & Word Report (.docx) Generator**<br>Agent 4 patch compiler (`temperature=0.4`), `python-docx` executive audit report service with author credits, and download endpoint. | [Phase_5_Senior_Analyst_and_Docx_Report_Plan.md](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/Phase_5_Senior_Analyst_and_Docx_Report_Plan.md) |
| **Phase 6** | **Next.js Real-Time Animated DAG Dashboard (React Flow)**<br>8-node `@xyflow/react` visualizer, live SSE status animations (pulsing, red confirmed, green secure, amber loop), terminal console, and report export. | [Phase_6_Nextjs_React_Flow_Dashboard_Plan.md](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/Phase_6_Nextjs_React_Flow_Dashboard_Plan.md) |

---

## 🔄 End-to-End Pipeline Data Flow

```
+-------------------------------------------------------------------------------+
|                             Next.js Frontend                                  |
|  [Repository Selector] ---> [Start Scan] ---> [Live React Flow DAG Animation]  |
|                                       ▲                                       |
|                                       │ (Server-Sent Events: /api/scan/stream)|
+---------------------------------------┼────────────────────────────────-------+
                                        │
+---------------------------------------┼---------------------------------------+
|                             Flask Backend                                     |
|                                       │                                       |
|  1. Ingest Diff ──────► 2. Discovery Agent (Gemini 2.5 Flash, temp=0.2)       |
|                                       │                                       |
|                         3. ChromaDB RAG (MITRE CWE Context Enrichment)        |
|                                       │                                       |
|                         4. Critic Agent (Triage & Fixture Synthesis, temp=0.0)|
|                                       │                                       |
|                         5. Sandbox Execution (Docker / Subprocess Isolation)  |
|                                       │                                       |
|                                ┌──────┴──────┐                                |
|             [Syntax Error?]    │             │   [VULNERABILITY_CONFIRMED]    |
|             (retry_count < 3)  ▼             ▼                                |
|        ◄── Self-Healing Loop ──┘     6. Senior Remediation (temp=0.4)         |
|                                              │                                |
|                                      7. python-docx Audit Report Generator    |
|                                              │                                |
|                                      8. GET /api/report/download?scan_id=...   |
+-------------------------------------------------------------------------------+
```

---

## 👥 Workload Allocation & Team Verification

- **Backend Developer Responsibilities**: Phases 2, 3, 4, 5 (Engine, Agents, Vector RAG, Sandbox, Word Report Service).
- **Frontend Developer Responsibilities**: Phase 6 & Phase 1.2 (Next.js App Router, React Flow visualizer, EventSource hook, UI components).
- **Automated CI/CD**: Monitored by `.github/workflows/ci-cd.yml` running backend tests (`pytest`, `flake8`) and frontend checks (`npm run lint`, `npm run build`).
