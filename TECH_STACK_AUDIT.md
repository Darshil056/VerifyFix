# 🛠️ VerifyFix: Comprehensive Tech Stack Audit

This document provides an exhaustive, line-by-line audit of every technology, library, framework, and tool present in the **VerifyFix** repository. It details **where** each is used, **why** it was chosen, and identifies **"phantom" / unused dependencies or features** that are mentioned in documentation, resumes, or configuration files but are not actively implemented or are only present as passive fallbacks.

---

## 📌 Table of Contents
1. [Active Tech Stack: Where & Why](#1-active-tech-stack-where--why)
   - [Frontend Ecosystem](#frontend-ecosystem)
   - [Backend Ecosystem](#backend-ecosystem)
   - [AI & Agentic Orchestration](#ai--agentic-orchestration)
   - [Vector Search & Threat Intelligence (RAG)](#vector-search--threat-intelligence-rag)
   - [Sandbox & Execution Harness](#sandbox--execution-harness)
   - [Persistence & Databases](#persistence--databases)
   - [Reporting & Output Synthesis](#reporting--output-synthesis)
   - [DevOps, Testing & Quality Assurance](#devops-testing--quality-assurance)
2. [Unused, Phantom, or Discrepant Technologies](#2-unused-phantom-or-discrepant-technologies)
3. [Summary Matrix](#3-summary-matrix)

---

## 1. Active Tech Stack: Where & Why

### Frontend Ecosystem

| Technology / Library | Where in Codebase | Why it was Chosen |
| :--- | :--- | :--- |
| **Next.js 16 (v16.3.4, App Router)** | `frontend/src/app/`, `frontend/package.json` | Modern React framework providing standard server/client boundary separation, App Router directory structure (`/dashboard`), optimized script loading, and production-ready static/dynamic asset bundling. |
| **React 19 (v19.2.8) & React DOM 19** | `frontend/src/app/`, `frontend/src/components/` | Foundation UI library; enables reactive client state management for real-time node transitions, log streaming, and dynamic UI panels. |
| **TypeScript 5** | `frontend/tsconfig.json`, `*.ts`, `*.tsx` files | Provides static typing across API payloads, state objects, DAG nodes, and vulnerability interfaces (`useScanStream.ts`), preventing runtime UI crashes. |
| **Tailwind CSS v4 (`tailwindcss`, `@tailwindcss/postcss`)** | `frontend/src/app/globals.css`, component JSX | Utility-first CSS engine for high-density, dark-themed cybersecurity UI styling (glow states, animated borders, monospace badges) without writing custom CSS files. |
| **React Flow (`@xyflow/react` v12.11.6)** | `frontend/src/components/dag/DagVisualizer.tsx`, `frontend/src/components/dag/CustomNode.tsx` | Specialized node-and-edge canvas used to visually map the 8-stage LangGraph execution graph and animate node transitions (idle, running, confirmed, secure, healing) in real time. |
| **Lucide React (`lucide-react` v1.41.0)** | `frontend/src/components/` (all dashboard and drawer components) | Clean, lightweight icon suite for security indicators (shields, terminal, bug badges, git branches, spinners). |
| **Utility Helpers (`clsx` v2.1.1, `tailwind-merge` v3.6.0)** | `frontend/src/lib/utils.ts` (`cn()` helper function) | Safely resolves Tailwind class conflicts and dynamically composes conditional class names based on state (e.g., active node glow). |
| **Server-Sent Events (Native `EventSource`)** | `frontend/src/hooks/useScanStream.ts` | Consumes unidirectional streaming events (`pipeline_start`, `node_update`, `log`, `state_delta`, `scan_complete`) from the Flask backend over standard HTTP. |

---

### Backend Ecosystem

| Technology / Library | Where in Codebase | Why it was Chosen |
| :--- | :--- | :--- |
| **Python 3.11** | Monorepo root, `backend/`, `runtime environment` | Modern Python runtime offering improved exception groups, performance enhancements, and native typing compatibility with LangGraph and ChromaDB. |
| **Flask (v3.0.0+)** | `backend/app.py` | Lightweight, un-opinionated microframework suited for orchestrating long-running asynchronous threads, SSE response streams, and clean REST endpoints without ORM bloat. |
| **Flask-CORS (v4.0.0+)** | `backend/app.py` (`CORS(app)`) | Configures Cross-Origin Resource Sharing headers allowing the Next.js frontend (`localhost:3000`) to communicate seamlessly with the backend (`localhost:5000`). |
| **python-dotenv (v1.0.0+)** | `backend/config.py` | Automatically injects environment secrets (`GEMINI_API_KEY`, `GITHUB_TOKEN`, `MONGO_URI`) from `.env` into `os.environ`. |
| **Requests (v2.31.0+)** | `backend/services/github_context.py`, `backend/rag/cwe_fetcher.py` | Synchronous HTTP client used to fetch remote repository directory trees and files from GitHub API, and scrape MITRE CWE definitions. |

---

### AI & Agentic Orchestration

| Technology / Library | Where in Codebase | Why it was Chosen |
| :--- | :--- | :--- |
| **LangGraph (v0.2.0+)** | `backend/agents/graph.py`, `backend/agents/state.py` | Core orchestration framework. Provides a stateful Directed Acyclic Graph (DAG) state machine supporting conditional branching and cyclic self-healing loops when test fixtures fail. |
| **LangChain Core (v0.3.0+)** | `backend/requirements.txt`, `backend/agents/` | Base abstractions and state typing required by LangGraph for structured dictionary state transitions. |
| **Google Generative AI SDK (`google-generativeai` v0.8.0+)** | `backend/agents/discovery.py`, `backend/agents/critic.py`, `backend/agents/remediation.py`, `backend/rag/chroma_service.py` | Direct API interface to **Gemini 2.5 Flash** (for reasoning, fixture generation, root-cause criticism, and code patches) and **Gemini Embedding** models (`models/gemini-embedding-2`). |

---

### Vector Search & Threat Intelligence (RAG)

| Technology / Library | Where in Codebase | Why it was Chosen |
| :--- | :--- | :--- |
| **ChromaDB (v0.5.0+)** | `backend/rag/chroma_service.py`, `backend/chroma_data/` | Embedded, serverless vector database operating locally with SQLite/DuckDB persistence; stores vectorized CWE threat profiles for instant semantic similarity queries without cloud DB latency. |
| **BeautifulSoup4 (v4.12.0+)** | `backend/rag/cwe_fetcher.py` | Parses HTML pages from `cwe.mitre.org` to extract CWE descriptions, common consequences, and recommended mitigations for RAG vectorization. |

---

### Sandbox & Execution Harness

| Technology / Library | Where in Codebase | Why it was Chosen |
| :--- | :--- | :--- |
| **Unified Multi-Runtime Docker Image (`verifyfix-sandbox:latest`)** | `backend/sandbox/Dockerfile`, `backend/sandbox/runner.py` | Unified isolated container packaging Python 3.11, Node.js 20 LTS, and Bash with pre-bundled web frameworks (`flask`, `fastapi`, `sqlalchemy`, `pydantic`, `express`, `jsonwebtoken`, `axios`). Eliminates external package download delays in network-isolated (`--network none`) scans. |
| **Automated Workspace Staging Engine** | `backend/sandbox/runner.py` (`stage_workspace_files()`), `backend/agents/nodes.py` | Automatically materializes the full repository file tree and resolved dependencies (`full_files`, `dependency_files`) into the sandbox temp root with `PYTHONPATH=/app` and `NODE_PATH=/app`. Allows relative cross-file imports (Python, JS, Bash) to resolve naturally without manual file copying. |
| **Universal Auto-Mock & Package Namespace Engine** | `backend/sandbox/auto_mock.py`, `backend/sandbox/runner.py` | Virtualizes uninstalled symbols into real `Exception` + `type` hybrid subclasses. Solves "TypeError: catching classes that do not inherit from BaseException", enables `isinstance()`, provides passthrough decorators, and creates `__init__.py` markers across the staged tree to resolve relative imports (`from . import`). |
| **Fallback Container Images (`python:3.11-slim`, `node:20-alpine`)** | `backend/sandbox/runner.py` | Automatic fallback images used if the unified custom image has not yet been built locally. |
| **Restricted Process Sandbox (Subprocess)** | `backend/sandbox/runner.py` (`_run_process_sandbox()`) | Automatic local fallback harness if the Docker daemon is unreachable. Strips sensitive environment variables (API keys, DB URIs) and enforces execution timeouts for Python, Node.js, and Bash. |

---

### Persistence & Databases

| Technology / Library | Where in Codebase | Why it was Chosen |
| :--- | :--- | :--- |
| **MongoDB / PyMongo (v4.8.0+)** | `backend/services/mongodb.py`, `backend/app.py` | Document store for persisting JSON-like scan sessions, node state deltas, log events, and finalized vulnerability summaries. |
| **In-Memory Thread-Safe Dict (Fallback)** | `backend/services/mongodb.py` (`_in_memory_scans`), `backend/app.py` (`ScanRegistry`) | Eliminates hard database installation requirements for local development; if MongoDB is not running, the application gracefully stores all scans in memory. |

---

### Reporting & Output Synthesis

| Technology / Library | Where in Codebase | Why it was Chosen |
| :--- | :--- | :--- |
| **`python-docx` (v1.1.0+)** | `backend/services/report_generator.py` | Programmatically generates formatted, styled Microsoft Word (`.docx`) audit reports containing executive summaries, CWE badges, root cause breakdowns, and patch diffs. |

---

### DevOps, Testing & Quality Assurance

| Technology / Library | Where in Codebase | Why it was Chosen |
| :--- | :--- | :--- |
| **Pytest (v8.0.0+)** | `backend/tests/`, `backend/requirements.txt` | Automated backend testing framework validating state graph transitions, fixture generation, API routes, and sandbox runners. |
| **Flake8 (v7.0.0+)** | `backend/requirements.txt`, `.github/workflows/ci.yml` | Python linter enforcing PEP 8 style standards and syntax checks. |
| **ESLint 9 & Next.js ESLint Plugin** | `frontend/package.json`, `.github/workflows/ci.yml` | Static analysis tool ensuring React hooks compliance, TypeScript type hygiene, and optimal Next.js code patterns. |
| **GitHub Actions** | `.github/workflows/ci.yml` | CI automation workflow executing parallel backend lint/pytest and frontend lint/build verification on every push and pull request. |

---

## 2. Unused, Phantom, or Discrepant Technologies

During the audit, several tools and dependencies were identified that appear in **documentation**, **resumes**, **configurations**, or **code comments**, but are **NOT actively used or are phantom mentions**:

### 🚫 1. NextAuth.js / GitHub OAuth
* **Where it appears:**
  * Mentioned in `resume_context.md` (lines 12, 27, 37): *"Frontend: ... NextAuth.js"*, *"secured user onboarding with NextAuth.js and GitHub OAuth integration"*.
* **Actual State:**
  * **NOT INSTALLED & NOT USED.**
  * `next-auth` is **absent** from `frontend/package.json`.
  * There are zero auth routes (`/api/auth/`), middleware, or session hooks in `frontend/src`.
  * Repository scanning accepts an optional raw token input via client state instead of an OAuth session.

---

### 🚫 2. Sentence-Transformers
* **Where it appears:**
  * Mentioned in `resume_context.md` (line 14): *"Sentence-Transformers (RAG)"*.
  * Mentioned in `backend/rag/chroma_service.py` (line 31): *"ChromaDB will fall back to default local sentence-transformers"*.
* **Actual State:**
  * **NOT IN REQUIREMENTS & NOT IMPORTED.**
  * `sentence-transformers` is not present in `backend/requirements.txt`.
  * The actual embedding logic uses **Google Gemini Embeddings** (`genai.embed_content` with `models/gemini-embedding-2`). If Gemini fails or has no key, it lets ChromaDB use its built-in default rather than an explicit `sentence-transformers` package.

---

### 🚫 3. Gunicorn (Local Execution)
* **Where it appears:**
  * Listed in `backend/requirements.txt`, `README.md`, and `resume_context.md`.
* **Actual State:**
  * **INSTALLED BUT UNUSED IN DEV/REPO.**
  * Local backend runs via `python app.py` (Flask's built-in development server).
  * There is no `Procfile`, `Dockerfile` for the backend server, or deployment script actively invoking `gunicorn app:app`. It exists purely as a standard dependency for hypothetical production hosting.

---

### ⚠️ 4. MongoDB as a Strict Requirement (Soft Dependency)
* **Where it appears:**
  * Listed in `requirements.txt` (`pymongo`), `.env.example` (`MONGO_URI`), and docs as the main database.
* **Actual State:**
  * **OPTIONAL / GRACEFUL FALLBACK.**
  * The application does not require a live MongoDB instance to run. `backend/services/mongodb.py` encapsulates all database operations inside try/except blocks and falls back to an internal dictionary (`_in_memory_scans`) if MongoDB is unreachable or if `pymongo` is missing.

---

### ⚠️ 5. Docker as a Hard Requirement (Dual-Mode Execution)
* **Where it appears:**
  * Described in `resume_context.md` and `README.md` as the core sandbox mechanism.
* **Actual State:**
  * **OPTIONAL WITH LOCAL SUBPROCESS FALLBACK.**
  * `backend/sandbox/runner.py` checks `_is_docker_available()`. If Docker daemon is stopped, it gracefully redirects code fixture execution to a local Python subprocess.

---

## 3. Summary Matrix

| Category | Component | Status in Codebase | Notes |
| :--- | :--- | :--- | :--- |
| **Frontend** | Next.js 16 (App Router) | ✅ **Actively Used** | Page routing, layouts, and dashboard |
| **Frontend** | React 19 & React DOM | ✅ **Actively Used** | Core UI rendering |
| **Frontend** | TypeScript 5 | ✅ **Actively Used** | Static typing across all components |
| **Frontend** | Tailwind CSS v4 | ✅ **Actively Used** | Theme styling and responsive design |
| **Frontend** | React Flow (`@xyflow/react`) | ✅ **Actively Used** | Visualizing 8-node LangGraph execution |
| **Frontend** | Lucide React | ✅ **Actively Used** | Status and navigation iconography |
| **Frontend** | `clsx` & `tailwind-merge` | ✅ **Actively Used** | Dynamic class concatenation (`cn()`) |
| **Frontend** | NextAuth.js / OAuth | ❌ **Phantom / Not Used** | Listed in resume context only; not installed |
| **Backend** | Python 3.11 | ✅ **Actively Used** | Core backend language |
| **Backend** | Flask 3.0+ | ✅ **Actively Used** | REST API & SSE streaming server |
| **Backend** | Flask-CORS | ✅ **Actively Used** | Cross-origin request management |
| **Backend** | Requests & BeautifulSoup4 | ✅ **Actively Used** | Ingestion & MITRE CWE scraping |
| **Backend** | python-dotenv | ✅ **Actively Used** | Environment variable management |
| **Backend** | Gunicorn | ⚠️ **Present but Unused** | In requirements, but not invoked in repo |
| **AI / DAG** | LangGraph & LangChain Core | ✅ **Actively Used** | State machine, DAG transitions, healing |
| **AI / LLM** | Google Gemini 2.5 Flash | ✅ **Actively Used** | Code analysis, fixture & patch generation |
| **AI / LLM** | Sentence-Transformers | ❌ **Phantom / Not Used** | Mentioned in docs; replaced by Gemini Embeddings |
| **RAG** | ChromaDB (Persistent) | ✅ **Actively Used** | Vector storage for CWE mitigation context |
| **Sandbox** | Docker (`python:3.11-slim`) | ✅ **Actively Used** | Primary test harness (when Docker runs) |
| **Sandbox** | Python Subprocess Fallback | ✅ **Actively Used** | Secondary test harness (when Docker is down) |
| **Database** | MongoDB (`pymongo`) | ⚠️ **Active with Fallback**| Full integration; falls back to in-memory |
| **Reporting**| `python-docx` | ✅ **Actively Used** | Generates `.docx` audit deliverables |
| **CI / CD**  | GitHub Actions | ✅ **Actively Used** | Automated linting, build, and test runner |
| **Testing**  | Pytest & Flake8 | ✅ **Actively Used** | Backend unit tests & style enforcement |
| **Testing**  | ESLint 9 | ✅ **Actively Used** | Frontend linting and type hygiene |

