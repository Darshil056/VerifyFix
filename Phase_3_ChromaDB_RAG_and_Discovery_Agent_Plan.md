# Phase 3 Implementation Plan: Online ChromaDB RAG & Discovery Agent

## 1. Overview & Objectives
Phase 3 builds the intelligence intake layer:
1. **Agent 1 (Candidate Discovery Scanner):** Leverages Google Gemini 2.5 Flash (`temperature=0.2`) to analyze target repository code diffs and extract candidate vulnerabilities into a strict JSON schema.
2. **Layer 2 (Constrained ChromaDB RAG):** On-demand lookup and ingestion of official MITRE CWE threat models, attack vectors, and sanitization techniques, injecting context directly into `state["rag_context"]`.

---

## 2. Technical Specifications

### 2.1 Agent 1: Gemini 2.5 Flash Scanner (`backend/agents/discovery.py`)
- **Model**: `gemini-2.5-flash` (via `google-generativeai` SDK or REST API).
- **Fallback**: (`in-memory pattern matching`) or local security heuristic pattern matcher for zero-dependency test runs.
- **Parameters**: `temperature=0.2`, `top_p=0.95`.
- **System Prompt & JSON Schema**:
```json
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
```

### 2.2 Vector DB & RAG Knowledge Store (`backend/rag/`)
- **Database**: ChromaDB persistent client on disk (`backend/chroma_data/`).
- **Collection Name**: `threat_intelligence`.
- **Embedding Function**: Google Gemini text embedding model (`text-embedding-004` or latest compatible) via the `google-generativeai` SDK.
- **Target CWE Coverage**:
  - `CWE-89`: SQL Injection
  - `CWE-79`: Cross-Site Scripting (XSS)
  - `CWE-78`: OS Command Injection
  - `CWE-1321`: Prototype Pollution
  - `CWE-918`: Server-Side Request Forgery (SSRF)
  - `CWE-22`: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
  - `CWE-639`: Authorization Bypass Through User-Controlled Key (IDOR)

### 2.3 Context Injection Node (`backend/agents/rag_enricher.py`)
- For each unique `cwe_id` in `state["candidate_vulns"]`:
  - Query ChromaDB collection `threat_intelligence` for top 3 matching chunks (`n_results=3`).
  - If the CWE is not present in ChromaDB, trigger on-demand scraping/fetching from MITRE/OWASP repository and index chunks immediately.
  - Store enriched context in `state["rag_context"][cwe_id]`.

---

## 3. Implementation Steps

1. **Install & Configure Dependencies**:
   Add `chromadb` and `google-generativeai` to `backend/requirements.txt`.
2. **Implement Knowledge Base (`backend/rag/cwe_knowledge.py`)**:
   Curated MITRE CWE data with exploit signatures and validation patterns.
3. **Implement Vector Service (`backend/rag/chroma_service.py`)**:
   Initialize ChromaDB persistent collection and retrieval functions.
4. **Implement Discovery Agent (`backend/agents/discovery.py`)**:
   Implement Gemini prompt wrapper, JSON parsing, and fallback heuristic analyzer.
5. **Implement RAG Node (`backend/agents/rag_enricher.py`)**:
   Connect discovery output to ChromaDB lookup and update `rag_context`.
6. **Create Test Suite (`backend/tests/test_rag.py`)**:
   Verify extraction schema and ChromaDB similarity search.

---

## 4. Verification & Testing

```bash
# Test discovery extraction & ChromaDB RAG
cd backend
python -m pytest tests/test_rag.py -v

# Direct Python test of discovery scanner
python -c "from agents.discovery import scan_diff; print(scan_diff('sample_diff'))"
```
