# VerifyFix - Project Context for Resume

**Project Name:** VerifyFix: Execution-Grounded AI Vulnerability Validator
**Role:** Full Stack / AI Software Engineer

## 🚀 Short Project Description (Elevator Pitch)
Developed VerifyFix, an execution-grounded AI vulnerability validation and remediation platform. It leverages agentic LLM orchestration via LangGraph and isolated Docker sandbox execution to detect, validate, and automatically remediate security flaws, eliminating false positives and producing verified, deployable code fixes.

---

## 🛠️ Tech Stack & Skills Used
* **Frontend:** Next.js 15 (App Router), React, Tailwind CSS, React Flow (@xyflow/react), NextAuth.js
* **Backend:** Python 3.11, Flask, Flask-CORS, Gunicorn
* **AI & Orchestration:** LangGraph (DAG State Machine), Google Gemini 2.5 Flash, ChromaDB, Sentence-Transformers (RAG)
* **DevOps & Execution:** Docker Sandbox, GitHub Actions (CI/CD), Server-Sent Events (SSE) streaming
* **Database:** MongoDB, ChromaDB (Vector Store)

---

## 🌟 Key Features & Accomplishments to Highlight

* **Agentic AI Orchestration:** Designed and implemented a hierarchical LangGraph Directed Acyclic Graph (DAG) state machine to coordinate specialized LLM agents (Discovery, Critic, Remediation). Optimized LLM token usage and execution via targeted temperature control and zero-redundancy state passing.
* **Execution-Grounded Validation (Zero False Positives):** Engineered a dynamic test fixture generation system that extracts suspect code and runs it in an isolated Docker sandbox. The system uses real execution exit codes to definitively confirm exploitability and self-correct on harness errors, virtually eliminating false-positive security alerts.
* **On-Demand Contextual RAG:** Built an automated Threat Intelligence ingestion pipeline using ChromaDB. Dynamically scraped and vectorized MITRE CWE definitions to provide precise context to the LLM agent, enhancing remediation accuracy.
* **Real-Time Interactive Dashboard:** Developed a dynamic Next.js React Flow dashboard mapping the live LangGraph execution state. Consumed real-time Server-Sent Events (SSE) from the Flask backend to visualize node transitions, live terminal logs, and real-time vulnerability statistics.
* **Automated Audit Reporting:** Implemented a backend service using `python-docx` to synthesize validated vulnerability data, sandbox execution proof, and remediation advice into professional, formatted Word (.docx) security audit reports.
* **CI/CD & Security:** Set up robust GitHub Actions workflows for continuous integration (linting, type checking, pytest) and automated deployments. Integrated GitHub OAuth securely to allow read-only repository scanning.

---

## 📝 Example Resume Bullet Points

* **Engineered VerifyFix**, an AI-driven vulnerability validator using **Python, Flask, and Next.js**, reducing false-positive security alerts through execution-grounded **Docker** sandbox testing.
* **Orchestrated a Multi-Agent System** using **LangGraph** and **Google Gemini**, integrating a **ChromaDB RAG** pipeline to dynamically retrieve MITRE CWE threat context for accurate automated remediation.
* **Developed a Real-Time Interactive Dashboard** in **React Flow** and **Tailwind CSS**, consuming **Server-Sent Events (SSE)** to visualize live AI decision-making graphs and streaming execution logs.
* **Automated Security Audit Reporting** by generating dynamic `.docx` reports containing verified vulnerability proofs, root-cause analysis, and safe-code patches using **python-docx**.
* **Implemented CI/CD pipelines** using **GitHub Actions** and secured user onboarding with **NextAuth.js** and **GitHub OAuth** integration.
