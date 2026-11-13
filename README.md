# 🛡️ VerifyFix: Execution-Grounded AI Vulnerability Validator

[![CI/CD Pipeline](https://github.com/Darshil056/VerifyFix/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/Darshil056/VerifyFix/actions/workflows/ci-cd.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Next.js 15](https://img.shields.io/badge/Next.js-15-black.svg?logo=next.svg)](https://nextjs.org/)

VerifyFix is an execution-grounded AI vulnerability validation and remediation platform. It combines agentic LLM orchestration (LangGraph) with isolated sandbox execution to eliminate false positives and produce verified, deployable security fixes.

---

## 🏗️ Architecture Overview

```
VerifyFix Monorepo
├── backend/                  # Flask REST API & LangGraph state machine
│   ├── app.py                # Core application factory & route handlers
│   ├── config.py             # Config & environment variable loader
│   ├── requirements.txt      # Python dependencies
│   └── tests/                # Automated pytest suites
├── frontend/                 # Next.js 15 (App Router) + Tailwind CSS
│   ├── src/app/              # Pages, layout, and UI components
│   └── package.json          # Node dependencies & build scripts
└── .github/workflows/        # CI/CD workflows for testing & deployment
```

### Tech Stack
- **Frontend:** Next.js (App Router), React, Tailwind CSS, Lucide Icons
- **Backend:** Python 3.11, Flask, Flask-CORS, Gunicorn
- **Orchestration:** LangGraph (DAG State Machine)
- **Vector DB & RAG:** ChromaDB (Persistent)
- **CI/CD:** GitHub Actions (ESLint, TypeScript, Pytest, Flake8)

---

## 🚀 Getting Started

### Prerequisites
- Node.js 18+ and npm
- Python 3.11+

### 1. Backend Setup

```bash
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env

# Run development server
python app.py
```
The backend will start at `http://127.0.0.1:5000`.

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```
The frontend will start at `http://localhost:3000`.

---

## 🧪 Running Tests

### Backend Tests
```bash
cd backend
pytest
```

### Frontend Lint & Type Checks
```bash
cd frontend
npm run lint
```

---

## 📄 License
This project is licensed under the MIT License.
