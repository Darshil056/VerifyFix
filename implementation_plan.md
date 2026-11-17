# Implementation Plan - Phase 1: Project Foundation & Infrastructure Setup

Set up the monorepo foundation for **VerifyFix**, including the Flask backend API, Next.js frontend with Tailwind CSS and NextAuth/GitHub repository onboarding, and GitHub Actions CI/CD workflows.

## User Review Required

> [!NOTE]
> For local testing of GitHub/Google OAuth, credentials can be added to `frontend/.env.local` and `backend/.env`. Placeholder fallback support (direct GitHub Personal Access Token or demo repos) will be provided out of the box so development and UI testing can proceed immediately even without live OAuth apps configured.

---

## Proposed Changes

### Root & CI/CD Configuration

#### [NEW] [.gitignore](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/.gitignore)
- Standard monorepo `.gitignore` covering Python (`venv/`, `__pycache__/`, `.pytest_cache/`, `*.pyc`), Node.js (`node_modules/`, `.next/`, `out/`, `dist/`), and environment files (`.env`, `.env.local`).

#### [NEW] [.github/workflows/ci-cd.yml](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/.github/workflows/ci-cd.yml)
- **Job 1 (Lint & Test)**: 
  - Sets up Python and Node.js environments.
  - Runs `pytest` and `flake8` for the `backend/`.
  - Runs TypeScript check and ESLint for the `frontend/`.
- **Job 2 (Deploy Frontend)**:
  - Vercel deployment step triggered on `main` branch pushes.
- **Job 3 (Deploy Backend)**:
  - Render / Fly.io deploy webhook trigger on `main` branch pushes.

---

### Backend (`backend/`)

#### [NEW] [backend/requirements.txt](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/backend/requirements.txt)
- Essential dependencies: `flask`, `flask-cors`, `gunicorn`, `python-dotenv`, `requests`, `pytest`, `flake8`, `python-docx`.

#### [NEW] [backend/config.py](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/backend/config.py)
- Configuration loader for environment variables (GitHub tokens, Gemini API keys, MongoDB credentials, Flask Secret).

#### [NEW] [backend/app.py](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/backend/app.py)
- Flask application factory with CORS enabled.
- Endpoints:
  - `GET /health`: Health check endpoint.
  - `GET /api/auth/session`: Session validation endpoint.
  - `POST /api/github/repos`: Lists accessible GitHub repositories and branches given an access token or public repo identifier.
  - `POST /api/github/diff`: Fetches pull request / branch diffs for security analysis.

#### [NEW] [backend/.env.example](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/backend/.env.example)
- Example configuration with descriptions for all backend environment variables.

#### [NEW] [backend/tests/test_api.py](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/backend/tests/test_api.py)
- Pytest suite testing health check and API endpoints to satisfy CI requirements.

---

### Frontend (`frontend/`)

#### [NEW] Next.js 14/15 App Router Project Structure
- Initialized with TypeScript, Tailwind CSS, Lucide icons, and modern design tokens.

#### [NEW] [frontend/src/app/page.tsx](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/frontend/src/app/page.tsx)
- Premium dark-mode landing page highlighting VerifyFix execution-grounded architecture, live DAG capabilities, and direct CTA to onboarding.

#### [NEW] [frontend/src/app/auth/page.tsx](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/frontend/src/app/auth/page.tsx)
- Authentication interface supporting GitHub OAuth, Google OAuth, and manual PAT/Demo mode.

#### [NEW] [frontend/src/app/dashboard/page.tsx](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/frontend/src/app/dashboard/page.tsx)
- Repository onboarding and branch selector with search, active branch picking, and "Start Verification Scan" action.

#### [NEW] [frontend/src/lib/api.ts](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/frontend/src/lib/api.ts)
- Typed API client communicating with Flask backend.

#### [NEW] [frontend/.env.example](file:///c:/Users/VICTUS/OneDrive/Desktop/Verifyfix/frontend/.env.example)
- Frontend environment variable template.

---

## Verification Plan

### Automated Tests
1. **Backend Tests**: Run `pytest` on `backend/tests/test_api.py`.
2. **Backend Linting**: Run `flake8 backend/ --max-line-length=120 --exclude=venv,__pycache__`.
3. **Frontend Build & Lint**: Run `npm run lint` and `npm run build` in `frontend/`.

### Manual Verification
1. Start Flask backend (`python backend/app.py`) on port 5000 and verify `GET http://localhost:5000/health`.
2. Test `/api/github/repos` with sample inputs.
3. Start Next.js frontend (`npm run dev`) on port 3000 and verify:
   - Landing page styling and navigation.
   - Auth page UI & demo token fallback.
   - Dashboard repository selector and branch selection.
