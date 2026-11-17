# Phase 6 Implementation Plan: Next.js Real-Time Animated DAG Dashboard (React Flow)

## 1. Overview & Objectives
Phase 6 builds the frontend user experience for VerifyFix. It integrates `@xyflow/react` (React Flow) to visually render the live LangGraph execution state machine, subscribes to the Flask Server-Sent Events (SSE) stream, and animates node states, logs, and verified findings in real time.

---

## 2. Technical Specifications

### 2.1 8-Node React Flow Visualizer (`frontend/src/components/dag/DagVisualizer.tsx`)
Render the 8 formal nodes:
1. `node_github_ingest`: GitHub Ingest (Read-Only)
2. `node_discovery`: Candidate Discovery Agent (Gemini 2.5 Flash)
3. `node_rag`: Constrained Vector RAG (ChromaDB)
4. `node_critic`: Critic Triage & Fixture Generator
5. `node_sandbox`: Docker Sandbox Execution
6. `node_retry`: Self-Healing Loop (`HARNESS_ERROR`)
7. `node_remediation`: Senior Remediation Compiler
8. `node_complete`: VerifyFix Dashboard (Final Report)

#### Live Animation & Color Tokens:
| Node State | Visual Styling | Indicator |
| :--- | :--- | :--- |
| **Idle** | Dark slate background, 1px neutral border (`border-slate-700`) | Dim node icon |
| **Running** | Pulsing cyan/blue border (`border-cyan-400 animate-pulse`), glowing shadow | Animated spinner icon |
| **Confirmed Vulnerability** | Crimson red border (`border-rose-500`), subtle red glow | Bug badge with count |
| **Secure / False Alarm Discarded** | Emerald green border (`border-emerald-500`) | Green checkmark badge |
| **Healing Loop Active** | Amber/Orange directional pulse along edge (`border-amber-400`) | Re-attempt counter (e.g., `Retry 1/3`) |

### 2.2 Live SSE Hook (`frontend/src/hooks/useScanStream.ts`)
- Subscribes to `http://localhost:5000/api/scan/stream?scan_id=<ID>` using `EventSource`.
- Updates React Flow node states on `node_update` events.
- Appends to live log stream on `log` events.
- Stores verified findings on `state_delta` events.

### 2.3 Terminal Log Console (`frontend/src/components/terminal/TerminalView.tsx`)
- Dark high-contrast streaming terminal window.
- Auto-scrolls as new logs arrive from the backend.
- Color-coded log level tags: `[INFO]`, `[DISCOVERY]`, `[SANDBOX]`, `[CONFIRMED]`, `[HEALING]`.

### 2.4 Findings & Report Drawer (`frontend/src/components/findings/FindingsDrawer.tsx`)
- Displays real-time metrics: Total candidates, Pruned false positives, Confirmed exploits.
- Displays confirmed vulnerability cards with CWE badges and code snippets.
- Includes the interactive **"Download Word Audit Report (.docx)"** button that triggers `GET /api/report/download?scan_id=...`.

### 2.5 Integrated Dashboard (`frontend/src/app/dashboard/page.tsx`)
- **Top Bar**:
  - Connected repository & active branch dropdown.
  - "Start Verification Scan" trigger button.
  - Quick demo selector: `Vulnerable Flask Auth (SQLi)`, `Insecure Express (SSRF)`, `FastAPI IDOR`.
- **Center Canvas**: Interactive React Flow visualizer with zoom/pan and minimap.
- **Bottom / Side Drawer**: Tabbed interface switching between Live Execution Terminal and Verified Findings.

---

## 3. Implementation Steps

1. **Install Frontend Dependencies**:
   ```bash
   cd frontend
   npm install @xyflow/react lucide-react clsx tailwind-merge
   ```
2. **Build Custom Nodes (`frontend/src/components/dag/CustomNode.tsx`)**:
   Create styled nodes with badge indicators and glow effects.
3. **Build Visualizer Canvas (`frontend/src/components/dag/DagVisualizer.tsx`)**:
   Setup initial nodes and edges, including the dashed animated feedback edge for self-healing.
4. **Build Stream Hook (`frontend/src/hooks/useScanStream.ts`)**:
   Implement EventSource listener with reconnection and state update logic.
5. **Build Terminal & Findings Panels**:
   Create `TerminalView.tsx` and `FindingsDrawer.tsx`.
6. **Assemble `frontend/src/app/dashboard/page.tsx`**:
   Connect controls, DAG visualizer, terminal, and report download action.
7. **Verify Frontend Build**:
   Run `npm run build` and `npm run lint`.

---

## 4. Verification & Testing

```bash
# Verify build
cd frontend
npm run build

# Start frontend dev server
npm run dev

# Open in browser
http://localhost:3000/dashboard
```
- Verify DAG nodes render with correct initial states.
- Trigger a scan and observe node color transitions and glowing effects.
- Confirm live logs stream into the terminal.
- Click "Download Word Report" upon completion and verify file download.
