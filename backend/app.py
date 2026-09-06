import logging
import json
import threading
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, request, Response, stream_with_context, send_file
from flask_cors import CORS
import requests as http_requests

from config import config
from agents.state import create_initial_state, VerifyFixState
from agents.graph import VerifyFixDAG
from services.mongodb import init_mongo, save_scan, mark_scan_completed, is_fallback

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("verifyfix-backend")


# ---------------------------------------------------------------------------
# Thread-safe Scan Registry
# ---------------------------------------------------------------------------

class ScanRegistry:
    """
    In-memory registry of active and completed scans.
    Thread-safe access via a reentrant lock.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._scans: dict = {}        # scan_id -> state dict
        self._events: dict = {}       # scan_id -> list of SSE event dicts
        self._completed: dict = {}    # scan_id -> bool

    def register(self, scan_id: str, state: VerifyFixState):
        with self._lock:
            self._scans[scan_id] = state
            self._events[scan_id] = []
            self._completed[scan_id] = False
            # Persist to MongoDB
            save_scan(scan_id, dict(state))

    def get_state(self, scan_id: str):
        with self._lock:
            return self._scans.get(scan_id)

    def update_state(self, scan_id: str, state: VerifyFixState):
        with self._lock:
            self._scans[scan_id] = state
            save_scan(scan_id, dict(state))

    def push_event(self, scan_id: str, event: dict):
        with self._lock:
            if scan_id in self._events:
                self._events[scan_id].append(event)

    def get_events(self, scan_id: str, from_index: int = 0):
        with self._lock:
            events = self._events.get(scan_id, [])
            return events[from_index:]

    def mark_completed(self, scan_id: str):
        with self._lock:
            self._completed[scan_id] = True
            state = self._scans.get(scan_id, {})
            mark_scan_completed(scan_id, dict(state))

    def is_completed(self, scan_id: str) -> bool:
        with self._lock:
            return self._completed.get(scan_id, False)

    def exists(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._scans

    def list_scans(self):
        with self._lock:
            return {
                sid: {
                    "execution_step": s.get("execution_step", "UNKNOWN"),
                    "completed": self._completed.get(sid, False),
                    "repo": f"{s.get('repo_owner', '?')}/{s.get('repo_name', '?')}",
                    "started_at": s.get("started_at"),
                }
                for sid, s in self._scans.items()
            }


# Global scan registry
scan_registry = ScanRegistry()


def create_app():
    app = Flask(__name__)
    app.config.from_object(config)

    # Initialize MongoDB (falls back to in-memory if unavailable)
    init_mongo(config.MONGO_URI, config.MONGO_DB_NAME)

    # Enable Cross-Origin Resource Sharing
    CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

    # -----------------------------------------------------------------------
    # Root & Health
    # -----------------------------------------------------------------------

    @app.route("/", methods=["GET"])
    def root():
        return jsonify({
            "service": "VerifyFix AI Vulnerability Validator Engine",
            "version": "2.0.0-phase2",
            "status": "online",
            "phase": "Phase 2 — LangGraph State Machine & SSE Engine",
            "llm_provider": "Google Gemini 2.5 Flash",
            "database": "MongoDB" if not is_fallback() else "In-Memory (MongoDB unavailable)",
            "endpoints": {
                "health": "/health",
                "scan_start": "POST /api/scan/start",
                "scan_stream": "GET /api/scan/stream?scan_id=<ID>",
                "scan_status": "GET /api/scan/status?scan_id=<ID>",
                "scan_list": "GET /api/scan/list",
            },
        }), 200

    @app.route("/health", methods=["GET"])
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "healthy",
            "service": "verifyfix-backend",
            "version": "2.0.0-phase2",
            "environment": "development" if config.DEBUG else "production"
        }), 200

    # -----------------------------------------------------------------------
    # Auth & GitHub (Phase 1 endpoints — preserved)
    # -----------------------------------------------------------------------

    @app.route("/api/auth/session", methods=["GET", "POST"])
    def auth_session():
        """
        Validates the incoming user session or GitHub token.
        """
        auth_header = request.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
        elif request.is_json:
            token = request.json.get("token", "")

        if not token and config.GITHUB_TOKEN:
            token = config.GITHUB_TOKEN

        if token:
            # Query GitHub user API
            try:
                headers = {
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "VerifyFix-App"
                }
                gh_res = http_requests.get("https://api.github.com/user", headers=headers, timeout=5)
                if gh_res.status_code == 200:
                    user_data = gh_res.json()
                    return jsonify({
                        "authenticated": True,
                        "user": {
                            "login": user_data.get("login"),
                            "name": user_data.get("name") or user_data.get("login"),
                            "avatar_url": user_data.get("avatar_url"),
                            "html_url": user_data.get("html_url")
                        }
                    }), 200
            except Exception as e:
                logger.warning(f"GitHub user query failed: {e}")

        # Fallback / Demo session
        return jsonify({
            "authenticated": False,
            "demo_mode": True,
            "user": {
                "login": "developer-guest",
                "name": "VerifyFix Guest Explorer",
                "avatar_url": "https://avatars.githubusercontent.com/u/9919?v=4",
                "html_url": "https://github.com"
            }
        }), 200

    @app.route("/api/github/repos", methods=["POST"])
    def list_repos():
        """
        Lists repositories available to the user or popular public demonstration repositories.
        """
        data = request.get_json(silent=True) or {}
        token = data.get("token") or config.GITHUB_TOKEN
        username = data.get("username")

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "VerifyFix-App"
        }
        if token:
            headers["Authorization"] = f"token {token}"

        try:
            if token and not username:
                url = "https://api.github.com/user/repos?sort=updated&per_page=30"
            elif username:
                url = f"https://api.github.com/users/{username}/repos?sort=updated&per_page=30"
            else:
                # Return sample vulnerable demo repositories for instant testing
                return jsonify({
                    "success": True,
                    "source": "demo",
                    "repos": [
                        {
                            "id": 101,
                            "name": "vulnerable-flask-auth",
                            "full_name": "verifyfix-demo/vulnerable-flask-auth",
                            "owner": "verifyfix-demo",
                            "description": "Demonstration Flask app containing SQL injection (CWE-89) & command injection",
                            "default_branch": "main",
                            "private": False,
                            "updated_at": "2026-03-01T10:00:00Z"
                        },
                        {
                            "id": 102,
                            "name": "insecure-node-express",
                            "full_name": "verifyfix-demo/insecure-node-express",
                            "owner": "verifyfix-demo",
                            "description": "Express.js target with Prototype Pollution (CWE-1321) & SSRF (CWE-918)",
                            "default_branch": "master",
                            "private": False,
                            "updated_at": "2026-02-28T14:30:00Z"
                        },
                        {
                            "id": 103,
                            "name": "ecommerce-api-fastapi",
                            "full_name": "verifyfix-demo/ecommerce-api-fastapi",
                            "owner": "verifyfix-demo",
                            "description": "FastAPI microservice with Insecure Direct Object References (IDOR / CWE-639)",
                            "default_branch": "main",
                            "private": False,
                            "updated_at": "2026-02-20T08:15:00Z"
                        }
                    ]
                }), 200

            gh_res = http_requests.get(url, headers=headers, timeout=8)
            if gh_res.status_code == 200:
                raw_repos = gh_res.json()
                repos = [
                    {
                        "id": r.get("id"),
                        "name": r.get("name"),
                        "full_name": r.get("full_name"),
                        "owner": r.get("owner", {}).get("login"),
                        "description": r.get("description") or "No description provided",
                        "default_branch": r.get("default_branch", "main"),
                        "private": r.get("private", False),
                        "updated_at": r.get("updated_at")
                    }
                    for r in raw_repos
                ]
                return jsonify({
                    "success": True,
                    "source": "github_api",
                    "repos": repos
                }), 200
            else:
                err_msg = f"GitHub API error: {gh_res.status_code}"
                return jsonify({"success": False, "error": err_msg, "repos": []}), gh_res.status_code
        except Exception as e:
            logger.error(f"Error fetching repos: {e}")
            return jsonify({"success": False, "error": str(e), "repos": []}), 500

    @app.route("/api/github/branches", methods=["POST"])
    def list_branches():
        data = request.get_json(silent=True) or {}
        owner = data.get("owner")
        repo = data.get("repo")
        token = data.get("token") or config.GITHUB_TOKEN

        if not owner or not repo:
            return jsonify({"success": False, "error": "Missing owner or repo parameter"}), 400

        # Handle demo repos
        if owner == "verifyfix-demo":
            return jsonify({
                "success": True,
                "branches": ["main", "feature/auth-patch", "dev", "vulnerability-test"]
            }), 200

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "VerifyFix-App"
        }
        if token:
            headers["Authorization"] = f"token {token}"

        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/branches"
            gh_res = http_requests.get(url, headers=headers, timeout=8)
            if gh_res.status_code == 200:
                branches = [b["name"] for b in gh_res.json()]
                return jsonify({"success": True, "branches": branches}), 200
            return jsonify({"success": False, "branches": ["main"]}), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e), "branches": ["main"]}), 200

    @app.route("/api/github/diff", methods=["POST"])
    def get_diff():
        data = request.get_json(silent=True) or {}
        owner = data.get("owner")
        repo = data.get("repo")
        branch = data.get("branch", "main")

        # Return realistic sample diff if demo repo or fallback
        sample_diff = (
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
        return jsonify({
            "success": True,
            "owner": owner,
            "repo": repo,
            "branch": branch,
            "diff": sample_diff
        }), 200

    # -----------------------------------------------------------------------
    # Phase 2: Scan API & SSE Streaming Engine
    # -----------------------------------------------------------------------

    @app.route("/api/scan/start", methods=["POST"])
    def scan_start():
        """
        Register and launch a new vulnerability scan.

        Request body (JSON):
            - repo_owner (str): GitHub repository owner
            - repo_name (str): Repository name
            - branch_name (str, optional): Branch to scan (default: main)
            - target_diff (str, optional): Pre-fetched diff content

        Returns:
            - scan_id: Unique identifier for the scan session
            - stream_url: SSE endpoint URL to subscribe to
        """
        data = request.get_json(silent=True) or {}

        is_demo = data.get("demo", False)
        github_token = data.get("token")
        repo_url = data.get("repo_url", "").strip()

        if is_demo:
            repo_owner = "verifyfix-demo"
            repo_name = "vulnerable-flask-auth"
            branch_name = "main"
        else:
            # Try parsing the URL (e.g., https://github.com/owner/repo)
            import re
            match = re.search(r"github\.com/([^/]+)/([^/]+)", repo_url)
            if match:
                repo_owner = match.group(1)
                repo_name = match.group(2).replace(".git", "")
            else:
                # Fallback if the user just pasted "owner/repo"
                parts = repo_url.split("/")
                if len(parts) == 2:
                    repo_owner, repo_name = parts
                else:
                    return jsonify({"success": False, "error": "Invalid GitHub repository URL or format."}), 400
            
            branch_name = data.get("branch_name", "main")

        target_diff = data.get("target_diff", "")
        scan_id = str(uuid.uuid4())

        # Create initial state
        state = create_initial_state(
            repo_owner=repo_owner,
            repo_name=repo_name,
            branch_name=branch_name,
            github_token=github_token,
            target_diff=target_diff,
            scan_id=scan_id,
        )

        # Register in the scan registry
        scan_registry.register(scan_id, state)

        # Launch DAG execution in a background thread
        def _run_dag():
            try:
                dag = VerifyFixDAG()
                for event in dag.execute(state):
                    scan_registry.push_event(scan_id, event)
                    scan_registry.update_state(scan_id, state)
            except Exception as e:
                logger.error(f"DAG execution failed for scan {scan_id}: {e}", exc_info=True)
                scan_registry.push_event(scan_id, {
                    "event": "error",
                    "data": {"message": str(e), "timestamp": datetime.now(timezone.utc).isoformat()},
                })
            finally:
                scan_registry.mark_completed(scan_id)
                scan_registry.update_state(scan_id, state)

        thread = threading.Thread(target=_run_dag, daemon=True)
        thread.start()

        logger.info(f"Scan {scan_id} started for {repo_owner}/{repo_name}@{branch_name}")

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "stream_url": f"/api/scan/stream?scan_id={scan_id}",
            "status_url": f"/api/scan/status?scan_id={scan_id}",
            "message": f"Scan initiated for {repo_owner}/{repo_name}@{branch_name}",
        }), 201

    @app.route("/api/scan/stream", methods=["GET"])
    def scan_stream():
        """
        Server-Sent Events (SSE) endpoint for real-time scan progress.

        Query params:
            - scan_id (str): The scan identifier returned by /api/scan/start

        Streams events in SSE format:
            event: node_update
            data: {"step": "DISCOVERY", "status": "running", ...}

            event: log
            data: {"message": "...", "timestamp": "..."}

            event: state_delta
            data: {"candidate_vulns": [...], ...}
        """
        scan_id = request.args.get("scan_id", "")

        if not scan_id or not scan_registry.exists(scan_id):
            return jsonify({
                "success": False,
                "error": f"Scan '{scan_id}' not found. Start a scan first via POST /api/scan/start",
            }), 404

        def _generate():
            event_index = 0
            heartbeat_counter = 0

            while True:
                # Fetch new events since last check
                new_events = scan_registry.get_events(scan_id, from_index=event_index)

                if new_events:
                    for event in new_events:
                        event_type = event.get("event", "message")
                        event_data = json.dumps(event.get("data", {}))
                        yield f"event: {event_type}\ndata: {event_data}\n\n"
                        event_index += 1

                    heartbeat_counter = 0
                else:
                    # Send heartbeat comment to keep connection alive
                    heartbeat_counter += 1
                    if heartbeat_counter % 10 == 0:
                        yield f": heartbeat {datetime.now(timezone.utc).isoformat()}\n\n"

                # Check if scan is completed
                if scan_registry.is_completed(scan_id):
                    # Drain any remaining events
                    remaining = scan_registry.get_events(scan_id, from_index=event_index)
                    for event in remaining:
                        event_type = event.get("event", "message")
                        event_data = json.dumps(event.get("data", {}))
                        yield f"event: {event_type}\ndata: {event_data}\n\n"

                    # Signal end of stream
                    yield f"event: stream_end\ndata: {json.dumps({'scan_id': scan_id, 'message': 'Scan completed'})}\n\n"
                    break

                import time
                time.sleep(0.2)

        return Response(
            stream_with_context(_generate()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    @app.route("/api/scan/status", methods=["GET"])
    def scan_status():
        """
        Returns the current state snapshot for a scan.

        Query params:
            - scan_id (str): The scan identifier
        """
        scan_id = request.args.get("scan_id", "")

        if not scan_id or not scan_registry.exists(scan_id):
            return jsonify({
                "success": False,
                "error": f"Scan '{scan_id}' not found",
            }), 404

        state = scan_registry.get_state(scan_id)
        completed = scan_registry.is_completed(scan_id)

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "completed": completed,
            "state": {
                "execution_step": state.get("execution_step"),
                "started_at": state.get("started_at"),
                "completed_at": state.get("completed_at"),
                "retry_count": state.get("retry_count", 0),
                "candidate_vulns_count": len(state.get("candidate_vulns", [])),
                "pruned_vulns_count": len(state.get("pruned_vulns", [])),
                "confirmed_count": sum(
                    1 for s in state.get("docker_status", {}).values()
                    if s == "VULNERABILITY_CONFIRMED"
                ),
                "remediations_count": len(state.get("final_remediations", [])),
                "logs": state.get("logs", []),
                "error": state.get("error"),
            },
        }), 200

    @app.route("/api/scan/list", methods=["GET"])
    def scan_list():
        """Returns a summary of all registered scans."""
        return jsonify({
            "success": True,
            "scans": scan_registry.list_scans(),
        }), 200

    @app.route("/api/scan/result", methods=["GET"])
    def scan_result():
        """
        Returns the full final result of a completed scan including
        all remediations, docker verdicts, and execution logs.
        """
        scan_id = request.args.get("scan_id", "")

        if not scan_id or not scan_registry.exists(scan_id):
            return jsonify({"success": False, "error": f"Scan '{scan_id}' not found"}), 404

        state = scan_registry.get_state(scan_id)
        completed = scan_registry.is_completed(scan_id)

        if not completed:
            return jsonify({
                "success": False,
                "error": "Scan is still in progress",
                "execution_step": state.get("execution_step"),
            }), 202

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "repo": f"{state.get('repo_owner')}/{state.get('repo_name')}",
            "branch": state.get("branch_name"),
            "started_at": state.get("started_at"),
            "completed_at": state.get("completed_at"),
            "candidate_vulns": state.get("candidate_vulns", []),
            "pruned_vulns": state.get("pruned_vulns", []),
            "docker_status": state.get("docker_status", {}),
            "final_remediations": state.get("final_remediations", []),
            "retry_count": state.get("retry_count", 0),
            "logs": state.get("logs", []),
        }), 200

    @app.route("/api/report/download", methods=["GET"])
    def download_report():
        """
        Generates and serves a .docx vulnerability report for a completed scan.
        """
        from services.report_generator import generate_docx_report
        
        scan_id = request.args.get("scan_id", "")

        if not scan_id or not scan_registry.exists(scan_id):
            return jsonify({"success": False, "error": f"Scan '{scan_id}' not found"}), 404

        completed = scan_registry.is_completed(scan_id)
        if not completed:
            return jsonify({
                "success": False,
                "error": "Scan is not completed yet"
            }), 400

        state = scan_registry.get_state(scan_id)
        
        try:
            docx_stream = generate_docx_report(state)
            
            return send_file(
                docx_stream,
                mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                as_attachment=True,
                download_name=f"VerifyFix_Audit_Report_{scan_id}.docx"
            )
        except Exception as e:
            logger.error(f"Failed to generate report for {scan_id}: {e}")
            return jsonify({"success": False, "error": "Internal error generating report"}), 500

    return app


app = create_app()

if __name__ == "__main__":
    logger.info(f"Starting VerifyFix API Engine v2.0.0-phase2 on port {config.PORT}...")
    app.run(host="0.0.0.0", port=config.PORT, debug=config.DEBUG)
