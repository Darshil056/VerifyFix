import pytest
import sys
import os
import json
import time

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app  # noqa: E402


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ---------------------------------------------------------------------------
# Phase 1 Endpoint Tests
# ---------------------------------------------------------------------------

def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["status"] == "online"
    assert "VerifyFix" in json_data["service"]


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["status"] == "healthy"


def test_auth_session_fallback(client):
    response = client.get("/api/auth/session")
    assert response.status_code == 200
    json_data = response.get_json()
    assert "user" in json_data
    assert json_data["user"]["login"] is not None


def test_github_repos_demo_fallback(client, monkeypatch):
    import config
    monkeypatch.setattr(config, "GITHUB_TOKEN", None)
    response = client.post("/api/github/repos", json={})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert len(json_data["repos"]) > 0


def test_github_branches(client):
    response = client.post("/api/github/branches", json={"owner": "verifyfix-demo", "repo": "vulnerable-flask-auth"})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert "main" in json_data["branches"]


def test_github_diff(client):
    response = client.post("/api/github/diff", json={"owner": "test", "repo": "test", "branch": "main"})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert "diff" in json_data


# ---------------------------------------------------------------------------
# Phase 2 Scan API Tests
# ---------------------------------------------------------------------------

def test_scan_start(client):
    """Test that a scan can be started and returns a scan_id."""
    response = client.post("/api/scan/start", json={
        "repo_url": "test-org/test-repo",
        "branch_name": "main",
    })
    assert response.status_code == 201
    json_data = response.get_json()
    assert json_data["success"] is True
    assert "scan_id" in json_data
    assert "stream_url" in json_data
    assert "status_url" in json_data


def test_scan_start_defaults(client):
    """Test that scan start works with demo=True."""
    response = client.post("/api/scan/start", json={"demo": True})
    assert response.status_code == 201
    json_data = response.get_json()
    assert json_data["success"] is True
    assert json_data["scan_id"] is not None


def test_scan_status_not_found(client):
    """Test 404 for non-existent scan."""
    response = client.get("/api/scan/status?scan_id=nonexistent-id")
    assert response.status_code == 404
    json_data = response.get_json()
    assert json_data["success"] is False


def test_scan_status_after_start(client):
    """Test that status endpoint returns valid data after scan is started."""
    # Start a scan
    start_resp = client.post("/api/scan/start", json={
        "repo_url": "test-org/test-repo",
    })
    scan_id = start_resp.get_json()["scan_id"]

    # Wait briefly for the background thread to begin
    time.sleep(0.5)

    # Check status
    status_resp = client.get(f"/api/scan/status?scan_id={scan_id}")
    assert status_resp.status_code == 200
    json_data = status_resp.get_json()
    assert json_data["success"] is True
    assert json_data["scan_id"] == scan_id
    assert "state" in json_data


def test_scan_list(client):
    """Test the scan listing endpoint."""
    # Start a scan
    client.post("/api/scan/start", json={"demo": True})

    # List scans
    response = client.get("/api/scan/list")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert len(json_data["scans"]) >= 1


def test_scan_stream_not_found(client):
    """Test 404 for SSE stream of non-existent scan."""
    response = client.get("/api/scan/stream?scan_id=nonexistent")
    assert response.status_code == 404


def test_scan_result_not_found(client):
    """Test 404 for result of non-existent scan."""
    response = client.get("/api/scan/result?scan_id=nonexistent")
    assert response.status_code == 404


def test_scan_full_lifecycle(client):
    """Test the complete scan lifecycle: start → wait → status → result."""
    # Start scan
    start_resp = client.post("/api/scan/start", json={
        "repo_url": "lifecycle-test/vuln-app",
        "branch_name": "main",
    })
    assert start_resp.status_code == 201
    scan_id = start_resp.get_json()["scan_id"]

    # Wait for DAG to complete (stub nodes are fast)
    max_wait = 15
    elapsed = 0
    while elapsed < max_wait:
        time.sleep(0.5)
        elapsed += 0.5
        status_resp = client.get(f"/api/scan/status?scan_id={scan_id}")
        data = status_resp.get_json()
        if data.get("completed"):
            break

    # Should be completed now
    assert data["completed"] is True
    assert data["state"]["execution_step"] == "COMPLETED"

    # Fetch full result
    result_resp = client.get(f"/api/scan/result?scan_id={scan_id}")
    assert result_resp.status_code == 200
    result = result_resp.get_json()
    assert result["success"] is True
    assert len(result["final_remediations"]) > 0
    assert result["retry_count"] >= 1  # Retry loop should have fired
