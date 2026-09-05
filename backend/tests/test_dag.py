"""
VerifyFix DAG Unit Tests
========================

Tests for the LangGraph-style DAG executor, node traversal order,
retry-count boundary conditions, and SSE event generation.
"""

import pytest
import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.state import (  # noqa: E402
    VerifyFixState,
    create_initial_state,
    EXECUTION_STEPS,
    VulnerabilityCandidate,
    RemediationItem,
)
from agents.graph import VerifyFixDAG, should_retry, MAX_RETRIES  # noqa: E402
from agents.nodes import (  # noqa: E402
    node_github_ingest,
    node_discovery,
    node_rag,
    node_critic,
    node_sandbox,
    node_remediation,
    node_complete,
)


# ---------------------------------------------------------------------------
# State Creation Tests
# ---------------------------------------------------------------------------

class TestStateCreation:

    def test_create_initial_state_defaults(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        assert state["repo_owner"] == "test"
        assert state["repo_name"] == "repo"
        assert state["branch_name"] == "main"
        assert state["execution_step"] == "INITIALIZED"
        assert state["retry_count"] == 0
        assert state["candidate_vulns"] == []
        assert state["logs"] == []
        assert state["scan_id"] is not None
        assert state["started_at"] is not None
        assert state["completed_at"] is None
        assert state["error"] is None

    def test_create_initial_state_custom_params(self):
        state = create_initial_state(
            repo_owner="acme",
            repo_name="web-app",
            branch_name="develop",
            target_diff="some diff",
            scan_id="custom-id-123",
        )
        assert state["repo_owner"] == "acme"
        assert state["repo_name"] == "web-app"
        assert state["branch_name"] == "develop"
        assert state["target_diff"] == "some diff"
        assert state["scan_id"] == "custom-id-123"

    def test_execution_steps_constants(self):
        assert "INITIALIZED" in EXECUTION_STEPS
        assert "COMPLETED" in EXECUTION_STEPS
        assert "RETRY" in EXECUTION_STEPS
        assert "ERROR" in EXECUTION_STEPS


# ---------------------------------------------------------------------------
# Individual Node Tests
# ---------------------------------------------------------------------------

class TestNodes:

    def _drain_generator(self, gen):
        """Run a node generator to completion, collecting events and final state."""
        events = []
        state = None
        try:
            while True:
                event = next(gen)
                events.append(event)
        except StopIteration as e:
            state = e.value
        return events, state

    def test_node_github_ingest(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        events, result = self._drain_generator(node_github_ingest(state))

        assert len(events) > 0
        assert any(e["event"] == "node_update" for e in events)
        assert any(e["event"] == "log" for e in events)
        assert state["execution_step"] == "GITHUB_INGEST"
        # Should load demo diff since none was provided
        assert state["target_diff"] != ""

    def test_node_github_ingest_with_diff(self):
        state = create_initial_state(
            repo_owner="test", repo_name="repo",
            target_diff="my custom diff content"
        )
        events, result = self._drain_generator(node_github_ingest(state))
        assert state["target_diff"] == "my custom diff content"

    def test_node_discovery(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        events, _ = self._drain_generator(node_discovery(state))

        assert len(state["candidate_vulns"]) > 0
        assert all("cwe_id" in v for v in state["candidate_vulns"])
        assert state["execution_step"] == "DISCOVERY"

    def test_node_rag(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        events, _ = self._drain_generator(node_rag(state))

        assert len(state["rag_context"]) > 0
        assert "CWE-89" in state["rag_context"]
        assert state["execution_step"] == "RAG"

    def test_node_critic(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        # Setup prerequisites
        state["candidate_vulns"] = [
            {"cwe_id": "CWE-89", "vulnerability_name": "SQL Injection",
             "file_path": "auth.py", "line_start": 1, "line_end": 5,
             "suspect_code": "test", "reasoning": "test"},
            {"cwe_id": "CWE-200", "vulnerability_name": "Info Exposure",
             "file_path": "auth.py", "line_start": 1, "line_end": 1,
             "suspect_code": "test", "reasoning": "test"},
        ]

        events, _ = self._drain_generator(node_critic(state))

        assert len(state["pruned_vulns"]) == 1
        assert state["pruned_vulns"][0]["cwe_id"] == "CWE-89"
        assert len(state["generated_fixtures"]) > 0
        assert state["execution_step"] == "CRITIC"

    def test_node_sandbox_first_run_harness_error(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        state["generated_fixtures"] = {"CWE-89_test": "print('test')"}
        state["retry_count"] = 0

        events, _ = self._drain_generator(node_sandbox(state))

        assert state["docker_status"]["CWE-89_test"] == "HARNESS_ERROR"
        assert "CWE-89_test" in state["harness_error_traces"]

    def test_node_sandbox_retry_confirms(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        state["generated_fixtures"] = {"CWE-89_test": "print('test')"}
        state["retry_count"] = 1

        events, _ = self._drain_generator(node_sandbox(state))

        assert state["docker_status"]["CWE-89_test"] == "VULNERABILITY_CONFIRMED"

    def test_node_remediation(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        state["docker_status"] = {"CWE-89_test": "VULNERABILITY_CONFIRMED"}

        events, _ = self._drain_generator(node_remediation(state))

        assert len(state["final_remediations"]) > 0
        assert state["final_remediations"][0]["severity"] == "CRITICAL"
        assert state["execution_step"] == "REMEDIATION"

    def test_node_complete(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        state["docker_status"] = {"CWE-89": "VULNERABILITY_CONFIRMED"}
        state["final_remediations"] = [{"cwe_id": "CWE-89"}]

        events, _ = self._drain_generator(node_complete(state))

        assert state["execution_step"] == "COMPLETED"
        assert state["completed_at"] is not None


# ---------------------------------------------------------------------------
# Conditional Edge Tests
# ---------------------------------------------------------------------------

class TestConditionalEdge:

    def test_should_retry_on_harness_error(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        state["docker_status"] = {"test": "HARNESS_ERROR"}
        state["retry_count"] = 0
        assert should_retry(state) == "retry_critic"

    def test_should_not_retry_at_max(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        state["docker_status"] = {"test": "HARNESS_ERROR"}
        state["retry_count"] = MAX_RETRIES
        assert should_retry(state) == "proceed_to_remediation"

    def test_should_proceed_on_confirmed(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        state["docker_status"] = {"test": "VULNERABILITY_CONFIRMED"}
        state["retry_count"] = 0
        assert should_retry(state) == "proceed_to_remediation"

    def test_should_proceed_on_secure(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        state["docker_status"] = {"test": "SECURE"}
        state["retry_count"] = 0
        assert should_retry(state) == "proceed_to_remediation"

    def test_should_proceed_on_empty(self):
        state = create_initial_state(repo_owner="test", repo_name="repo")
        assert should_retry(state) == "proceed_to_remediation"


# ---------------------------------------------------------------------------
# Full DAG Execution Test
# ---------------------------------------------------------------------------

class TestDAGExecution:

    def test_full_pipeline_execution(self):
        """Test that the full DAG pipeline executes all nodes in order."""
        state = create_initial_state(
            repo_owner="test-org",
            repo_name="test-repo",
            branch_name="main",
            scan_id="test-scan-001",
        )

        dag = VerifyFixDAG()
        events = []

        for event in dag.execute(state):
            events.append(event)

        # Should have pipeline_start and pipeline_end events
        event_types = [e["event"] for e in events]
        assert "pipeline_start" in event_types
        assert "pipeline_end" in event_types

        # Should have node_update events for all major nodes
        node_updates = [
            e["data"]["step"]
            for e in events
            if e["event"] == "node_update"
        ]
        assert "GITHUB_INGEST" in node_updates
        assert "DISCOVERY" in node_updates
        assert "RAG" in node_updates
        assert "CRITIC" in node_updates
        assert "SANDBOX" in node_updates
        assert "REMEDIATION" in node_updates
        assert "COMPLETED" in node_updates

        # State should be completed
        assert state["execution_step"] == "COMPLETED"
        assert state["completed_at"] is not None

    def test_retry_loop_executes(self):
        """Test that the retry loop fires exactly once (first run → HARNESS_ERROR → retry → CONFIRMED)."""
        state = create_initial_state(
            repo_owner="test-org",
            repo_name="test-repo",
            scan_id="test-retry-scan",
        )

        dag = VerifyFixDAG()
        events = list(dag.execute(state))

        # Should have triggered the retry loop
        assert state["retry_count"] == 1

        # Retry event should be in the stream
        retry_events = [
            e for e in events
            if e["event"] == "node_update" and e["data"].get("step") == "RETRY"
        ]
        assert len(retry_events) == 1

    def test_sse_event_format(self):
        """Test that all emitted events have the correct SSE format."""
        state = create_initial_state(repo_owner="test", repo_name="repo")
        dag = VerifyFixDAG()

        for event in dag.execute(state):
            assert "event" in event, "Event must have an 'event' field"
            assert "data" in event, "Event must have a 'data' field"
            assert isinstance(event["data"], dict), "Event data must be a dict"

    def test_log_events_have_timestamps(self):
        """Test that log events include timestamps."""
        state = create_initial_state(repo_owner="test", repo_name="repo")
        dag = VerifyFixDAG()

        for event in dag.execute(state):
            if event["event"] == "log":
                assert "timestamp" in event["data"]
                assert "message" in event["data"]
