"""
VerifyFix DAG Executor (Graph Engine)
======================================

Implements the 8-stage directed acyclic graph with a conditional feedback
edge for the retry loop.  The executor is a pure-Python generator that
yields SSE-compatible event dicts at every node transition — no external
LangGraph runtime dependency is required for Phase 2.

Graph topology::

    [Start]
       │
       ▼
    [node_github_ingest]
       │
       ▼
    [node_discovery]  (Agent 1)
       │
       ▼
    [node_rag]  (Layer 2)
       │
       ▼
    [node_critic]  (Agent 3)  ◄────────┐
       │                               │  (HARNESS_ERROR &
       ▼                               │   retry_count < 3)
    [node_sandbox]  ───────────────────┘
       │
       ├──► (VULNERABILITY_CONFIRMED / SECURE)
       │
       ▼
    [node_remediation]  (Agent 4)
       │
       ▼
    [node_complete]
"""

import logging
from datetime import datetime, timezone
from typing import Generator, Dict, Any

from agents.state import VerifyFixState, create_initial_state
from agents.nodes import (
    node_github_ingest,
    node_discovery,
    node_rag,
    node_critic,
    node_sandbox,
    node_remediation,
    node_complete,
)

logger = logging.getLogger("verifyfix.graph")

# Maximum retry iterations before forcing progression
MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Conditional edge
# ---------------------------------------------------------------------------

def should_retry(state: VerifyFixState) -> str:
    """
    Conditional edge logic after sandbox execution.

    Returns:
        ``"retry_critic"`` if any fixture resulted in ``HARNESS_ERROR`` and
        the retry budget has not been exhausted, otherwise
        ``"proceed_to_remediation"``.
    """
    statuses = state.get("docker_status", {}).values()
    retry_count = state.get("retry_count", 0)

    if "HARNESS_ERROR" in statuses and retry_count < MAX_RETRIES:
        return "retry_critic"
    return "proceed_to_remediation"


# ---------------------------------------------------------------------------
# DAG Executor
# ---------------------------------------------------------------------------

class VerifyFixDAG:
    """
    The core pipeline executor.

    Usage::

        dag = VerifyFixDAG()
        initial_state = create_initial_state(owner, repo, branch, diff)
        for event in dag.execute(initial_state):
            # broadcast each event via SSE
            send_sse(event)
    """

    # Ordered list of nodes (linear portion before the conditional edge)
    LINEAR_NODES = [
        ("node_github_ingest", node_github_ingest),
        ("node_discovery", node_discovery),
        ("node_rag", node_rag),
    ]

    def __init__(self):
        self.max_retries = MAX_RETRIES

    def execute(self, state: VerifyFixState) -> Generator[Dict[str, Any], None, VerifyFixState]:
        """
        Execute the full DAG pipeline as a generator.

        Yields SSE event dicts at every node transition and state change.
        Returns the final state when the pipeline completes.
        """
        logger.info(f"Starting DAG execution for scan {state.get('scan_id', 'unknown')}")

        # Emit pipeline start event
        yield {
            "event": "pipeline_start",
            "data": {
                "scan_id": state.get("scan_id"),
                "repo": f"{state.get('repo_owner')}/{state.get('repo_name')}",
                "branch": state.get("branch_name"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }

        try:
            # ------ Linear phase: ingest → discovery → RAG ------
            for node_name, node_fn in self.LINEAR_NODES:
                logger.info(f"Executing node: {node_name}")
                gen = node_fn(state)
                try:
                    while True:
                        event = next(gen)
                        yield event
                except StopIteration as e:
                    state = e.value if e.value is not None else state

            # ------ Critic → Sandbox loop with retry edge ------
            while True:
                # Critic node
                logger.info("Executing node: node_critic")
                gen = node_critic(state)
                try:
                    while True:
                        event = next(gen)
                        yield event
                except StopIteration as e:
                    state = e.value if e.value is not None else state

                # Sandbox node
                logger.info("Executing node: node_sandbox")
                gen = node_sandbox(state)
                try:
                    while True:
                        event = next(gen)
                        yield event
                except StopIteration as e:
                    state = e.value if e.value is not None else state

                # Conditional edge: retry or proceed?
                decision = should_retry(state)
                logger.info(f"Conditional edge decision: {decision} (retry_count={state.get('retry_count', 0)})")

                if decision == "retry_critic":
                    state["retry_count"] = state.get("retry_count", 0) + 1
                    state["execution_step"] = "RETRY"
                    state["logs"].append(
                        f"[DAG] Retry loop triggered — attempt {state['retry_count']}/{self.max_retries}"
                    )
                    yield {
                        "event": "node_update",
                        "data": {
                            "step": "RETRY",
                            "status": "looping",
                            "retry_count": state["retry_count"],
                            "max_retries": self.max_retries,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    }
                    yield {
                        "event": "log",
                        "data": {
                            "message": f"[DAG] Looping back to Critic Agent — attempt {state['retry_count']}/{self.max_retries}",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    }
                    # Loop continues — will re-enter node_critic
                else:
                    # Break out of the retry loop
                    break

            # ------ Remediation ------
            logger.info("Executing node: node_remediation")
            gen = node_remediation(state)
            try:
                while True:
                    event = next(gen)
                    yield event
            except StopIteration as e:
                state = e.value if e.value is not None else state

            # ------ Complete ------
            logger.info("Executing node: node_complete")
            gen = node_complete(state)
            try:
                while True:
                    event = next(gen)
                    yield event
            except StopIteration as e:
                state = e.value if e.value is not None else state

        except Exception as exc:
            logger.error(f"DAG execution error: {exc}", exc_info=True)
            state["execution_step"] = "ERROR"
            state["error"] = str(exc)
            state["logs"].append(f"[DAG] Fatal error: {exc}")
            yield {
                "event": "error",
                "data": {
                    "message": str(exc),
                    "step": state.get("execution_step", "UNKNOWN"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            }

        # Emit pipeline end event
        yield {
            "event": "pipeline_end",
            "data": {
                "scan_id": state.get("scan_id"),
                "final_step": state.get("execution_step"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }

        logger.info(f"DAG execution completed for scan {state.get('scan_id', 'unknown')}")
        return state
