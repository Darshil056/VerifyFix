"""
VerifyFix Sandbox Execution Runner
====================================

Dual-mode execution harness for running AI-generated test fixtures
in an isolated environment.

Mode 1: Docker container (network-isolated, resource-capped)
Mode 2: Restricted subprocess (fallback when Docker is unavailable)

Both crashes and timeouts are treated as HARNESS_ERROR to trigger
the self-healing retry loop in the DAG.
"""

import os
import sys
import logging
import subprocess
import tempfile
import shutil
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Timeout settings (generous — only retry on real errors, not slow scripts)
DOCKER_TIMEOUT_SECONDS = 60
PROCESS_TIMEOUT_SECONDS = 30

# Docker image for fixture execution
DOCKER_IMAGE = "python:3.11-slim"

# Environment variables to strip from subprocess execution
SENSITIVE_ENV_VARS = [
    "GEMINI_API_KEY",
    "GITHUB_TOKEN",
    "MONGO_URI",
    "FLASK_SECRET_KEY",
    "FLASK_DEBUG",
    "DATABASE_URL",
    "SECRET_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
]


def _is_docker_available() -> bool:
    """Check if Docker daemon is running and accessible."""
    try:
        # Use 'docker info' instead of 'docker --version' because
        # 'docker --version' returns 0 even if the daemon is not running.
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _parse_verdict(stdout: str, stderr: str, exit_code: int, timed_out: bool) -> Dict[str, Any]:
    """
    Parse the fixture execution output to determine the verdict.

    Returns a SandboxResult dict with:
        - verdict: VULNERABILITY_CONFIRMED | SECURE | HARNESS_ERROR
        - stdout: captured stdout
        - stderr: captured stderr
        - exit_code: process exit code
        - timed_out: whether the process timed out
    """
    if timed_out:
        timeout_mode = "Docker" if DOCKER_TIMEOUT_SECONDS > PROCESS_TIMEOUT_SECONDS else "Process"
        timeout_val = DOCKER_TIMEOUT_SECONDS if timeout_mode == "Docker" else PROCESS_TIMEOUT_SECONDS
        return {
            "verdict": "HARNESS_ERROR",
            "stdout": stdout,
            "stderr": f"Fixture timed out after {timeout_val}s. The script took too long to execute. "
                      f"Consider simplifying the test logic or removing any loops/delays.",
            "exit_code": -1,
            "timed_out": True,
        }

    if exit_code != 0:
        return {
            "verdict": "HARNESS_ERROR",
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "timed_out": False,
        }

    # Exit code 0 — parse stdout for verdict markers
    if "[VULNERABILITY_CONFIRMED]" in stdout:
        return {
            "verdict": "VULNERABILITY_CONFIRMED",
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": 0,
            "timed_out": False,
        }
    elif "[SECURE]" in stdout:
        return {
            "verdict": "SECURE",
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": 0,
            "timed_out": False,
        }
    else:
        # Exit 0 but no verdict marker — treat as harness error
        return {
            "verdict": "HARNESS_ERROR",
            "stdout": stdout,
            "stderr": "Script exited successfully but did not print [VULNERABILITY_CONFIRMED] or [SECURE]. "
                      "Ensure the script prints the correct verdict marker.",
            "exit_code": 0,
            "timed_out": False,
        }


def _run_docker(fixture_path: str, temp_dir: str) -> Dict[str, Any]:
    """Execute fixture inside an isolated Docker container."""
    logger.info(f"Running fixture in Docker container ({DOCKER_IMAGE})...")

    # Convert Windows paths to Docker-compatible format
    # Docker on Windows needs forward slashes for volume mounts
    docker_temp_dir = temp_dir.replace("\\", "/")

    cmd = [
        "docker", "run",
        "--rm",                          # Remove container after exit
        "--network", "none",             # No network access
        "--memory", "256m",              # Memory limit
        "--cpus", "0.5",                 # CPU limit
        "-v", f"{docker_temp_dir}:/app:ro",  # Mount fixture directory read-only
        DOCKER_IMAGE,
        "python", "/app/fixture.py",
    ]

    logger.info(f"Docker command: {' '.join(cmd)}")

    timed_out = False
    stdout = ""
    stderr = ""
    exit_code = -1

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
        stdout = result.stdout
        stderr = result.stderr
        exit_code = result.returncode

        # Log Docker output for debugging
        if exit_code != 0:
            logger.error(f"Docker exited with code {exit_code}. stderr: {stderr[:500]}")
        elif stdout:
            logger.info(f"Docker stdout: {stdout[:200]}")

    except subprocess.TimeoutExpired as e:
        timed_out = True
        stdout = e.stdout or "" if hasattr(e, 'stdout') and e.stdout else ""
        stderr = e.stderr or "" if hasattr(e, 'stderr') and e.stderr else ""
        # Kill the container if it's still running
        try:
            subprocess.run(["docker", "kill", f"verifyfix-fixture"],
                         capture_output=True, timeout=5)
        except Exception:
            pass

    return _parse_verdict(stdout, stderr, exit_code, timed_out)


def _run_process_sandbox(fixture_path: str) -> Dict[str, Any]:
    """Execute fixture in a restricted subprocess (Docker fallback)."""
    logger.info("Running fixture in process sandbox mode (Docker unavailable)...")

    # Build a cleaned environment — strip all sensitive variables
    clean_env = {}
    for key, value in os.environ.items():
        if key.upper() not in [v.upper() for v in SENSITIVE_ENV_VARS]:
            clean_env[key] = value

    timed_out = False
    stdout = ""
    stderr = ""
    exit_code = -1

    try:
        result = subprocess.run(
            [sys.executable, fixture_path],
            capture_output=True,
            text=True,
            timeout=PROCESS_TIMEOUT_SECONDS,
            env=clean_env,
            cwd=os.path.dirname(fixture_path),
        )
        stdout = result.stdout
        stderr = result.stderr
        exit_code = result.returncode
    except subprocess.TimeoutExpired as e:
        timed_out = True
        stdout = e.stdout or "" if hasattr(e, 'stdout') and e.stdout else ""
        stderr = e.stderr or "" if hasattr(e, 'stderr') and e.stderr else ""

    return _parse_verdict(stdout, stderr, exit_code, timed_out)


def run_fixture(fixture_name: str, fixture_code: str) -> Dict[str, Any]:
    """
    Execute a test fixture in an isolated environment.

    Automatically selects Docker mode if available, otherwise falls back
    to process sandbox mode.

    Args:
        fixture_name: Identifier for the fixture (e.g., "CWE-89_sql_injection").
        fixture_code: The Python source code to execute.

    Returns:
        SandboxResult dict with verdict, stdout, stderr, exit_code, timed_out.
    """
    temp_dir = None
    try:
        # Create a temporary directory and write the fixture
        temp_dir = tempfile.mkdtemp(prefix=f"verifyfix_{fixture_name}_")
        fixture_path = os.path.join(temp_dir, "fixture.py")

        with open(fixture_path, "w", encoding="utf-8") as f:
            f.write(fixture_code)

        logger.info(f"Fixture '{fixture_name}' written to {fixture_path} ({len(fixture_code)} chars)")

        # Choose execution mode
        if _is_docker_available():
            logger.info(f"Docker detected — using container isolation for '{fixture_name}'")
            result = _run_docker(fixture_path, temp_dir)
        else:
            logger.info(f"Docker not available — using process sandbox for '{fixture_name}'")
            result = _run_process_sandbox(fixture_path)

        logger.info(
            f"Fixture '{fixture_name}' result: verdict={result['verdict']}, "
            f"exit_code={result['exit_code']}, timed_out={result['timed_out']}"
        )
        return result

    except Exception as e:
        logger.error(f"Unexpected error running fixture '{fixture_name}': {e}")
        return {
            "verdict": "HARNESS_ERROR",
            "stdout": "",
            "stderr": f"Sandbox runner internal error: {str(e)}",
            "exit_code": -1,
            "timed_out": False,
        }
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to clean up temp dir {temp_dir}: {e}")
