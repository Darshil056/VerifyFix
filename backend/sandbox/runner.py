"""
VerifyFix Sandbox Execution Runner
====================================

Dual-mode, multi-runtime execution harness for running AI-generated test fixtures
in an isolated environment.

Supported Runtimes:
  - Python (.py)       -> Python 3.11 runtime
  - JavaScript (.js)   -> Node.js 20 LTS runtime
  - Bash (.sh)         -> Bash shell runtime

Mode 1: Docker container (network-isolated, resource-capped)
        Prefers unified 'verifyfix-sandbox:latest' image containing Python + Node.js + Bash.
        Falls back to runtime-specific images ('python:3.11-slim', 'node:20-alpine') if needed.
Mode 2: Restricted subprocess (fallback when Docker daemon is unavailable)

Both crashes and timeouts are treated as HARNESS_ERROR to trigger
the self-healing retry loop in the DAG.
"""

import os
import sys
import logging
import subprocess
import tempfile
import shutil
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Timeout settings (generous — only retry on real errors, not slow scripts)
DOCKER_TIMEOUT_SECONDS = 60
PROCESS_TIMEOUT_SECONDS = 30

# Docker images
SANDBOX_IMAGE_UNIFIED = "verifyfix-sandbox:latest"
PYTHON_FALLBACK_IMAGE = "python:3.11-slim"
NODE_FALLBACK_IMAGE = "node:20-alpine"
BASH_FALLBACK_IMAGE = "bash:latest"

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


def detect_runtime(
    language: Optional[str] = None,
    file_path: Optional[str] = None,
    code: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Detect the runtime language ('python', 'javascript', or 'bash') and return
    associated execution parameters.
    """
    selected_lang = "python"

    if language:
        lang_clean = language.lower().strip()
        # [FUTURE EXTENSION: JAVASCRIPT RUNTIME]
        # if lang_clean in ("js", "javascript", "node", "nodejs", "typescript", "ts"):
        #     selected_lang = "javascript"
        # elif lang_clean in ("sh", "bash", "shell"):
        if lang_clean in ("sh", "bash", "shell"):
            selected_lang = "bash"
        elif lang_clean in ("py", "python", "python3"):
            selected_lang = "python"

    elif file_path:
        ext = os.path.splitext(file_path)[1].lower()
        # [FUTURE EXTENSION: JAVASCRIPT RUNTIME]
        # if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        #     selected_lang = "javascript"
        # elif ext in (".sh", ".bash"):
        if ext in (".sh", ".bash"):
            selected_lang = "bash"
        elif ext in (".py", ".pyw"):
            selected_lang = "python"

    elif code:
        # [FUTURE EXTENSION: JAVASCRIPT RUNTIME]
        # js_indicators = ["const ", "let ", "var ", "require(", "console.log(", "process.exit(", "=>"]
        py_indicators = ["def ", "import ", "from ", "print(", "__name__", "sys.exit("]
        # js_count = sum(1 for ind in js_indicators if ind in code)
        py_count = sum(1 for ind in py_indicators if ind in code)
        # if js_count > py_count:
        #     selected_lang = "javascript"
        # elif code.startswith("#!/bin/bash") or code.startswith("#!/bin/sh"):
        if code.startswith("#!/bin/bash") or code.startswith("#!/bin/sh"):
            selected_lang = "bash"

    # [FUTURE EXTENSION: JAVASCRIPT RUNTIME]
    # if selected_lang == "javascript":
    #     return {
    #         "language": "javascript",
    #         "fixture_file": "fixture.js",
    #         "docker_cmd": ["node", "/app/fixture.js"],
    #         "fallback_image": NODE_FALLBACK_IMAGE,
    #         "local_exec": ["node"],
    #     }
    # elif selected_lang == "bash":
    if selected_lang == "bash":
        return {
            "language": "bash",
            "fixture_file": "fixture.sh",
            "docker_cmd": ["bash", "/app/fixture.sh"],
            "fallback_image": BASH_FALLBACK_IMAGE,
            "local_exec": ["bash"],
        }
    else:
        return {
            "language": "python",
            "fixture_file": "fixture.py",
            "docker_cmd": ["python", "/app/fixture.py"],
            "fallback_image": PYTHON_FALLBACK_IMAGE,
            "local_exec": [sys.executable],
        }


def stage_workspace_files(temp_dir: str, workspace_files: Optional[Dict[str, str]] = None) -> int:
    """
    Materializes repository files and dependencies into the temporary sandbox
    directory so internal cross-file imports (Python, JS, Bash) resolve naturally.
    Also injects auto_mock.py and creates __init__.py files for seamless relative imports.
    """
    staged_count = 0
    norm_temp = os.path.abspath(temp_dir)

    # 1. Stage the auto_mock.py engine into temp_dir root
    auto_mock_src = os.path.join(os.path.dirname(__file__), "auto_mock.py")
    if os.path.exists(auto_mock_src):
        try:
            shutil.copy2(auto_mock_src, os.path.join(temp_dir, "auto_mock.py"))
        except Exception as e:
            logger.warning(f"Could not stage auto_mock.py: {e}")

    # 2. Stage workspace repository files
    if workspace_files:
        for rel_path, content in workspace_files.items():
            if not rel_path or content is None:
                continue

            clean_rel = rel_path.lstrip("/\\")
            dest_path = os.path.abspath(os.path.join(temp_dir, clean_rel))

            # Prevent directory traversal outside temp_dir
            if not dest_path.startswith(norm_temp):
                logger.warning(f"Skipping dangerous path traversal attempt: {rel_path}")
                continue

            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            try:
                with open(dest_path, "w", encoding="utf-8") as f:
                    f.write(content)
                staged_count += 1
            except Exception as e:
                logger.warning(f"Failed to stage workspace file '{rel_path}': {e}")

    # 3. Ensure __init__.py exists in all subdirectories containing .py files for relative import support
    for root, dirs, files in os.walk(temp_dir):
        if any(f.endswith(".py") for f in files) and root != temp_dir:
            init_file = os.path.join(root, "__init__.py")
            if not os.path.exists(init_file):
                try:
                    with open(init_file, "w", encoding="utf-8") as f:
                        f.write("# auto-generated package marker by verifyfix\n")
                except Exception:
                    pass

    logger.info(f"Staged {staged_count} workspace file(s) into sandbox environment ({temp_dir})")
    return staged_count


def _is_docker_available() -> bool:
    """Check if Docker daemon is running and accessible."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _is_docker_image_available(image_name: str) -> bool:
    """Check if a specific Docker image is available locally."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image_name],
            capture_output=True,
            text=True,
            timeout=4,
        )
        return result.returncode == 0
    except Exception:
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

    # 1. Parse stdout for explicit verdict markers first (even if exploit caused crash/exit 1)
    if "[VULNERABILITY_CONFIRMED]" in stdout:
        return {
            "verdict": "VULNERABILITY_CONFIRMED",
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "timed_out": False,
        }
    elif "[SECURE]" in stdout and exit_code == 0:
        return {
            "verdict": "SECURE",
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": 0,
            "timed_out": False,
        }

    # 2. Non-zero exit code without positive exploit verdict is a harness error
    if exit_code != 0:
        return {
            "verdict": "HARNESS_ERROR",
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
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


def _run_docker(
    fixture_path: str,
    temp_dir: str,
    runtime_info: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute fixture inside an isolated Docker container."""
    # Determine the Docker image: prefer unified multi-runtime, fallback to language-specific image
    if _is_docker_image_available(SANDBOX_IMAGE_UNIFIED):
        docker_image = SANDBOX_IMAGE_UNIFIED
    else:
        docker_image = runtime_info["fallback_image"]

    logger.info(
        f"Running {runtime_info['language']} fixture in Docker container "
        f"({docker_image})..."
    )

    # Convert Windows paths to Docker-compatible format
    docker_temp_dir = temp_dir.replace("\\", "/")

    cmd = [
        "docker", "run",
        "--rm",                               # Remove container after exit
        "--network", "none",                  # No network access
        "--memory", "256m",                   # Memory limit
        "--cpus", "0.5",                      # CPU limit
        "-v", f"{docker_temp_dir}:/app:ro",   # Mount fixture directory read-only
        "-w", "/app",                         # Run from workspace root
        "-e", "PYTHONPATH=/app",              # Auto-resolve Python sibling/parent modules
        "-e", "NODE_PATH=/app:/usr/lib/node_modules:/usr/local/lib/node_modules",  # Auto-resolve Node modules
        docker_image,
        *runtime_info["docker_cmd"],
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

        if exit_code != 0:
            logger.error(f"Docker exited with code {exit_code}. stderr: {stderr[:500]}")
        elif stdout:
            logger.info(f"Docker stdout: {stdout[:200]}")

    except subprocess.TimeoutExpired as e:
        timed_out = True
        stdout = e.stdout or "" if hasattr(e, "stdout") and e.stdout else ""
        stderr = e.stderr or "" if hasattr(e, "stderr") and e.stderr else ""
        try:
            subprocess.run(
                ["docker", "kill", "verifyfix-fixture"],
                capture_output=True,
                timeout=5,
            )
        except Exception:
            pass

    return _parse_verdict(stdout, stderr, exit_code, timed_out)


def _run_process_sandbox(
    fixture_path: str,
    runtime_info: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute fixture in a restricted subprocess (Docker fallback)."""
    logger.info(
        f"Running {runtime_info['language']} fixture in process sandbox mode "
        f"(Docker unavailable)..."
    )

    # Build a cleaned environment — strip all sensitive variables
    clean_env = {}
    for key, value in os.environ.items():
        if key.upper() not in [v.upper() for v in SENSITIVE_ENV_VARS]:
            clean_env[key] = value

    # Set workspace path so local sibling imports resolve
    fixture_dir = os.path.dirname(fixture_path)
    clean_env["PYTHONPATH"] = f"{fixture_dir}{os.pathsep}{clean_env.get('PYTHONPATH', '')}"
    clean_env["NODE_PATH"] = f"{fixture_dir}{os.pathsep}{clean_env.get('NODE_PATH', '')}"

    timed_out = False
    stdout = ""
    stderr = ""
    exit_code = -1

    exec_cmd = [*runtime_info["local_exec"], fixture_path]

    try:
        result = subprocess.run(
            exec_cmd,
            capture_output=True,
            text=True,
            timeout=PROCESS_TIMEOUT_SECONDS,
            env=clean_env,
            cwd=fixture_dir,
        )
        stdout = result.stdout
        stderr = result.stderr
        exit_code = result.returncode
    except FileNotFoundError:
        return {
            "verdict": "HARNESS_ERROR",
            "stdout": "",
            "stderr": (
                f"Runtime executable '{runtime_info['local_exec'][0]}' is not installed on the host. "
                f"Please install it or start Docker to use the containerized sandbox."
            ),
            "exit_code": -1,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        timed_out = True
        stdout = e.stdout or "" if hasattr(e, "stdout") and e.stdout else ""
        stderr = e.stderr or "" if hasattr(e, "stderr") and e.stderr else ""

    return _parse_verdict(stdout, stderr, exit_code, timed_out)


def run_fixture(
    fixture_name: str,
    fixture_code: str,
    language: Optional[str] = None,
    file_path: Optional[str] = None,
    workspace_files: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Execute a test fixture in an isolated environment.

    Automatically selects Docker mode if available, otherwise falls back
    to process sandbox mode. Automatically detects language/runtime (Python,
    JavaScript/Node.js, or Bash).

    Args:
        fixture_name: Identifier for the fixture (e.g., "CWE-89_sql_injection").
        fixture_code: Source code of the fixture to execute.
        language: Optional language override ("python", "javascript", "bash").
        file_path: Optional original target file path for automatic extension detection.
        workspace_files: Optional mapping of relative file paths to contents to stage into the sandbox.

    Returns:
        SandboxResult dict with verdict, stdout, stderr, exit_code, timed_out.
    """
    temp_dir = None
    try:
        # Detect runtime
        runtime_info = detect_runtime(
            language=language,
            file_path=file_path or fixture_name,
            code=fixture_code,
        )

        # Create temporary directory and write the fixture file
        temp_dir = tempfile.mkdtemp(prefix=f"verifyfix_{fixture_name}_")

        # Materialize entire repository workspace and import dependencies
        stage_workspace_files(temp_dir, workspace_files)

        fixture_filename = runtime_info["fixture_file"]
        fixture_path = os.path.join(temp_dir, fixture_filename)

        # Prepend auto_mock engine for Python fixtures to handle missing packages, relative imports & exceptions
        final_code = fixture_code
        if runtime_info["language"] == "python" and "import auto_mock" not in fixture_code:
            final_code = "import auto_mock  # VerifyFix Auto-Mock & Exception Engine\n" + fixture_code

        with open(fixture_path, "w", encoding="utf-8") as f:
            f.write(final_code)

        logger.info(
            f"Fixture '{fixture_name}' ({runtime_info['language']}) written to "
            f"{fixture_path} ({len(fixture_code)} chars)"
        )

        # Choose execution mode
        if _is_docker_available():
            logger.info(f"Docker detected — using container isolation for '{fixture_name}'")
            result = _run_docker(fixture_path, temp_dir, runtime_info)
        else:
            logger.info(f"Docker not available — using process sandbox for '{fixture_name}'")
            result = _run_process_sandbox(fixture_path, runtime_info)

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
