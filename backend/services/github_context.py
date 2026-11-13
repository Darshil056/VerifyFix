"""
GitHub Context Fetcher Service
================================

Builds a rich code context for LLM analysis by:
1. Parsing unified diffs to extract changed file paths
2. Fetching full file contents from GitHub API
3. Resolving Python import dependencies (files imported by changed files)
4. Assembling a structured context payload

This gives the LLM full visibility into the codebase, not just the diff,
enabling detection of cross-file and deep-context vulnerabilities.
"""

import re
import ast
import logging
import base64
from typing import List, Dict, Optional, Tuple
import requests

logger = logging.getLogger("verifyfix.github_context")

# ---------------------------------------------------------------------------
# Safety limits
# ---------------------------------------------------------------------------

MAX_CONTEXT_FILES = 15      # Max number of files to fetch (changed + deps)
MAX_FILE_SIZE = 50_000      # 50KB per file — truncate beyond this
TRUNCATION_MARKER = "\n\n# ... [TRUNCATED — file exceeds 50KB limit] ...\n"

# File extensions we care about for vulnerability analysis
ANALYZABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".cpp", ".h", ".cs", ".rs", ".swift", ".kt", ".scala",
    ".sql", ".yaml", ".yml", ".json", ".xml", ".toml", ".cfg", ".ini", ".env",
}

# Extensions to skip entirely (binaries, assets, etc.)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar", ".gz", ".pdf",
    ".lock", ".min.js", ".min.css", ".map",
}


# ---------------------------------------------------------------------------
# 1. Parse changed files from unified diff
# ---------------------------------------------------------------------------

def parse_changed_files(diff_text: str) -> List[str]:
    """
    Extract the list of changed file paths from a unified diff.

    Parses lines like:
        diff --git a/routes/auth.py b/routes/auth.py
        --- a/routes/auth.py
        +++ b/routes/auth.py

    Returns deduplicated list of file paths (using the 'b/' side — new version).
    """
    if not diff_text:
        return []

    files = set()

    # Primary pattern: diff --git a/path b/path
    for match in re.finditer(r"diff --git a/(.+?) b/(.+)", diff_text):
        b_path = match.group(2).strip()
        files.add(b_path)

    # Fallback: +++ b/path (in case diff header is non-standard)
    if not files:
        for match in re.finditer(r"\+\+\+ b/(.+)", diff_text):
            files.add(match.group(1).strip())

    # Filter to analyzable file types
    filtered = []
    for f in files:
        ext = _get_extension(f)
        if ext in SKIP_EXTENSIONS:
            logger.debug(f"Skipping binary/asset file: {f}")
            continue
        filtered.append(f)

    return sorted(filtered)


def _get_extension(filepath: str) -> str:
    """Get the file extension (lowercase), handling multi-part extensions."""
    # Handle .min.js, .min.css etc.
    if filepath.endswith(".min.js"):
        return ".min.js"
    if filepath.endswith(".min.css"):
        return ".min.css"
    dot_idx = filepath.rfind(".")
    if dot_idx == -1:
        return ""
    return filepath[dot_idx:].lower()


# ---------------------------------------------------------------------------
# 2. Fetch file content from GitHub API
# ---------------------------------------------------------------------------

def fetch_file_content(
    owner: str,
    repo: str,
    branch: str,
    filepath: str,
    token: str,
) -> Optional[str]:
    """
    Fetch a single file's content from the GitHub Contents API.

    Returns the decoded UTF-8 content, or None on failure.
    Large files are truncated at MAX_FILE_SIZE.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filepath}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "VerifyFix-App",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    params = {"ref": branch}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)

        if resp.status_code == 404:
            logger.warning(f"File not found on GitHub: {filepath}")
            return None

        if resp.status_code != 200:
            logger.warning(f"GitHub API error ({resp.status_code}) for {filepath}: {resp.text[:200]}")
            return None

        data = resp.json()

        # GitHub returns base64-encoded content
        if data.get("encoding") == "base64" and data.get("content"):
            content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")

            # Truncate oversized files
            if len(content) > MAX_FILE_SIZE:
                logger.info(f"Truncating large file {filepath} ({len(content)} bytes > {MAX_FILE_SIZE})")
                content = content[:MAX_FILE_SIZE] + TRUNCATION_MARKER

            return content

        # Some files might be too large for the Contents API (>1MB)
        # In that case, GitHub returns a different response with a download_url
        if data.get("download_url"):
            logger.info(f"File {filepath} too large for Contents API, using download_url")
            dl_resp = requests.get(data["download_url"], headers=headers, timeout=15)
            if dl_resp.status_code == 200:
                content = dl_resp.text
                if len(content) > MAX_FILE_SIZE:
                    content = content[:MAX_FILE_SIZE] + TRUNCATION_MARKER
                return content

        logger.warning(f"Unexpected GitHub response format for {filepath}")
        return None

    except requests.Timeout:
        logger.error(f"Timeout fetching {filepath} from GitHub")
        return None
    except Exception as e:
        logger.error(f"Error fetching {filepath} from GitHub: {e}")
        return None


# ---------------------------------------------------------------------------
# 3. Fetch repository file tree
# ---------------------------------------------------------------------------

def fetch_repo_tree(
    owner: str,
    repo: str,
    branch: str,
    token: str,
) -> List[str]:
    """
    Fetch the full file listing of a repository at a given branch.
    Uses the Git Trees API with recursive=1.

    Returns a list of all file paths in the repo.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "VerifyFix-App",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        resp = requests.get(url, headers=headers, params={"recursive": "1"}, timeout=15)
        if resp.status_code != 200:
            logger.warning(f"Failed to fetch repo tree: {resp.status_code}")
            return []

        data = resp.json()
        tree = data.get("tree", [])
        return [item["path"] for item in tree if item.get("type") == "blob"]

    except Exception as e:
        logger.error(f"Error fetching repo tree: {e}")
        return []


def build_file_tree_string(file_paths: List[str]) -> str:
    """
    Build a human-readable directory tree string from a list of file paths.
    """
    if not file_paths:
        return "(no files)"

    # Build tree structure
    tree: Dict = {}
    for path in sorted(file_paths):
        parts = path.split("/")
        current = tree
        for part in parts:
            if part not in current:
                current[part] = {}
            current = current[part]

    lines = []
    _render_tree(tree, "", lines, is_last=True, is_root=True)
    return "\n".join(lines)


def _render_tree(node: Dict, prefix: str, lines: List[str], is_last: bool, is_root: bool):
    """Recursively render a tree dictionary into ASCII art lines."""
    if is_root:
        for i, (name, children) in enumerate(sorted(node.items())):
            is_final = i == len(node) - 1
            connector = "└── " if is_final else "├── "
            lines.append(f"{connector}{name}/" if children else f"{connector}{name}")
            child_prefix = "    " if is_final else "│   "
            _render_tree(children, child_prefix, lines, is_final, False)
    else:
        for i, (name, children) in enumerate(sorted(node.items())):
            is_final = i == len(node) - 1
            connector = "└── " if is_final else "├── "
            lines.append(f"{prefix}{connector}{name}/" if children else f"{prefix}{connector}{name}")
            child_prefix = prefix + ("    " if is_final else "│   ")
            _render_tree(children, child_prefix, lines, is_final, False)


# ---------------------------------------------------------------------------
# 4. Resolve import dependencies (Python-focused)
# ---------------------------------------------------------------------------

def resolve_python_imports(file_content: str, repo_files: List[str]) -> List[str]:
    """
    Parse Python import statements from file_content and match them
    against the actual files in the repository.

    Returns a list of repo file paths that are imported by this file.
    """
    if not file_content or not repo_files:
        return []

    imported_modules = set()

    try:
        tree = ast.parse(file_content)
    except SyntaxError:
        # If it's not valid Python, skip import resolution
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.add(node.module)

    # Convert module paths to potential file paths
    # e.g., "routes.auth" -> "routes/auth.py"
    # e.g., "config" -> "config.py" or "config/__init__.py"
    candidate_paths = set()
    for module in imported_modules:
        # Skip standard library and third-party imports
        top_level = module.split(".")[0]
        if top_level in _STDLIB_MODULES:
            continue

        module_path = module.replace(".", "/")
        candidate_paths.add(f"{module_path}.py")
        candidate_paths.add(f"{module_path}/__init__.py")

        # Also check partial paths (for relative-like imports)
        parts = module.split(".")
        for i in range(1, len(parts)):
            partial = "/".join(parts[:i+1])
            candidate_paths.add(f"{partial}.py")

    # Match candidates against actual repo files
    repo_files_set = set(repo_files)
    matched = [path for path in candidate_paths if path in repo_files_set]

    return sorted(matched)


def resolve_js_imports(file_content: str, file_path: str, repo_files: List[str]) -> List[str]:
    """
    Parse JavaScript/TypeScript import statements and resolve them against repo files.
    Handles: import X from './path', require('./path'), import('./path')
    """
    if not file_content or not repo_files:
        return []

    imported_paths = set()

    # Match: import ... from 'path' or import ... from "path"
    # Match: require('path') or require("path")
    # Match: import('path') or import("path")
    patterns = [
        r"""(?:import\s+.*?from\s+|require\s*\(\s*|import\s*\(\s*)['"]([^'"]+)['"]""",
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, file_content):
            import_path = match.group(1)
            # Only resolve relative imports (starting with . or ..)
            if import_path.startswith("."):
                imported_paths.add(import_path)

    if not imported_paths:
        return []

    # Resolve relative paths against the file's directory
    import posixpath
    file_dir = posixpath.dirname(file_path)
    repo_files_set = set(repo_files)
    matched = []

    for imp in imported_paths:
        resolved = posixpath.normpath(posixpath.join(file_dir, imp))

        # Try various extensions
        candidates = [
            resolved,
            f"{resolved}.py",
            f"{resolved}.js",
            f"{resolved}.ts",
            f"{resolved}.jsx",
            f"{resolved}.tsx",
            f"{resolved}/index.js",
            f"{resolved}/index.ts",
            f"{resolved}/index.tsx",
        ]

        for candidate in candidates:
            if candidate in repo_files_set:
                matched.append(candidate)
                break

    return sorted(matched)


# Common Python stdlib modules to skip during import resolution
_STDLIB_MODULES = {
    "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
    "asyncore", "atexit", "base64", "bdb", "binascii", "binhex",
    "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb", "chunk",
    "cmath", "cmd", "code", "codecs", "codeop", "collections",
    "colorsys", "compileall", "concurrent", "configparser", "contextlib",
    "contextvars", "copy", "copyreg", "cProfile", "crypt", "csv",
    "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
    "difflib", "dis", "distutils", "doctest", "email", "encodings",
    "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
    "fnmatch", "formatter", "fractions", "ftplib", "functools", "gc",
    "getopt", "getpass", "gettext", "glob", "grp", "gzip", "hashlib",
    "heapq", "hmac", "html", "http", "idlelib", "imaplib", "imghdr",
    "imp", "importlib", "inspect", "io", "ipaddress", "itertools",
    "json", "keyword", "lib2to3", "linecache", "locale", "logging",
    "lzma", "mailbox", "mailcap", "marshal", "math", "mimetypes",
    "mmap", "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
    "numbers", "operator", "optparse", "os", "ossaudiodev", "parser",
    "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil",
    "platform", "plistlib", "poplib", "posix", "posixpath", "pprint",
    "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr",
    "pydoc", "queue", "quopri", "random", "re", "readline", "reprlib",
    "resource", "rlcompleter", "runpy", "sched", "secrets", "select",
    "selectors", "shelve", "shlex", "shutil", "signal", "site",
    "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "sqlite3",
    "ssl", "stat", "statistics", "string", "stringprep", "struct",
    "subprocess", "sunau", "symtable", "sys", "sysconfig", "syslog",
    "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "test",
    "textwrap", "threading", "time", "timeit", "tkinter", "token",
    "tokenize", "trace", "traceback", "tracemalloc", "tty", "turtle",
    "turtledemo", "types", "typing", "unicodedata", "unittest", "urllib",
    "uu", "uuid", "venv", "warnings", "wave", "weakref", "webbrowser",
    "winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc",
    "zipapp", "zipfile", "zipimport", "zlib",
    # Common third-party libraries to skip
    "flask", "django", "fastapi", "requests", "numpy", "pandas",
    "sqlalchemy", "celery", "redis", "pymongo", "pydantic", "pytest",
    "setuptools", "pip", "wheel", "google", "genai", "openai",
    "langchain", "chromadb", "tiktoken", "dotenv",
}


# ---------------------------------------------------------------------------
# 5. Build full context payload
# ---------------------------------------------------------------------------

def build_full_context(
    owner: str,
    repo: str,
    branch: str,
    diff_text: str,
    token: str,
    emit_log=None,
) -> Dict:
    """
    Build the complete context payload for LLM analysis.

    Args:
        owner: GitHub repo owner
        repo: GitHub repo name
        branch: Target branch
        diff_text: The unified diff text
        token: GitHub personal access token
        emit_log: Optional callback for SSE logging: emit_log(message: str)

    Returns:
        {
            "full_files": {filepath: content, ...},
            "dependency_files": {filepath: content, ...},
            "file_tree": "ASCII tree string",
            "analyzed_context_summary": "Human-readable summary",
            "changed_file_paths": [list of changed file paths],
            "dependency_file_paths": [list of dependency file paths],
        }
    """
    result = {
        "full_files": {},
        "dependency_files": {},
        "file_tree": "",
        "analyzed_context_summary": "",
        "changed_file_paths": [],
        "dependency_file_paths": [],
    }

    if not token:
        if emit_log:
            emit_log("[Context Builder] No GitHub token provided — using diff-only mode")
        result["analyzed_context_summary"] = "Diff-only mode (no GitHub token provided)"
        return result

    # Step 1: Parse changed files from diff
    changed_files = parse_changed_files(diff_text)
    result["changed_file_paths"] = changed_files

    if not changed_files:
        if emit_log:
            emit_log("[Context Builder] No changed files detected in diff")
        result["analyzed_context_summary"] = "No changed files detected in diff"
        return result

    if emit_log:
        emit_log(f"[Context Builder] Detected {len(changed_files)} changed file(s): {', '.join(changed_files)}")

    # Step 2: Fetch repo file tree (for import resolution)
    if emit_log:
        emit_log("[Context Builder] Fetching repository file tree...")
    repo_files = fetch_repo_tree(owner, repo, branch, token)
    if repo_files:
        result["file_tree"] = build_file_tree_string(repo_files[:200])  # Cap tree rendering
        if emit_log:
            emit_log(f"[Context Builder] Repository contains {len(repo_files)} files")

    # Step 3: Fetch full contents of changed files
    files_fetched = 0
    for filepath in changed_files:
        if files_fetched >= MAX_CONTEXT_FILES:
            if emit_log:
                emit_log(f"[Context Builder] Reached file limit ({MAX_CONTEXT_FILES}), skipping remaining changed files")
            break

        if emit_log:
            emit_log(f"[Context Builder] Fetching: {filepath}")

        content = fetch_file_content(owner, repo, branch, filepath, token)
        if content is not None:
            result["full_files"][filepath] = content
            files_fetched += 1
        else:
            if emit_log:
                emit_log(f"[Context Builder] ⚠ Could not fetch {filepath}")

    # Step 4: Resolve import dependencies
    all_dependency_paths = set()
    for filepath, content in result["full_files"].items():
        ext = _get_extension(filepath)
        deps = []

        if ext == ".py":
            deps = resolve_python_imports(content, repo_files)
        elif ext in {".js", ".ts", ".jsx", ".tsx"}:
            deps = resolve_js_imports(content, filepath, repo_files)

        for dep in deps:
            if dep not in result["full_files"]:  # Don't re-fetch already fetched files
                all_dependency_paths.add(dep)

    # Step 5: Fetch dependency file contents
    if all_dependency_paths and emit_log:
        emit_log(f"[Context Builder] Resolved {len(all_dependency_paths)} import dependency file(s)")

    for dep_path in sorted(all_dependency_paths):
        if files_fetched >= MAX_CONTEXT_FILES:
            if emit_log:
                emit_log(f"[Context Builder] Reached file limit ({MAX_CONTEXT_FILES}), skipping remaining dependencies")
            break

        if emit_log:
            emit_log(f"[Context Builder] Fetching dependency: {dep_path}")

        content = fetch_file_content(owner, repo, branch, dep_path, token)
        if content is not None:
            result["dependency_files"][dep_path] = content
            files_fetched += 1

    result["dependency_file_paths"] = sorted(result["dependency_files"].keys())

    # Step 6: Build summary
    changed_count = len(result["full_files"])
    dep_count = len(result["dependency_files"])
    changed_names = ", ".join(result["full_files"].keys())
    dep_names = ", ".join(result["dependency_files"].keys()) if result["dependency_files"] else "none"

    summary = (
        f"Analyzed {changed_count} changed file(s) + {dep_count} dependency file(s).\n"
        f"Changed: {changed_names}\n"
        f"Dependencies: {dep_names}"
    )
    result["analyzed_context_summary"] = summary

    if emit_log:
        emit_log(f"[Context Builder] Context ready: {changed_count} changed + {dep_count} dependencies ({files_fetched} total files)")

    return result


# ---------------------------------------------------------------------------
# 6. Format context for LLM prompts
# ---------------------------------------------------------------------------

def format_context_for_prompt(
    diff_text: str,
    full_files: Dict[str, str],
    dependency_files: Dict[str, str],
    max_total_chars: int = 200_000,
) -> str:
    """
    Format the full context into a single string suitable for LLM prompts.

    Includes:
    - Full file contents of changed files (with diff markers)
    - Dependency file contents
    - The original diff for reference

    Respects max_total_chars to avoid token budget blowouts.
    """
    sections = []
    total_chars = 0

    # Section 1: Changed files (full source)
    if full_files:
        sections.append("=" * 60)
        sections.append("CHANGED FILES (Full Source Code)")
        sections.append("=" * 60)
        for filepath, content in full_files.items():
            header = f"\n--- FILE: {filepath} ---"
            if total_chars + len(header) + len(content) > max_total_chars:
                sections.append(f"\n--- FILE: {filepath} --- [SKIPPED — context budget exceeded]")
                continue
            sections.append(header)
            sections.append(content)
            total_chars += len(header) + len(content)

    # Section 2: Dependency files
    if dependency_files:
        sections.append("\n" + "=" * 60)
        sections.append("DEPENDENCY FILES (Imported by Changed Files)")
        sections.append("=" * 60)
        for filepath, content in dependency_files.items():
            header = f"\n--- DEPENDENCY: {filepath} ---"
            if total_chars + len(header) + len(content) > max_total_chars:
                sections.append(f"\n--- DEPENDENCY: {filepath} --- [SKIPPED — context budget exceeded]")
                continue
            sections.append(header)
            sections.append(content)
            total_chars += len(header) + len(content)

    # Section 3: The diff (what actually changed)
    if diff_text:
        sections.append("\n" + "=" * 60)
        sections.append("GIT DIFF (What Changed)")
        sections.append("=" * 60)
        if total_chars + len(diff_text) > max_total_chars:
            sections.append(diff_text[:max_total_chars - total_chars] + "\n[DIFF TRUNCATED]")
        else:
            sections.append(diff_text)

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# 7. Fetch diff from the latest commit
# ---------------------------------------------------------------------------

def fetch_branch_diff(
    owner: str,
    repo: str,
    branch: str,
    token: str,
) -> str:
    """
    Fetch the diff between main and the specified branch.
    Useful when no target diff is explicitly provided.
    """
    # If the target branch IS main, compare against its parent commit to get the latest changes
    compare_str = f"main~1...main" if branch == "main" else f"main...{branch}"
    url = f"https://api.github.com/repos/{owner}/{repo}/compare/{compare_str}"
    headers = {
        "Accept": "application/vnd.github.v3.diff",
        "User-Agent": "VerifyFix-App",
    }
    if token:
        headers["Authorization"] = f"token {token}"
        
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.text
        else:
            logger.warning(f"Failed to fetch branch diff: {resp.status_code}")
            return ""
    except Exception as e:
        logger.error(f"Error fetching branch diff: {e}")
        return ""
