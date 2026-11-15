"""
VerifyFix Context Builder Alias
Re-exports all functionality from services.github_context for clean namespacing.
"""

from services.github_context import *  # noqa: F401, F403
from services.github_context import resolve_local_dependencies  # noqa: F401
