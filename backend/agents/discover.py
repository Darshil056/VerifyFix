"""
VerifyFix Discover Agent Alias
Re-exports all functionality from agents.discovery for clean namespacing.
"""

from agents.discovery import *  # noqa: F401, F403
from agents.discovery import run_discovery_agent, DISCOVERY_SYSTEM_PROMPT  # noqa: F401
