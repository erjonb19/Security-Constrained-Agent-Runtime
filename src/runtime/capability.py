"""
Capability names and helpers (plan §1.2).

Define capability names as constants; optional helpers to map tool name to
capability and to check if a capability is high-risk (for approval/sandbox).
"""

from __future__ import annotations

# -----------------------------------------------------------------------------
# Capability names (plan §1.2; design §3.2)
# -----------------------------------------------------------------------------

FILESYSTEM_READ = "filesystem.read"
FILESYSTEM_WRITE = "filesystem.write"
GIT_COMMIT = "git.commit"
GIT_PUSH = "git.push"
GIT_PULL = "git.pull"
SHELL_EXECUTE = "shell.execute"
HTTP_FETCH = "http.fetch"
PACKAGE_MANAGER_QUERY = "package_manager.query"

# All known capabilities (for validation and iteration)
ALL_CAPABILITIES = frozenset({
    FILESYSTEM_READ,
    FILESYSTEM_WRITE,
    GIT_COMMIT,
    GIT_PUSH,
    GIT_PULL,
    SHELL_EXECUTE,
    HTTP_FETCH,
    PACKAGE_MANAGER_QUERY,
})

# Capabilities considered high-risk: typically require approval or sandbox (design §4.1, §8.3)
HIGH_RISK_CAPABILITIES = frozenset({
    FILESYSTEM_WRITE,
    GIT_COMMIT,
    GIT_PUSH,
    SHELL_EXECUTE,
    HTTP_FETCH,
})

# Tool name / alias -> canonical capability name (plan §1.2 optional)
TOOL_NAME_TO_CAPABILITY: dict[str, str] = {
    "read_file": FILESYSTEM_READ,
    "read": FILESYSTEM_READ,
    "filesystem_read": FILESYSTEM_READ,
    "write_file": FILESYSTEM_WRITE,
    "write": FILESYSTEM_WRITE,
    "filesystem_write": FILESYSTEM_WRITE,
    "commit": GIT_COMMIT,
    "git_commit": GIT_COMMIT,
    "push": GIT_PUSH,
    "git_push": GIT_PUSH,
    "pull": GIT_PULL,
    "git_pull": GIT_PULL,
    "shell": SHELL_EXECUTE,
    "execute": SHELL_EXECUTE,
    "run": SHELL_EXECUTE,
    "http_fetch": HTTP_FETCH,
    "fetch": HTTP_FETCH,
    "package_manager_query": PACKAGE_MANAGER_QUERY,
    "package_query": PACKAGE_MANAGER_QUERY,
    "pip_list": PACKAGE_MANAGER_QUERY,
    "npm_list": PACKAGE_MANAGER_QUERY,
}


def resolve_capability(name: str) -> str:
    """
    Map a tool name or alias to the canonical capability name.

    If the name is already a known capability, return it. Otherwise look up
    in TOOL_NAME_TO_CAPABILITY (case-normalized). If unknown, return the
    original string so the policy engine can treat it as an unknown capability
    (default deny).
    """
    if not name or not isinstance(name, str):
        return name or ""
    normalized = name.strip().lower().replace("-", "_")
    if normalized in ALL_CAPABILITIES:
        return normalized
    return TOOL_NAME_TO_CAPABILITY.get(normalized, name.strip())


def is_high_risk(capability: str) -> bool:
    """
    Return True if the capability is considered high-risk (approval/sandbox).

    High-risk capabilities: filesystem.write, git.commit, git.push,
    shell.execute, http.fetch.
    """
    if not capability:
        return False
    return capability.strip() in HIGH_RISK_CAPABILITIES


def is_known_capability(capability: str) -> bool:
    """Return True if the capability is one of the defined constants."""
    if not capability:
        return False
    return capability.strip() in ALL_CAPABILITIES
