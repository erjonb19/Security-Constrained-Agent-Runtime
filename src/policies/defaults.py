"""
Default policies (plan §1.1).

Provide a default policy (default deny) and optionally a "development" default
that allows a minimal set of capabilities for local use, aligned with design §3.1.
"""

from __future__ import annotations

from typing import Any


def get_default_policy() -> dict[str, Any]:
    """
    Return a default-deny policy with no capabilities allowed.

    Use when no policy file is provided or as the secure baseline.
    Structure matches design §3.1 (version, default_policy, capabilities).
    """
    return {
        "version": "1.0",
        "default_policy": "deny",
        "capabilities": [],
    }


def get_development_policy() -> dict[str, Any]:
    """
    Return a development default: minimal allow list for local use.

    Allows filesystem.read and filesystem.write under /workspace with deny for
    .git and common sensitive patterns; other capabilities (git, http, shell,
    package_manager) follow design §3.1 examples with conservative constraints.
    """
    return {
        "version": "1.0",
        "default_policy": "deny",
        "capabilities": [
            {
                "name": "filesystem.read",
                "allowed": True,
                "constraints": {
                    "paths": {
                        "allow": ["/workspace/**"],
                        "deny": [
                            "/workspace/.git/**",
                            "/workspace/**/*.key",
                            "/workspace/**/.env",
                        ],
                    },
                    "max_file_size": "10MB",
                    "require_approval": False,
                },
            },
            {
                "name": "filesystem.write",
                "allowed": True,
                "constraints": {
                    "paths": {
                        "allow": ["/workspace/src/**", "/workspace/tests/**"],
                        "deny": ["/workspace/.git/**", "/workspace/**/*.key"],
                    },
                    "require_approval": False,
                },
            },
            {
                "name": "git.commit",
                "allowed": True,
                "constraints": {
                    "prevent_history_rewrite": True,
                    "prevent_force_push": True,
                    "require_approval": False,
                },
            },
            {
                "name": "git.push",
                "allowed": True,
                "constraints": {
                    "prevent_force_push": True,
                    "require_approval": False,
                },
            },
            {
                "name": "shell.execute",
                "allowed": False,
            },
            {
                "name": "http.fetch",
                "allowed": True,
                "constraints": {
                    "endpoints": {
                        "allow": ["https://api.github.com/**", "https://pypi.org/**"],
                        "deny": ["http://**"],
                    },
                    "require_approval": True,
                    "max_response_size": "5MB",
                },
            },
            {
                "name": "package_manager.query",
                "allowed": True,
                "constraints": {
                    "operations": ["list", "search", "info"],
                    "require_approval": False,
                },
            },
        ],
    }
