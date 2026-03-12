"""Base tool interface.

This module defines the abstract contract that all concrete tool implementations
must follow as well as a very small helper registry used by the runtime.

Tools live in the "tool layer" of the security runtime (see
``docs/DESIGN.md`` §4.5 and §5.3).  Each tool corresponds to one or moreå
capabilities (e.g. ``filesystem.read`` or ``http.fetch``) and is responsible for
carrying out the operation once the policy engine has granted permission.

The runtime will call :func:`register_tool` when it boots or when a plugin is
loaded.  Registered tools are looked up by name when :py:meth:`AgentRuntime`
requests execution.

A simple ``ToolResult`` object is returned from :meth:`BaseTool.execute` so the
runtime has a consistent shape to log, sanitize or redact before replying to the
agent.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class ToolError(Exception):
    """Generic error raised by a tool during execution.

    Concrete implementations may raise more specific subclasses if desired, but
    the runtime will catch ``ToolError`` and convert it into a denial or
    failure result for the agent.
    """


class ToolResult:
    """Standardized return value from :class:`BaseTool.execute`.

    Attributes:
        success: ``True`` when the operation completed without error.  ``False``
            otherwise.
        output: The raw value returned by the tool.  This will normally be a
            string, dict, list, or bytes depending on the capability.
        error:  An optional error message present when ``success`` is ``False``.
    """

    def __init__(self, success: bool, output: Any = None, error: Optional[str] = None):
        self.success = success
        self.output = output
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {"success": self.success, "output": self.output, "error": self.error}


class BaseTool(ABC):
    """Abstract base class for all tool implementations.

    Subclasses *must* define a ``name`` property that matches the capability
    string used in policies (e.g. ``"filesystem.read"``) and implement
    :meth:`execute`.
    """

    @property
    @abstractmethod
    def name(self) -> str:  # pragma: no cover - implemented by subclasses
        """The capability name exposed by this tool."""

    @abstractmethod
    def execute(self, params: Dict[str, Any]) -> ToolResult:  # pragma: no cover
        """Perform the requested operation.

        ``params`` is the dictionary of arguments supplied by the agent/runtime
        (after policy validation).  The semantics of the parameters are
        capability-specific.

        The returned :class:`ToolResult` will be logged and returned to the
        caller; the runtime may sanitize or redact values before sending the
        response back to the agent.
        """


# simple global registry -----------------------------------------------------

# maps capability name -> tool instance
_TOOL_REGISTRY: Dict[str, BaseTool] = {}


def register_tool(tool: BaseTool) -> None:
    """Register a tool implementation globally.

    This is a convenience helper; the runtime typically calls it during
    startup as it imports concrete tool modules.  If a tool with the same
    name already exists an exception is raised to prevent accidental
    overwriting.
    """
    if tool.name in _TOOL_REGISTRY:
        raise ValueError(f"tool already registered: {tool.name}")
    _TOOL_REGISTRY[tool.name] = tool


def get_tool(name: str) -> Optional[BaseTool]:
    """Return the previously registered tool instance for ``name``.

    ``None`` is returned if no such tool has been registered.
    """
    return _TOOL_REGISTRY.get(name)


def list_tools() -> Dict[str, BaseTool]:
    """Return a snapshot of all registered tools."""
    return dict(_TOOL_REGISTRY)

