import os
import pathspec
from typing import Dict, Any
from src.tools.base import ToolInterface

class FilesystemTool(ToolInterface):
    """
    Concrete implementation of filesystem operations with security constraints.
    Enforces path traversal protection and policy-based glob filtering.
    """
    def __init__(self, workspace_root: str):
        # Resolve to absolute path to prevent traversal via symlinks or relative roots
        self.workspace_root = os.path.abspath(workspace_root)
        if not os.path.exists(self.workspace_root):
            os.makedirs(self.workspace_root, exist_ok=True)

    def _resolve_and_verify(self, requested_path: str, constraints: Dict[str, Any]) -> str:
        """
        Validates the path against traversal attacks and policy constraints.
        """
        # 1. Traversal Prevention: Resolve absolute path and verify it's within root
        target = os.path.abspath(os.path.join(self.workspace_root, requested_path))
        if os.path.commonpath([self.workspace_root, target]) != self.workspace_root:
            raise PermissionError(f"Security Violation: Path traversal attempted for '{requested_path}'")

        # 2. Policy Filtering: Apply allow/deny globs using pathspec
        rel_path = os.path.relpath(target, self.workspace_root)
        path_rules = constraints.get("paths", {})
        
        # Deny list takes precedence
        deny_patterns = path_rules.get("deny", [])
        if deny_patterns:
            deny_spec = pathspec.PathSpec.from_lines('gitwildmatch', deny_patterns)
            if deny_spec.match_file(rel_path):
                raise PermissionError(f"Policy Denial: Path '{rel_path}' is explicitly denied.")

        # Allow list verification
        allow_patterns = path_rules.get("allow", ["*"])
        allow_spec = pathspec.PathSpec.from_lines('gitwildmatch', allow_patterns)
        if not allow_spec.match_file(rel_path):
            raise PermissionError(f"Policy Denial: Path '{rel_path}' is not in the allow list.")

        return target

    def execute(self, command: str, params: Dict[str, Any], constraints: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main execution entry point for filesystem capabilities.
        """
        try:
            path = self._resolve_and_verify(params.get("path", ""), constraints)

            if command == "read":
                # Enforce max_file_size from policy constraints
                max_size = constraints.get("max_file_size", 1024 * 1024) # Default 1MB
                if os.path.exists(path) and os.path.getsize(path) > max_size:
                    return {"status": "error", "message": f"File size exceeds policy limit of {max_size} bytes."}
                
                with open(path, 'r', encoding='utf-8') as f:
                    return {"status": "success", "content": f.read()}

            elif command == "write":
                content = params.get("content", "")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return {"status": "success", "bytes_written": len(content)}

            return {"status": "error", "message": f"Unknown command: {command}"}

        except PermissionError as e:
            return {"status": "denied", "message": str(e)}
        except Exception as e:
            return {"status": "error", "message": str(e)}
