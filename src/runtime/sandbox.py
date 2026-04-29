"""Sandbox execution (optional).

Phase 5: Docker-based sandbox for high-risk capabilities.

Enable with environment variable:
  AGENT_RUNTIME_USE_DOCKER_SANDBOX=1
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from src.tools.base import ToolResult


SANDBOX_IMAGE = os.environ.get("AGENT_RUNTIME_DOCKER_IMAGE", "agent-runtime-sandbox:phase5")
SANDBOX_DOCKERFILE = "docker/Dockerfile.sandbox"


def _decode(buf: Any) -> str:
    """Decode subprocess stdout/stderr defensively.

    Docker output may include bytes that the host codepage (e.g. cp1252 on
    Windows) cannot decode. We capture in bytes mode and force UTF-8 with
    replacement so the runtime never crashes on non-UTF8 output.
    """
    if buf is None:
        return ""
    if isinstance(buf, bytes):
        return buf.decode("utf-8", errors="replace")
    return str(buf)


@dataclass
class SandboxConfig:
    image: str = SANDBOX_IMAGE
    network: str = "none"  # "none" for high-risk by default
    read_only: bool = True
    memory: str = "512m"
    cpus: str = "1.0"
    timeout_s: float = 45.0


def _repo_root() -> Path:
    # src/runtime/sandbox.py -> .../src/runtime -> .../src -> repo root
    return Path(__file__).resolve().parents[2]


def docker_available() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "version"],
            capture_output=True,
            text=False,
            timeout=5,
        )
        return proc.returncode == 0
    except Exception:
        return False


def ensure_sandbox_image(image: str = SANDBOX_IMAGE) -> Tuple[bool, str]:
    """Ensure Docker image exists; build it if missing."""
    try:
        inspect = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=False,
            timeout=10,
        )
        if inspect.returncode == 0:
            return True, "ok"
    except Exception:
        # fall through to build attempt
        pass

    root = _repo_root()
    dockerfile = root / SANDBOX_DOCKERFILE
    if not dockerfile.exists():
        return False, f"Missing sandbox Dockerfile: {dockerfile}"

    try:
        build = subprocess.run(
            ["docker", "build", "-t", image, "-f", str(dockerfile), str(root)],
            capture_output=True,
            text=False,
            timeout=600,
        )
        if build.returncode != 0:
            out = _decode(build.stdout).strip() + "\n" + _decode(build.stderr).strip()
            return False, f"Docker build failed: {out.strip()}"
        return True, "built"
    except Exception as e:
        return False, f"Docker build error: {e}"


def run_tool_in_docker(
    capability: str,
    parameters: Dict[str, Any],
    config: SandboxConfig,
) -> ToolResult:
    """
    Execute a supported tool inside Docker and return ToolResult.

    Note: the container runner supports a limited set of capabilities.
    """
    ok, msg = ensure_sandbox_image(config.image)
    if not ok:
        return ToolResult(success=False, output=None, error=f"Sandbox image unavailable: {msg}")

    payload = {"capability": capability, "parameters": parameters}
    payload_bytes = json.dumps(payload).encode("utf-8")

    cmd = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--cpus",
        str(config.cpus),
        "--memory",
        str(config.memory),
    ]
    if config.read_only:
        cmd.append("--read-only")
    if config.network:
        cmd.extend(["--network", config.network])

    cmd.extend([config.image, "python", "-m", "src.runtime.docker_tool_runner"])

    try:
        # NOTE: we intentionally use bytes (text=False). On Windows, Python's
        # default stdout decoding can fall back to the OEM codepage and crash
        # on non-cp1252 bytes emitted by Docker. Capturing bytes and decoding
        # explicitly with errors="replace" keeps the runtime resilient.
        proc = subprocess.run(
            cmd,
            input=payload_bytes,
            capture_output=True,
            text=False,
            timeout=config.timeout_s,
        )
        out = _decode(proc.stdout).strip()
        if proc.returncode != 0:
            err = _decode(proc.stderr).strip()
            return ToolResult(success=False, output={"stdout": out, "stderr": err}, error="Sandboxed tool failed.")
        try:
            data = json.loads(out) if out else {}
        except (ValueError, json.JSONDecodeError) as e:
            return ToolResult(
                success=False,
                output={"stdout": out},
                error=f"Sandbox produced non-JSON output: {e}",
            )
        return ToolResult(
            success=bool(data.get("success")),
            output=data.get("output"),
            error=data.get("error"),
        )
    except subprocess.TimeoutExpired:
        return ToolResult(success=False, output=None, error="Sandbox execution timed out.")
    except Exception as e:
        return ToolResult(success=False, output=None, error=f"Sandbox execution error: {e}")
