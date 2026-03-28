import ollama
import json
import os
import re

from pathlib import Path

from src.runtime import AgentRuntime
from src.tools.git_tool import GitBaseTool


def create_runtime(policy_path: str | Path | None) -> AgentRuntime:
    runtime = AgentRuntime()
    runtime.load_policy(policy_path)
    try:
        runtime.register_tool(GitBaseTool())
    except ValueError:
        pass  # already registered (e.g. tests)
    return runtime

def load_tool_definitions(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data["tools"]


def to_ollama_tools(tools: list[dict]) -> list[dict]:
    """Convert our tool definitions (name, description, parameters) to Ollama API format."""
    result = []
    for t in tools:
        result.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("parameters", {"type": "object", "properties": {}, "required": []}),
            },
        })
    return result


# Optional: filter to only capabilities allowed by policy
def tool_definitions_for_llm(tool_defs_path: str, policy_path: str) -> list[dict]:
    tools = load_tool_definitions(tool_defs_path)
    with open(policy_path, encoding="utf-8") as f:
        policy = json.load(f)
    allowed = { c["name"] for c in policy["capabilities"] if c.get("allowed") }
    return [t for t in tools if t["name"] in allowed]

def _extract_read_file_intent(prompt: str) -> tuple[str | None, dict]:
    """Extract (capability, params) from prompt for read-file requests. Returns (None, {}) if not detected."""
    prompt = (prompt or "").strip()
    # Match: "read the file PATH", "read file PATH", "open the file PATH", "open file PATH"
    # Path may be quoted or unquoted (e.g. C:\Windows\System32\debug.log)
    for pattern in [
        r"(?:read|open)\s+(?:the\s+)?file\s+[\"']?([^\"'\s]+(?:\s+[^\"'\s]+)*)[\"']?",
        r"file\s+[\"']?([^\"'\s]+(?:\s+[^\"'\s]+)*)[\"']?\s*(?:\s|$)",
    ]:
        m = re.search(pattern, prompt, re.IGNORECASE)
        if m:
            path = m.group(1).strip()
            if path and any(c in path for c in "/\\."):
                return "filesystem.read", {"path": path}
    return None, {}


def check_prompt_against_policy(runtime: AgentRuntime, user_prompt: str) -> tuple[bool, str]:
    """
    Pre-check: if the prompt clearly asks to read a file, evaluate that against policy only
    (no tool required). Returns (allowed, message). If intent not detected, returns (True, "Prompt allowed.").
    """
    capability, params = _extract_read_file_intent(user_prompt)
    if capability is None:
        return True, "Prompt allowed."
    decision = runtime.evaluate_policy(capability, params)
    if decision.allowed:
        return True, "Prompt allowed."
    explanation = runtime.get_explanation(decision)
    return False, f"Prompt denied. {explanation}"


SYSTEM_TOOL_INSTRUCTION = (
    "You have access to tools. You must use them when the user asks—do not refuse on your own. "
    "When the user asks to read a file, call filesystem.read with the exact path they give. "
    "When they ask to write or create a file, call filesystem.write. For git or URLs, use the git or http.fetch tools. "
    "For git commands (e.g. git status), use path '.' for the current directory—do not use '/think' or other placeholder paths. "
    "Security is enforced by the system: after you call a tool, the system may allow or deny it. "
    "Always call the tool and then report back exactly what the system returned (success with content, or denial with reason). "
    "Do not refuse or say you cannot access a path before calling the tool. "
    "When reporting tool results to the user, use plain text only—do not wrap the result in JSON or code blocks."
)


def run_loop(runtime, user_prompt: str, model: str = "llama3.2", tools: list[dict] | None = None, workspace: str | Path | None = None):
    tools = tools or []
    messages = []
    if tools:
        messages.append({"role": "system", "content": SYSTEM_TOOL_INSTRUCTION})
    messages.append({"role": "user", "content": user_prompt})
    while True:
        response = call_llm(messages, model=model, tools=tools)
        capability, params = parse_tool_call(response)
        if capability is None:
            return response.get("message", {}).get("content", "")
        tool_msg = run_tool_and_format(runtime, capability, params, workspace=workspace)
        messages.append({"role": "assistant", "content": response["message"]["content"]})
        messages.append({"role": "user", "content": tool_msg})

def call_llm(messages, model: str = "llama3.2", tools: list[dict] | None = None):
    kwargs = {"model": model, "messages": messages}
    if tools:
        kwargs["tools"] = to_ollama_tools(tools)
    response = ollama.chat(**kwargs)
    return response

def _parse_tool_call_from_content(content: str):
    """Fallback: extract tool name and params from message content (e.g. JSON snippet)."""
    if not content or not isinstance(content, str):
        return None, None
    content = content.strip()
    # Strip markdown code block if present
    if content.startswith("```"):
        lines = content.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines)
    # Try to parse as JSON (e.g. {"tool": "filesystem.read", "path": "..."})
    try:
        data = json.loads(content)
        if not isinstance(data, dict):
            return None, None
        name = data.get("tool") or data.get("name") or data.get("function")
        if not name:
            return None, None
        params = data.get("arguments") or data.get("params") or {
            k: v for k, v in data.items() if k not in ("tool", "name", "function")
        }
        return name, params if isinstance(params, dict) else {}
    except json.JSONDecodeError:
        return None, None


def parse_tool_call(response):
    """Return (capability, parameters) or (None, None) if no tool call."""
    msg = response.get("message", {})
    tool_calls = msg.get("tool_calls") or []
    if tool_calls:
        tc = tool_calls[0]
        fn = tc.get("function") or {}
        name = fn.get("name") or tc.get("name")
        raw_args = fn.get("arguments") or tc.get("args")
        if raw_args is None:
            raw_args = {}
        if isinstance(raw_args, str):
            try:
                raw_args = json.loads(raw_args) if raw_args.strip() else {}
            except json.JSONDecodeError:
                raw_args = {}
        return name, raw_args if isinstance(raw_args, dict) else {}
    # Fallback: model may have put tool call in message content as JSON
    content = msg.get("content") or ""
    return _parse_tool_call_from_content(content)

# Max chars of tool output to send back to the LLM (0 = no limit)
TOOL_OUTPUT_MAX_CHARS = 8000

# Placeholder path some models use; treat as "current directory"
GIT_PLACEHOLDER_PATHS = ("/think", "/workspace", "")


def _normalize_git_params(capability: str, parameters: dict, workspace: str | Path | None = None) -> dict:
    """Use workspace or current directory when model sends a placeholder path (e.g. /think) for git."""
    if capability != "git" or not parameters:
        return parameters
    params = dict(parameters)
    path = params.get("path") or params.get("repo_path") or "."
    if path in GIT_PLACEHOLDER_PATHS or not os.path.isdir(os.path.abspath(path)):
        cwd = os.path.abspath(workspace) if workspace else os.getcwd()
        params["path"] = cwd
        params["repo_path"] = cwd
    return params


def run_tool_and_format(runtime, capability: str, parameters: dict, workspace: str | Path | None = None) -> str:
    parameters = _normalize_git_params(capability, parameters, workspace)
    result = runtime.execute_tool(capability, parameters)
    if result.allowed and result.result:
        out = result.result.output
        raw = str(out)
        if TOOL_OUTPUT_MAX_CHARS and len(raw) > TOOL_OUTPUT_MAX_CHARS:
            raw = raw[:TOOL_OUTPUT_MAX_CHARS] + "\n... (truncated)"
        return f"Tool {capability} succeeded: {raw}"
    return f"Tool denied: {result.explanation}"

def _unwrap_result_for_display(result: str) -> str:
    """If the model returned JSON with a 'content' field, return that; else return result as-is."""
    if not result or not isinstance(result, str):
        return result
    text = result.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    try:
        data = json.loads(text)
        if isinstance(data, dict) and "content" in data:
            return str(data["content"])
    except json.JSONDecodeError:
        pass
    return result


def main():
    import argparse
    p = argparse.ArgumentParser()
    # p.add_argument("--policy", default=None)
    p.add_argument("--prompt", required=True)
    p.add_argument("--model", default="llama3.2")
    p.add_argument("--tools", default=None, help="Path to tool_definitions.json")
    p.add_argument("--workspace", default=None, help="Directory for git and path-based tools (default: current directory)")
    args = p.parse_args()
    tools_path = tool_definitions_json_path(args)
    tools_for_llm = load_tool_definitions(tools_path) if tools_path and tools_path.exists() else []
    # runtime = create_runtime(args.policy)
    runtime = create_runtime(None)
    workspace = os.path.abspath(args.workspace) if args.workspace else None
    if workspace and not os.path.isdir(workspace):
        print(f"Error: workspace is not a directory: {args.workspace}")
        return

    # Pre-check prompt against policy before sending to LLM
    allowed, msg = check_prompt_against_policy(runtime, args.prompt)
    print(msg)
    if not allowed:
        print("Finished with prompt (denied).")
        return

    result = run_loop(runtime, args.prompt, model=args.model, tools=tools_for_llm, workspace=workspace)
    # If the model returned JSON with a "content" field, show that as the main output
    display = _unwrap_result_for_display(result)
    print(display)
    print("Finished with prompt.")

def tool_definitions_json_path(args):
    if getattr(args, "tools", None):
        return Path(args.tools)
    # if getattr(args, "policy", None):
    #    return Path(args.policy).parent / "tool_definitions.json"
    return Path("examples/policies/tool_definitions.json")
