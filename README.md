# Agent Runtime Security

A capability-based security runtime for AI agents that mediates all tool calls through a policy engine, preventing unsafe actions while enabling legitimate work.

## Overview

This project provides a security layer for AI agent systems by implementing:

- **Policy-based access control**: Define fine-grained permissions for tool capabilities
- **Pre-call validation**: Check all tool calls against security policies before execution
- **Threat detection**: Detect prompt injection, parameter manipulation, and other attacks
- **Audit logging**: Complete trail of all security decisions
- **Explainable denials**: Clear error messages when operations are blocked

## Features

- ✅ Capability-based access control
- ✅ YAML/JSON policy configuration
- ✅ Path and endpoint constraints
- ✅ Injection detection
- ✅ Parameter validation
- ✅ Audit logging
- ✅ Human-in-the-loop approvals (planned)

## Installation

```bash
pip install -e .
```

## Run commands

After installation, two CLI commands are registered (see `setup.py`). Run them from the repository root (or any directory) so paths like `examples/policies/...` resolve if you use relative paths.

### `agent-runtime`

Load a policy and optionally execute a single tool call through the runtime.

```bash
# Load policy (prints readiness when no capability is given)
agent-runtime --policy examples/policies/Policy.yaml

# Demo: one secured tool call (JSON for --params)
agent-runtime --policy examples/policies/Policy.yaml --capability filesystem.read --params '{"path": "README.md"}'
```

Use `agent-runtime --help` for options (`--policy`, `--capability`, `--params`).

### `agent-loop`

Run the policy-aware loop with a local LLM (Ollama). Requires a working Ollama setup and the model you pass (default: `llama3.2`).

```bash
agent-loop --policy examples/policies/Policy.yaml --prompt "Summarize the project README."
```

Common options: `--model`, `--tools` (path to `tool_definitions.json`; defaults next to `--policy` or `examples/policies/tool_definitions.json`), `--workspace`, `--audit-log-dir` (default `logs/audit`), `--no-audit`. Use `agent-loop --help` for the full list.

## Quick Start

```python
from src.runtime.agent_runtime import AgentRuntime
from src.policies.parser import PolicyParser

# Load a policy
parser = PolicyParser()
policy = parser.load("examples/policies/Policy.yaml")

# Create runtime
runtime = AgentRuntime(policy)

# Intercept tool calls
result = runtime.execute_tool("filesystem.read", {"path": "/workspace/src/main.py"})
```

## Project Structure

```
agent-runtime-secure/
├── docs/              # Documentation
├── src/               # Source code
│   ├── runtime/       # Runtime orchestrator
│   ├── tools/         # Tool implementations
│   ├── policies/      # Policy parsing/validation
│   ├── security/      # Security components
│   └── utils/         # Utilities
├── tests/             # Test suite
├── examples/          # Example policies and workflows
└── scripts/           # Evaluation and benchmarking
```

## Documentation

- [Design Document](docs/DESIGN.md) - Threat model, security goals, and architecture
- [Policy Reference](docs/POLICY_REFERENCE.md) - Policy format documentation
- [Evaluation](docs/EVALUATION.md) - Evaluation methodology and results

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run security tests
pytest tests/security/

# Format code
black src/ tests/
```

## License

MIT License
