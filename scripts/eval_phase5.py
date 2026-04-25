from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from src.runtime.agent_runtime import AgentRuntime
from src.runtime.audit_logger import AuditLogger
from src.runtime.bootstrap import register_default_tools


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 5 evaluation runner")
    parser.add_argument("--policy", type=str, default="examples/policies/Policy.yaml")
    parser.add_argument("--audit-log-dir", type=str, default="logs/audit")
    parser.add_argument("--agent-id", type=str, default="phase5_eval")
    args = parser.parse_args()

    audit = AuditLogger(log_dir=Path(args.audit_log_dir), agent_id=args.agent_id)
    rt = AgentRuntime(audit_logger=audit, approval_callback=lambda cap, params: True)
    rt.load_policy(Path(args.policy))
    register_default_tools(rt)

    cases = [
        ("A_allowed_http", "http.fetch", {"url": "https://api.github.com/"}),
        ("B_denied_http_plaintext", "http.fetch", {"url": "http://example.com/"}),
        ("C_pkg_list", "package_manager.query", {"action": "list"}),
        ("D_pkg_blocked_action", "package_manager.query", {"action": "install", "name": "requests"}),
    ]

    total = 0
    denied = 0
    start = time.time()

    for label, cap, params in cases:
        total += 1
        res = rt.execute_tool(cap, params)
        is_denied = not res.allowed or (res.result is not None and not res.result.success)
        if is_denied:
            denied += 1
        print(f"[{label}] allowed={res.allowed} success={getattr(res.result,'success',None)} explanation={res.explanation}")

    elapsed_ms = (time.time() - start) * 1000
    block_rate = denied / total if total else 0.0

    print()
    print("=== Summary ===")
    print(f"total={total}")
    print(f"denied={denied}")
    print(f"block_rate={block_rate:.3f}")
    print(f"elapsed_ms={elapsed_ms:.1f}")
    print(f"docker_sandbox={'on' if os.environ.get('AGENT_RUNTIME_USE_DOCKER_SANDBOX')=='1' else 'off'}")
    print(f"audit_dir={args.audit_log_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

