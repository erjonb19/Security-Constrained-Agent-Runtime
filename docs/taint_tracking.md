# Taint Tracking (Phase 3 / DESIGN §6.4)

## Why this layer exists

The runtime already has four pre-execution gates: policy lookup, approval,
parameter validation, and pattern-based injection detection. Each one asks a
*different* question about a single tool call:

| Layer | Question |
|---|---|
| Policy engine | Is this capability allowed at all? |
| Approval | Does this need a human sign-off? |
| Parameter validator | Are the parameters structurally safe? |
| Injection detector | Do the values look malicious? |

None of them asks: **where did this value come from?**

That gap matters because the most realistic LLM-agent attack is the confused
deputy: an attacker plants a payload in some upstream resource (a file, a web
page, a previous tool's output), the agent reads it with a low-risk capability,
and then the agent — completely benignly, from its own perspective — feeds part
of that payload to a high-risk capability. None of the existing layers catches
this, because:

- The policy doesn't model data flow between calls.
- Approval was already granted (or not configured) for the sink capability.
- The parameter is structurally fine: a URL is a URL.
- The injection detector looks at *patterns*; an attacker-controlled URL that
  happens to point at `attacker.example.com` is syntactically clean.

The taint tracker fills this gap. It is the **fifth orthogonal gate** in the
pipeline.

## Threat model (in scope)

The attacker controls the content of some upstream resource the agent will
read. They cannot directly call the runtime API. They want the agent to
exfiltrate data, modify state, or pivot to another resource by smuggling a
payload from the upstream resource into a parameter of a downstream call.

Concrete attacks the tracker is designed to catch:

1. **Read-then-fetch exfiltration**: A file (read via `filesystem.read`)
   contains an attacker URL. The agent extracts the URL and calls
   `http.fetch` against it. The tainted URL never matches an injection
   pattern and may even be on an allow-listed host. The taint tracker blocks
   because the URL substring originated in an untrusted source.

2. **Read-then-commit poisoning**: A file contains a snippet the attacker
   wants written into git history. The agent reads the file and includes the
   snippet in a `git.commit` message. Existing layers permit this; the taint
   tracker blocks the flow.

3. **Fetch-then-write data laundering**: An HTTP response contains content
   destined for `filesystem.write`. The detector sees only innocent characters;
   the policy permits the write to a workspace path; the taint tracker
   notices the data came from `http.fetch` and blocks the flow into a sink.

## Threat model (out of scope)

- **Cross-session attacks**: The tracker is process-local. An attacker who can
  restart the agent cleans the taint store. Persistent taint stores are
  worth doing later but not in the MVP.
- **Encoded re-emission**: An adversary who base64-encodes a tainted token
  before it reaches a sink will not be caught by exact-substring matching.
  This is a real limitation; we note it in the paper limitations section
  rather than pretending we cover it.
- **Indirect transformations**: An LLM that paraphrases a tainted token into a
  semantically equivalent string defeats exact match. Same answer: out of
  scope for the MVP, listed in limitations.

## Design

### Where the layer sits

```
execute_tool
  ├── policy engine        (allow/deny)
  ├── approval             (require_approval)
  ├── parameter validator  (structural)
  ├── injection detector   (pattern-based)
  ├── taint tracker  ←  new gate, before tool lookup
  ├── policy resource limits
  └── tool execution
        └── on success: register output as taint source
                        if capability is in DEFAULT_SOURCE_CAPABILITIES
```

The layer runs **after** the injection detector because: (a) anything caught
by injection patterns should be blamed on the detector for cleaner audit
attribution; (b) the taint check is more expensive than pattern matching for
large parameter trees, and a deny from the cheaper layer should short-circuit
the more expensive one.

### What counts as a source

Default source capabilities (see `taint_tracking.DEFAULT_SOURCE_CAPABILITIES`):

- `filesystem.read`
- `http.fetch`
- `git.status`, `git.log`, `git.diff`

The list is conservative: every read-style capability that returns
external-looking content. Operators can override at construction time:

```python
tracker = TaintTracker(source_capabilities=["filesystem.read", "custom.tool"])
```

### What counts as a sink

Default sink capabilities (see `taint_tracking.DEFAULT_SINK_CAPABILITIES`):

- `filesystem.write`
- `git.commit`, `git.push`
- `http.fetch` (yes — both source and sink, intentionally)
- `shell.execute`
- `package_manager.query`

`http.fetch` appears on both lists because the same capability is a source for
*later* sinks (its output may be tainted) and itself a sink for *earlier*
sources (its URL may be tainted by a prior file read). This double-classification
is correct and necessary.

### Token granularity

The tracker splits tool outputs into substrings of at least 16 characters and
treats each as a taint marker. Below 16 characters we get false positives on
common short strings (`"the"`, `"http"`, `"/"`); 16 is empirically the sweet
spot where URLs, paths, command strings, and natural language phrases all
survive intact while noise drops out.

The full output (after stripping) is also retained as a single coarse-grained
token, so a verbatim copy of the entire output is always caught even if no
individual word is long enough on its own.

### Memory bound

`MAX_SOURCES = 256` per tracker, evicted FIFO. This bounds memory under
long-running sessions and prevents an attacker from filling the store with
crafted sources to push earlier real ones out.

### Determinism

Same inputs in the same order produce the same decision. The tracker:
- does not call the LLM
- does not retry
- does not consult external state

This makes denials reproducible and auditable in the strict sense — two
operators replaying the same audit log will reach the same conclusion.

## Audit

Every blocked flow emits one `TAINT_VIOLATION` JSONL event with this shape:

```json
{
  "event_type": "taint_violation",
  "capability": "http.fetch",
  "decision": "deny",
  "reason": "Parameter at 'url' contains data from earlier filesystem.read output (source 7d3a4b…).",
  "context": {
    "source_capability": "filesystem.read",
    "source_id": "7d3a4b9c2e1f8d6a",
    "parameter_path": "url",
    "matched_token": "https://attacker.example.com/exfil-endpoint…"
  }
}
```

The `source_id` is a 16-character prefix of the SHA-256 of the original source
output; operators can use it to correlate the deny event with the earlier
source-registration event in the same audit log if both events are kept (the
source-registration path is currently silent — we don't audit successful
source captures because that would double the log volume on every read).

The `matched_token` field is truncated to 80 characters to ensure a violation
record cannot itself become an exfiltration channel.

## Configuration

Three knobs, in increasing order of how often you'll touch them:

```python
# 1. Disable entirely
runtime = AgentRuntime(taint_tracker=None)

# 2. Custom source/sink lists (most common after MVP)
custom = TaintTracker(
    source_capabilities=["filesystem.read", "custom.tool"],
    sink_capabilities=["git.commit", "custom.danger"],
)
runtime = AgentRuntime(taint_tracker=custom)

# 3. Lower the minimum token length (rarely needed)
fine = TaintTracker(min_token_len=8)
```

## Why this is an MVP

The "MVP" qualifier is honest, not throat-clearing. Concrete things this
implementation does NOT do that a full taint-tracking system would:

- **No transformation tracking.** If the agent splits, recombines, or otherwise
  edits a tainted token, the tracker may lose the trail. We catch verbatim
  substring matches only.
- **No quantitative information flow.** We treat every taint source as equally
  untrusted. A real IFC system might assign labels per source class.
- **No declassification rules.** Some flows from source to sink are
  intentional (e.g., a file read piped through user review back to a write).
  The MVP has no mechanism to mark a flow as approved.
- **No persistence.** Restart loses the taint store.

Each of these is a distinct piece of follow-on work and intentionally out of
scope for the engineering window of Phase 3.

## Test coverage

- `tests/security/test_taint_tracking.py` — 30 unit tests of the module in
  isolation: token extraction, hashing, source registration, sink checking,
  custom configuration.
- `tests/security/test_taint_flow.py` — 6 end-to-end runtime tests:
  source-to-sink violation, false-positive avoidance, failed-source isolation,
  non-source-capability isolation, disabled-tracker pass-through, custom
  source/sink configuration.

All 36 new tests pass. The existing 297-test suite (unit + integration +
adversarial) continues to pass; no regressions.
