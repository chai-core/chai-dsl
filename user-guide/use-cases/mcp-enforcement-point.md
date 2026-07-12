# Use case: MCP enforcement point

**Goal:** put policy in front of MCP traffic: authorize tool **calls** (which
agent may call which tool with which args) and govern tool **results** (scrub PII
/ block secrets in returned data *before the model sees it*).

You are the **Policy Decision Point (PDP)**. A proxy (FastMCP, agentgateway) is
the **Policy Enforcement Point (PEP)**: it sits in the MCP data path, calls you
per message, and applies your verdict.

```
agent/host ──► PROXY (PEP) ──► MCP servers (tools)
                 │  ▲
       intercept │  │ verdict {allow|deny|redact|...}
                 ▼  │
            YOU (PDP): map → AFC → ESP → Emission → verdict
```

> You are **not** another proxy. You don't terminate transports or handle
> identity; the proxy does. You are the decision the proxy consults.

## The running example: Aria over MCP

Aria (a customer-support agent) reaches her tools through MCP. The same
[`samples/aria.chai`](../../samples/aria.chai) policy drives both directions: it
authorizes her `lookup_account` and `issue_refund` **calls**, and it governs the
**results** those tools return before Aria's model sees them. Two operations, one
policy:

| Operation | Question | API |
|---|---|---|
| **Tool-call authorization** | may this agent call this tool with these args? | `authorize_tool_call` / `decide_tools_call` |
| **Tool-result governance** | is this returned data safe to release (as-is / redacted / not at all)? | `filter_tool_result` / `decide_tools_result` |

Result governance is the **differentiator**: most gateways do call-time authz;
few scrub the data coming back. Aria's `refund-cap`/`untrusted-agent` rules gate
the call; her `secret`/`pii`/`clean` rules gate the result.

## In-process (library)

```rust
use chai_dsl::mcp::{authorize_tool_call, filter_tool_result, AgentSubject};
use chai_dsl::{parse_chai, Afc, EntityStore};
use chai_dsl::ast::{Effect, Value};
use chai_dsl::EmitAction;
use std::collections::HashMap;

let program = parse_chai(include_str!("../samples/aria.chai")).unwrap();
let store = EntityStore::new();
let afc = Afc::with_default_detectors();
let aria = AgentSubject::new("Agent::aria").attr("trust_tier", Value::Int(4));

// 1) authorize a call: an over-cap refund trips refund-cap
let mut args = HashMap::new();
args.insert("amount".into(), Value::Int(9999));
let d = authorize_tool_call(&program, &store, &aria, "issue_refund", &args, None).unwrap();
assert!(matches!(d.effect, Effect::Deny));      // refund-cap

// 2) govern a result: a returned secret trips `secret`
let rd = filter_tool_result(&program, &store, &afc, &aria, "lookup_account", "internal api key: sk-live-abc123");
assert!(matches!(rd.action, EmitAction::Drop)); // secret -> blocked
```

An in-cap refund by a trusted Aria (`trust_tier >= 2`, `amount <= 100`) matches no
`forbid` and is authorized; a `lookup_account` result carrying a card number comes
back `Redact` rather than `Drop`, from the `pii` rule. See
[Cedar-style authorization](cedar-style-authorization.md) for the call-side rules
and [agent-emission governance](agent-emission-governance.md) for the result-side
rules; here they run over the wire.

## From the wire (JSON-RPC): the PDP contract

When the proxy hands you a literal MCP message, use the contract layer
(`mcp_contract`). It is **fail-closed**: a malformed message denies.

```rust
use chai_dsl::mcp_contract::{decide_tools_call, response_json};
use chai_dsl::mcp::AgentSubject;
use serde_json::json;

let msg = json!({
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "issue_refund", "arguments": {"amount": 50}}
});
let aria = AgentSubject::new("Agent::aria").attr("trust_tier", chai_dsl::ast::Value::Int(4));

let decision = decide_tools_call(&program, &store, &aria, &msg, None);
let resp = response_json(Some(&json!(1)), &decision);
// {"jsonrpc":"2.0","id":1,"result":{"verdict":"allow",...}}   (in-cap refund)
```

Policies read tool arguments directly, which is exactly how Aria's `refund-cap`
rule (`action == "issue_refund" and args.amount > 100`) works. Other examples:

```
@id("big-query") forbid when args.limit >= 100
@id("ext-email") forbid when action == "send_email" and not (args.recipients contains "ops@corp.com")
```

For results, `decide_tools_result` parses an MCP result response and runs it
through AFC → ESP → Emission:

```rust
use chai_dsl::mcp_contract::decide_tools_result;
let result_msg = serde_json::json!({
    "jsonrpc": "2.0", "id": 1,
    "result": {"content": [{"type": "text", "text": "customer ssn 123-45-6789 on file"}]}
});
let rd = decide_tools_result(&program, &store, &afc, &aria, "lookup_account", &result_msg);
// rd.action -> Redact("customer ssn [SSN] on file")  (Aria's `pii` rule, span-masked)
// Note: a result with PII *words* but no maskable value (e.g. "ssn on file") is
// dropped instead, since a redaction that removes nothing is fail-closed.
```

### Streamed results (SSE)

For a *streamed* tool result, the contract layer governs it chunk-by-chunk:
`mcp_contract::parse_sse_events` splits the SSE stream and `govern_sse` runs each
prefix through AFC → ESP → Emission. Released prefixes come back as `data:`
events, withheld chunks as SSE comments, and any unapproved buffer is dropped at
end-of-stream, **fail-closed**, streaming, same guarantees as the emission path.
A streamed `lookup_account` result is governed prefix-by-prefix exactly like
Aria's own reply stream.

## Run the sidecar (call from any language)

```sh
cargo run --features server --example sidecar      # -> http://127.0.0.1:8731
```

Endpoints:

```
POST /authorize_tool_call   {subject_uid, subject_attrs, tool, args, resource?}
                         ->  {effect, reason, rule_trace, errors}
POST /filter_tool_result    {subject_uid, subject_attrs, tool, result}
                         ->  {action, released, effect, reason}
POST /filter_tool_result_sse  a streamed SSE tool-result stream
                         ->  governed SSE: `data:` events for released prefixes,
                             SSE comments for withheld chunks, unapproved buffer
                             dropped at end-of-stream (fail-closed)
```

Both are **fail-closed**: an internal error returns a deny/drop.

## Live: FastMCP (the PEP) → sidecar (the PDP)

A complete, runnable integration lives in
[`integrations/fastmcp/`](../../integrations/fastmcp/). FastMCP middleware calls
the sidecar on every tool call and result and enforces the verdict.

```sh
# terminal 1
cargo run --features server --example sidecar
# terminal 2
cd integrations/fastmcp
PYTHONPATH=. ../../eval/.venv/bin/python demo_test.py
```

Observed end-to-end (real run):

```
[PASS] clean result emitted verbatim            -> 'row count: 42'
[PASS] PII result span-masked (PII gone, rest kept)
       -> 'customer ssn [SSN] email [EMAIL] on file'
[PASS] secret result blocked                    -> blocked: ToolError
[PASS] low-trust call denied                    -> denied: ToolError
```

See [Deployment](../03-deployment.md) for wiring details. agentgateway is also
verified live: a request routed through it yields byte-identical verdicts to this
PDP and to FastMCP (read → 200 allow, write → 403 deny).

## Trust boundary (honest)

We prove/test the *decision*; the proxy performs the *enforcement*. The end-to-end
guarantee is conditional on the proxy faithfully (a) invoking us on every relevant
message and (b) applying the verdict, the standard "trusted PEP" boundary (same
as Cedar). The test plan includes fault injection to confirm we fail closed when
the proxy or transport misbehaves.
