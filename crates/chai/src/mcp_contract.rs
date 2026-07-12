//! MCP decision-point contract. The wire layer a proxy (agentgateway, FastMCP)
//! calls to enforce policy on intercepted MCP traffic.
//!
//! Flow: JSON-RPC MCP message + identity -> mapped request -> Decision -> verdict.
//! Thin and proxy-agnostic. It shapes an MCP message into the policy context and
//! delegates to the tested bindings in `mcp.rs`. All parsing is fail-closed. A
//! malformed message yields `Deny`, never `Allow`.
//!
//! Layers below this: `mcp.rs` (bindings) -> `evaluator.rs` (ESP, differential-
//! tested and Lean-proven decision algebra) -> `emission.rs`.

use crate::afc::Afc;
use chai_core::ast::{ChaiProgram, Decision, Effect, Value};
use chai_core::emission::{EmissionEnforcer, EmitAction};
use chai_core::entity::{json_to_value, EntityStore};
use crate::mcp::{authorize_tool_call, filter_tool_result, AgentSubject, ResultDecision};
use std::collections::HashMap;

/// A decoded MCP `tools/call` request. Only the fields policy cares about.
#[derive(Debug, Clone, PartialEq)]
pub struct McpCall {
    pub id: Option<serde_json::Value>,
    pub tool: String,
    pub args: HashMap<String, Value>,
}

/// Parse a JSON-RPC 2.0 MCP `tools/call` message. Fail-closed. Any unexpected
/// shape is an `Err`, which the caller turns into a `Deny`.
pub fn parse_tools_call(msg: &serde_json::Value) -> Result<McpCall, String> {
    if msg.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return Err("missing or wrong jsonrpc version".into());
    }
    match msg.get("method").and_then(|v| v.as_str()) {
        Some("tools/call") => {}
        Some(other) => return Err(format!("unexpected method {other}")),
        None => return Err("missing method".into()),
    }
    let params = msg.get("params").and_then(|v| v.as_object()).ok_or("missing params object")?;
    let tool = params.get("name").and_then(|v| v.as_str()).ok_or("missing params.name")?.to_string();
    let args: HashMap<String, Value> = match params.get("arguments") {
        None => HashMap::new(),
        Some(serde_json::Value::Object(o)) => {
            o.iter().map(|(k, v)| (k.clone(), json_to_value(v))).collect()
        }
        Some(_) => return Err("params.arguments must be an object".into()),
    };
    Ok(McpCall { id: msg.get("id").cloned(), tool, args })
}

/// Parse an identity envelope `{"uid": "...", "attrs": {...}}` into an
/// `AgentSubject`. Fail-closed. A missing or invalid uid is an `Err`.
pub fn parse_identity(v: &serde_json::Value) -> Result<AgentSubject, String> {
    let uid = v.get("uid").and_then(|u| u.as_str()).ok_or("identity missing uid")?;
    let mut subject = AgentSubject::new(uid);
    if let Some(attrs) = v.get("attrs").and_then(|a| a.as_object()) {
        for (k, val) in attrs {
            subject.attrs.insert(k.clone(), json_to_value(val));
        }
    }
    Ok(subject)
}

/// Wire string for a decision effect.
pub fn verdict_str(effect: &Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny | Effect::Forbid => "deny",
        Effect::RequireHuman => "require_human",
        Effect::Defer => "defer",
        Effect::Redact => "redact",
        Effect::Downgrade => "downgrade",
    }
}

/// The contract entry point for a `tools/call`. Parses, maps, then decides. Total
/// and fail-closed. A parse error or an eval error returns a `Deny` decision, so a
/// malformed or hostile message can never authorize a call.
pub fn decide_tools_call(
    program: &ChaiProgram,
    store: &EntityStore,
    subject: &AgentSubject,
    msg: &serde_json::Value,
    resource: Option<&str>,
) -> Decision {
    let call = match parse_tools_call(msg) {
        Ok(c) => c,
        Err(e) => return fail_closed(format!("malformed tools/call: {e}")),
    };
    match authorize_tool_call(program, store, subject, &call.tool, &call.args, resource) {
        Ok(d) => d,
        Err(e) => fail_closed(format!("eval error: {e}")),
    }
}

/// What an interceptor should do with a forwarded MCP body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateVerdict {
    /// Forward it (an authorized `tools/call`, or MCP plumbing we do not gate).
    Allow,
    /// Block it (a `tools/call` the policy denies, or anything we cannot authorize).
    Deny,
    /// Not a `tools/call`; forward as protocol plumbing (initialize, tools/list,
    /// notifications, ping). Kept distinct from `Allow` for clarity at the caller.
    PassThrough,
}

fn is_tools_call(msg: &serde_json::Value) -> bool {
    msg.get("method").and_then(|m| m.as_str()) == Some("tools/call")
}

fn call_allowed(program: &ChaiProgram, store: &EntityStore, subject: &AgentSubject, msg: &serde_json::Value) -> bool {
    matches!(decide_tools_call(program, store, subject, msg, None).effect, Effect::Allow)
}

/// The single gate every request-authorization transport (HTTP ext-authz, gRPC
/// ext-authz, ICAP REQMOD) shares. Parses a forwarded body and decides whether to
/// forward or block, fail-closed. Gating only `tools/call` lets MCP plumbing
/// through, since gating the handshake would kill the session.
///
/// A JSON-RPC **batch** (a top-level array) is handled explicitly: every
/// `tools/call` element must be authorized, and the whole batch is denied if any
/// is not. Without this a batch would parse as an array whose top-level `method`
/// is absent, slip past a naive `method == "tools/call"` check, and be forwarded
/// unauthorized.
pub fn gate_intercepted_body(
    program: &ChaiProgram,
    store: &EntityStore,
    subject: &AgentSubject,
    body: &[u8],
) -> GateVerdict {
    let msg: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        // Not JSON we can inspect; treat as non-tools/call plumbing.
        Err(_) => return GateVerdict::PassThrough,
    };
    if let serde_json::Value::Array(items) = &msg {
        let mut saw_call = false;
        for item in items {
            if is_tools_call(item) {
                saw_call = true;
                if !call_allowed(program, store, subject, item) {
                    return GateVerdict::Deny;
                }
            }
        }
        return if saw_call { GateVerdict::Allow } else { GateVerdict::PassThrough };
    }
    if is_tools_call(&msg) {
        if call_allowed(program, store, subject, &msg) {
            GateVerdict::Allow
        } else {
            GateVerdict::Deny
        }
    } else {
        GateVerdict::PassThrough
    }
}

/// Extract the governable text from an MCP `tools/call` result (a JSON-RPC
/// response). Concatenates its `result.content[]` text blocks. Non-text blocks
/// (image/resource) are skipped. Fail-closed. A malformed response is an `Err`,
/// which the caller turns into a `Drop`.
pub fn parse_tool_result(msg: &serde_json::Value) -> Result<String, String> {
    if msg.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return Err("missing or wrong jsonrpc version".into());
    }
    let result = msg.get("result").and_then(|v| v.as_object()).ok_or("missing result object")?;
    let content = result.get("content").and_then(|c| c.as_array()).ok_or("missing result.content array")?;
    let mut text = String::new();
    for block in content {
        if block.get("type").and_then(|t| t.as_str()) == Some("text") {
            let t = block.get("text").and_then(|t| t.as_str()).ok_or("text block missing text")?;
            text.push_str(t);
        }
    }
    Ok(text)
}

/// The contract entry point for governing a tool result. Runs the returned data
/// through AFC -> ESP -> Emission (emit / redact / drop / buffer / require-human).
/// Fail-closed. A malformed response is dropped, never emitted.
pub fn decide_tools_result(
    program: &ChaiProgram,
    store: &EntityStore,
    afc: &Afc,
    subject: &AgentSubject,
    tool: &str,
    msg: &serde_json::Value,
) -> ResultDecision {
    match parse_tool_result(msg) {
        Ok(text) => filter_tool_result(program, store, afc, subject, tool, &text),
        Err(e) => ResultDecision {
            action: EmitAction::Drop,
            decision: fail_closed(format!("malformed tool result: {e}")),
        },
    }
}

/// Governs a streamed tool result chunk by chunk, driving the Emission state
/// machine. For each chunk the running prefix's facts are recomputed and ESP
/// decides. The caller forwards `Emit`/`Redact` output and withholds
/// `Buffer`/`Drop`/`RequireHuman`. At end-of-stream, any unapproved buffered
/// prefix is dropped (fail-closed).
///
/// Use this for streamable-HTTP/SSE tool results. `decide_tools_result` is the
/// whole-result equivalent.
pub struct StreamingResultGovernor<'a> {
    enforcer: EmissionEnforcer<'a>,
    afc: &'a Afc,
    prefix: String,
    step: u64,
}

impl<'a> StreamingResultGovernor<'a> {
    pub fn new(
        program: &'a ChaiProgram,
        store: &'a EntityStore,
        afc: &'a Afc,
        subject: &AgentSubject,
        tool: &str,
    ) -> Self {
        // Same binding as the whole-result path: principal (UID) + subject (attrs) + action.
        let base = crate::mcp::base_context(subject, tool);
        StreamingResultGovernor {
            enforcer: EmissionEnforcer::new(program, store, base),
            afc,
            prefix: String::new(),
            step: 0,
        }
    }

    /// Govern one streamed chunk. Facts are computed over the prefix so far (`F_t`).
    pub fn chunk(&mut self, text: &str) -> EmitAction {
        self.prefix.push_str(text);
        let facts = self.afc.compute(&self.prefix, self.step);
        self.step += 1;
        self.enforcer.step(text, facts.to_context())
    }

    /// End of stream. Drops any unapproved buffer (fail-closed).
    pub fn finish(&mut self) -> EmitAction {
        self.enforcer.finish()
    }
}

/// Wire string for an emission action.
pub fn result_verdict_str(action: &EmitAction) -> &'static str {
    match action {
        EmitAction::Emit(_) => "emit",
        EmitAction::Redact(_) => "redact",
        EmitAction::Buffer => "buffer",
        EmitAction::Drop => "drop",
        EmitAction::RequireHuman => "require_human",
    }
}

/// JSON-RPC response for a governed result. Carries the verdict plus the possibly
/// transformed content the proxy may forward. `content` is null when nothing is
/// released (buffer / drop / require-human).
pub fn result_response_json(
    id: Option<&serde_json::Value>,
    decision: &ResultDecision,
) -> serde_json::Value {
    let content = match &decision.action {
        EmitAction::Emit(s) | EmitAction::Redact(s) => Some(s.clone()),
        _ => None,
    };
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(serde_json::Value::Null),
        "result": {
            "verdict": result_verdict_str(&decision.action),
            "content": content,
        }
    })
}

/// JSON-RPC response carrying the verdict, for the proxy to act on.
pub fn response_json(id: Option<&serde_json::Value>, decision: &Decision) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(serde_json::Value::Null),
        "result": {
            "verdict": verdict_str(&decision.effect),
            "reason": decision.reason,
            "rule_trace": decision.rule_trace,
        }
    })
}

fn fail_closed(reason: String) -> Decision {
    chai_core::emission::fail_closed_deny(reason)
}

// --- SSE wire transport ---------------------------------------------------
//
// Streamable-HTTP tool results arrive as Server-Sent Events. This is the
// transport layer that frames such a stream into chunks, drives the proven
// `StreamingResultGovernor` over them, and re-frames the governed output as SSE.
// The enforcement is the state machine; this only parses and serializes frames.

/// Parse an SSE stream into the sequence of event `data` payloads, per the
/// EventStream spec: within an event, `data:` lines are joined with `\n`; a
/// leading space after the colon is stripped; comment lines (`:`…) and other
/// fields (`event:`, `id:`, `retry:`) are ignored; a blank line ends an event.
/// Each payload is treated as one tool-result text chunk (`x_t`).
pub fn parse_sse_events(input: &str) -> Vec<String> {
    let mut events = Vec::new();
    let mut data: Vec<String> = Vec::new();
    let mut have = false;
    for raw in input.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            if have {
                events.push(std::mem::take(&mut data).join("\n"));
                have = false;
            }
        } else if line.starts_with(':') {
            continue; // comment
        } else if let Some(rest) = line.strip_prefix("data:") {
            data.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
            have = true;
        }
        // event:/id:/retry: and unknown fields are ignored
    }
    if have {
        events.push(data.join("\n"));
    }
    events
}

/// Serialize a released string as one SSE `data:` event (embedded newlines split
/// across `data:` lines, per spec).
fn sse_data(s: &str) -> String {
    format!("data: {}\n\n", s.replace('\n', "\ndata: "))
}

/// Drive a `StreamingResultGovernor` over an SSE-framed tool-result stream and
/// return the governed stream, also SSE-framed. Released prefixes (`emit`,
/// `redact`) become `data:` events; withheld chunks (`buffer`, `drop`,
/// `require_human`) become SSE **comments** carrying only the verdict label; the
/// stream stays valid and forwards no unapproved content. Fail-closed: an
/// unapproved buffer is dropped at end-of-stream.
pub fn govern_sse(gov: &mut StreamingResultGovernor<'_>, sse_input: &str) -> String {
    let mut out = String::new();
    for payload in parse_sse_events(sse_input) {
        match gov.chunk(&payload) {
            EmitAction::Emit(s) | EmitAction::Redact(s) => out.push_str(&sse_data(&s)),
            EmitAction::Buffer => out.push_str(": withheld (buffer)\n\n"),
            EmitAction::Drop => out.push_str(": withheld (drop)\n\n"),
            EmitAction::RequireHuman => out.push_str(": halted (require_human)\n\n"),
        }
    }
    match gov.finish() {
        EmitAction::Emit(s) | EmitAction::Redact(s) => out.push_str(&sse_data(&s)),
        _ => out.push_str(": end (unapproved buffer dropped)\n\n"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gate_policy() -> ChaiProgram {
        chai_core::parser::parse_chai(
            "@id(\"untrusted\") forbid when subject.trust_tier < 3\n\
             @id(\"ok\") permit when subject.trust_tier >= 3\n",
        )
        .unwrap()
    }

    #[test]
    fn gate_authorizes_single_calls_batches_and_plumbing() {
        let program = gate_policy();
        let store = EntityStore::new();
        let hi = AgentSubject::new("Agent::a1").attr("trust_tier", Value::Int(4));
        let lo = AgentSubject::new("Agent::a1").attr("trust_tier", Value::Int(1));
        let call = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}"#;
        assert_eq!(gate_intercepted_body(&program, &store, &hi, call), GateVerdict::Allow);
        assert_eq!(gate_intercepted_body(&program, &store, &lo, call), GateVerdict::Deny);
        // Plumbing and non-JSON pass through (gating the handshake kills the session).
        let init = br#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#;
        assert_eq!(gate_intercepted_body(&program, &store, &lo, init), GateVerdict::PassThrough);
        assert_eq!(gate_intercepted_body(&program, &store, &lo, b"not json"), GateVerdict::PassThrough);
        // Regression: a JSON-RPC batch (top-level array) must not slip past the gate.
        let batch = br#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}]"#;
        assert_eq!(gate_intercepted_body(&program, &store, &lo, batch), GateVerdict::Deny);
        assert_eq!(gate_intercepted_body(&program, &store, &hi, batch), GateVerdict::Allow);
        // A batch containing a denied call is denied whole, even if another is fine.
        let mixed = br#"[{"jsonrpc":"2.0","method":"initialize"},{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":{}}}]"#;
        assert_eq!(gate_intercepted_body(&program, &store, &lo, mixed), GateVerdict::Deny);
        // A batch of only plumbing passes through.
        let batch_plumbing = br#"[{"jsonrpc":"2.0","id":0,"method":"initialize"}]"#;
        assert_eq!(gate_intercepted_body(&program, &store, &lo, batch_plumbing), GateVerdict::PassThrough);
    }

    // JSON-RPC decode and mapping.

    #[test]
    fn parse_valid_tools_call() {
        let msg = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "db.write", "arguments": {"table": "users", "limit": 10}}
        });
        let call = parse_tools_call(&msg).unwrap();
        assert_eq!(call.tool, "db.write");
        assert_eq!(call.id, Some(json!(7)));
        assert_eq!(call.args.get("table"), Some(&Value::String("users".into())));
        assert_eq!(call.args.get("limit"), Some(&Value::Int(10)));
    }

    #[test]
    fn parse_missing_arguments_defaults_empty() {
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t"}});
        assert!(parse_tools_call(&msg).unwrap().args.is_empty());
    }

    #[test]
    fn parse_rejects_malformed() {
        // wrong version
        assert!(parse_tools_call(&json!({"jsonrpc": "1.0", "method": "tools/call", "params": {"name": "t"}})).is_err());
        // wrong method
        assert!(parse_tools_call(&json!({"jsonrpc": "2.0", "method": "tools/list", "params": {}})).is_err());
        // missing name
        assert!(parse_tools_call(&json!({"jsonrpc": "2.0", "method": "tools/call", "params": {}})).is_err());
        // arguments not an object
        assert!(parse_tools_call(&json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "t", "arguments": 5}})).is_err());
        // not even an object
        assert!(parse_tools_call(&json!("garbage")).is_err());
    }

    #[test]
    fn parse_identity_fields() {
        let id = json!({"uid": "Agent::a1", "attrs": {"trust_tier": 4}});
        let s = parse_identity(&id).unwrap();
        assert_eq!(s.uid, "Agent::a1");
        assert_eq!(s.attrs.get("trust_tier"), Some(&Value::Int(4)));
        // Missing uid is a fail-closed Err.
        assert!(parse_identity(&json!({"attrs": {}})).is_err());
    }

    #[test]
    fn verdict_strings() {
        assert_eq!(verdict_str(&Effect::Allow), "allow");
        assert_eq!(verdict_str(&Effect::Forbid), "deny");
        assert_eq!(verdict_str(&Effect::Deny), "deny");
        assert_eq!(verdict_str(&Effect::RequireHuman), "require_human");
    }

    // Fail-closed end-to-end on bad input.

    #[test]
    fn decide_malformed_message_denies() {
        let program = chai_core::parser::parse_chai("permit when true\n").unwrap();
        let store = EntityStore::new();
        let subject = AgentSubject::new("Agent::a1");
        // A permit-everything policy, but a malformed message must still deny.
        let d = decide_tools_call(&program, &store, &subject, &json!({"method": "tools/call"}), None);
        assert!(matches!(d.effect, Effect::Deny));
        assert_eq!(d.reason_codes, vec!["fail_closed".to_string()]);
    }

    // Tool-result parsing.

    #[test]
    fn parse_result_concatenates_text_blocks() {
        let msg = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {"content": [
                {"type": "text", "text": "row 1\n"},
                {"type": "image", "data": "..."},
                {"type": "text", "text": "row 2"}
            ]}
        });
        assert_eq!(parse_tool_result(&msg).unwrap(), "row 1\nrow 2");
    }

    #[test]
    fn parse_result_rejects_malformed() {
        assert!(parse_tool_result(&json!({"result": {"content": []}})).is_err()); // no jsonrpc
        assert!(parse_tool_result(&json!({"jsonrpc": "2.0", "id": 1})).is_err()); // no result
        assert!(parse_tool_result(&json!({"jsonrpc": "2.0", "result": {}})).is_err()); // no content
    }

    // SSE framing.

    #[test]
    fn parse_sse_events_spec_shapes() {
        // basic events, leading-space strip, multi-line data join, comment + other
        // fields ignored, trailing event with no final blank line.
        let input = "\
event: message\n\
data: hello\n\
\n\
: a comment\n\
data:no-space\n\
\n\
data: line1\n\
data: line2\n\
\n\
id: 9\n\
data: last";
        assert_eq!(
            parse_sse_events(input),
            vec!["hello".to_string(), "no-space".to_string(), "line1\nline2".to_string(), "last".to_string()]
        );
        assert!(parse_sse_events("").is_empty());
        assert!(parse_sse_events(": only a comment\n\n").is_empty());
    }
}
