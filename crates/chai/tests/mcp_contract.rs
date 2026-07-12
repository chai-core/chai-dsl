//! In-process integration for the MCP decision-point contract (`src/mcp_contract.rs`).
//! No external proxy; that's the next (gated) layer. Here we prove the wire
//! layer maps faithfully and never changes the engine's semantics.

use chai_dsl::afc::Afc;
use chai_dsl::ast::{Effect, Value};
use chai_dsl::mcp::{authorize_tool_call, filter_tool_result, AgentSubject};
use chai_dsl::mcp_contract::{
    decide_tools_call, decide_tools_result, govern_sse, parse_tools_call, response_json,
    StreamingResultGovernor,
};
use chai_dsl::{parse_chai, EmitAction, EntityStore};
use serde_json::json;

fn agent(tier: i64) -> AgentSubject {
    AgentSubject::new("Agent::a1").attr("trust_tier", Value::Int(tier))
}

fn tool_result(text: &str) -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": 1,
           "result": {"content": [{"type": "text", "text": text}]}})
}

const GOV_POLICY: &str = "\
@id(\"secret\") deny   when dlp_facts.secrets_found == true\n\
@id(\"pii\")    redact when dlp_facts.pii_confidence > 0.4\n\
@id(\"clean\")  permit when dlp_facts.pii_confidence <= 0.4\n";

fn tools_call(tool: &str, args: serde_json::Value) -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": args}})
}

/// The wire layer must produce EXACTLY the decision the engine would, for every
/// (policy, identity, message); it only transports, never reinterprets.
#[test]
fn contract_matches_engine_semantics() {
    let program = parse_chai(
        "@id(\"low\")  forbid when subject.trust_tier < 3\n\
         @id(\"high\") permit when subject.trust_tier >= 3\n",
    )
    .unwrap();
    let store = EntityStore::new();

    for tier in [0i64, 2, 3, 9] {
        for tool in ["db.read", "db.write", "vault.read"] {
            let subject = agent(tier);
            let msg = tools_call(tool, json!({"k": "v"}));

            let via_contract = decide_tools_call(&program, &store, &subject, &msg, None).effect;
            let call = parse_tools_call(&msg).unwrap();
            let via_engine =
                authorize_tool_call(&program, &store, &subject, &call.tool, &call.args, None)
                    .unwrap()
                    .effect;

            assert_eq!(
                format!("{via_contract:?}"),
                format!("{via_engine:?}"),
                "wire layer changed semantics for tier {tier} tool {tool}"
            );
        }
    }
}

/// Policy over a tool ARGUMENT must see the argument the message carried; proves
/// arg binding flows from JSON-RPC params into the eval context.
#[test]
fn argument_bound_policy() {
    let program = parse_chai(
        "@id(\"big\") forbid when args.limit >= 100\n\
         @id(\"ok\")  permit when args.limit < 100\n",
    )
    .unwrap();
    let store = EntityStore::new();
    let subject = agent(5);

    let small = decide_tools_call(&program, &store, &subject, &tools_call("db.read", json!({"limit": 10})), None);
    assert!(matches!(small.effect, Effect::Allow));

    let big = decide_tools_call(&program, &store, &subject, &tools_call("db.read", json!({"limit": 500})), None);
    assert!(matches!(big.effect, Effect::Deny));
    assert_eq!(big.rule_trace, vec!["big".to_string()]);
}

/// Even under a permit-everything policy, a malformed message denies (fail-closed).
#[test]
fn malformed_message_is_fail_closed() {
    let program = parse_chai("permit when true\n").unwrap();
    let store = EntityStore::new();
    let subject = agent(9);

    // missing params / name
    let d = decide_tools_call(&program, &store, &subject, &json!({"jsonrpc": "2.0", "method": "tools/call"}), None);
    assert!(matches!(d.effect, Effect::Deny));

    // not even JSON-RPC
    let d = decide_tools_call(&program, &store, &subject, &json!({"foo": "bar"}), None);
    assert!(matches!(d.effect, Effect::Deny));
}

/// Result governance over the wire must match the engine's `filter_tool_result`
/// exactly; the wire layer transports, the AFC→ESP→Emission semantics are
/// unchanged. Also exercises the actual emit/redact/drop differentiator.
#[test]
fn result_governance_matches_engine() {
    let program = parse_chai(GOV_POLICY).unwrap();
    let store = EntityStore::new();
    let afc = Afc::with_default_detectors();
    let subject = agent(5);

    for (text, want) in [
        ("row count: 42", "emit"),
        ("ssn 123-45-6789 email a@b.co", "redact"), // real PII -> span masked -> redact
        ("ssn and email on file", "drop"),          // PII words, no maskable value -> fail closed
        ("password: hunter2", "drop"),
    ] {
        let via_wire = decide_tools_result(&program, &store, &afc, &subject, "db.read", &tool_result(text));
        let via_engine = filter_tool_result(&program, &store, &afc, &subject, "db.read", text);

        // wire == engine
        assert_eq!(format!("{:?}", via_wire.action), format!("{:?}", via_engine.action), "wire≠engine for {text:?}");
        // and it is the expected governance action
        let got = match via_wire.action {
            EmitAction::Emit(_) => "emit",
            EmitAction::Redact(_) => "redact",
            EmitAction::Drop => "drop",
            _ => "other",
        };
        assert_eq!(got, want, "wrong governance for {text:?}");
    }
}

/// A malformed result response is dropped, never emitted (fail-closed), even
/// under a permit-everything policy.
#[test]
fn malformed_result_is_dropped() {
    let program = parse_chai("permit when true\n").unwrap();
    let store = EntityStore::new();
    let afc = Afc::with_default_detectors();
    let subject = agent(9);

    let d = decide_tools_result(&program, &store, &afc, &subject, "db.read", &json!({"jsonrpc": "2.0", "id": 1}));
    assert!(matches!(d.action, EmitAction::Drop));
}

/// Streaming result governance: the proven Emission state machine drives a chunked
/// result. Clean prefixes emit; the chunk that trips a deny is dropped (the secret
/// never leaves), while earlier safe chunks were already released.
#[test]
fn streaming_result_enforced_prefix_by_prefix() {
    let program = parse_chai(
        "@id(\"secret\") deny   when dlp_facts.secrets_found == true\n\
         @id(\"ok\")     permit when true\n",
    )
    .unwrap();
    let store = EntityStore::new();
    let afc = Afc::with_default_detectors();
    let subject = agent(5);

    let mut gov = StreamingResultGovernor::new(&program, &store, &afc, &subject, "db.read");
    assert!(matches!(gov.chunk("row 1 "), EmitAction::Emit(_)));        // clean -> emit
    assert!(matches!(gov.chunk("row 2 "), EmitAction::Emit(_)));        // still clean -> emit
    assert!(matches!(gov.chunk("password: hunter2"), EmitAction::Drop)); // secret -> dropped
    assert!(matches!(gov.finish(), EmitAction::Drop));
}

/// Fail-closed at end-of-stream: content deferred (buffered) but never approved is
/// dropped by `finish`, never emitted.
#[test]
fn streaming_unapproved_buffer_dropped_at_finish() {
    let program = parse_chai("@id(\"hold\") defer when true\n").unwrap();
    let store = EntityStore::new();
    let afc = Afc::with_default_detectors();
    let subject = agent(5);

    let mut gov = StreamingResultGovernor::new(&program, &store, &afc, &subject, "db.read");
    assert!(matches!(gov.chunk("partial sensitive data"), EmitAction::Buffer));
    assert!(matches!(gov.finish(), EmitAction::Drop)); // never approved -> dropped
}

/// SSE wire transport: an SSE-framed streamable-HTTP tool result is parsed into
/// chunks, governed by the proven state machine, and re-framed as SSE. Clean
/// prefixes are forwarded as `data:` events; the chunk that trips a deny (secret)
/// is withheld as an SSE comment; its content never appears in the output.
#[test]
fn sse_stream_governed_and_reframed() {
    let program = parse_chai(
        "@id(\"secret\") deny   when dlp_facts.secrets_found == true\n\
         @id(\"ok\")     permit when true\n",
    )
    .unwrap();
    let store = EntityStore::new();
    let afc = Afc::with_default_detectors();
    let subject = agent(5);

    let sse_in = "\
data: row 1 \n\
\n\
data: row 2 \n\
\n\
data: password: hunter2\n\
\n";
    let mut gov = StreamingResultGovernor::new(&program, &store, &afc, &subject, "db.read");
    let out = govern_sse(&mut gov, sse_in);

    // clean prefixes forwarded as data events
    assert!(out.contains("data: row 1 "));
    assert!(out.contains("data: row 2 "));
    // the secret is withheld (dropped) and never appears in the output stream
    assert!(!out.contains("hunter2"), "secret leaked into SSE output:\n{out}");
    assert!(out.contains(": withheld (drop)"));
    // fail-closed end marker
    assert!(out.contains(": end (unapproved buffer dropped)") || out.trim_end().ends_with("(drop)"));
}

/// The verdict serializes into a JSON-RPC response the proxy can act on.
#[test]
fn response_shape() {
    let program = parse_chai("permit when true\n").unwrap();
    let store = EntityStore::new();
    let subject = agent(5);
    let msg = tools_call("db.read", json!({}));
    let decision = decide_tools_call(&program, &store, &subject, &msg, None);

    let resp = response_json(Some(&json!(1)), &decision);
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], json!(1));
    assert_eq!(resp["result"]["verdict"], "allow");
}
