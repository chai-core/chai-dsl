//! Adversarial exfiltration suite for taint/dataflow.
//!
//! Honest by construction: MUST-BLOCK (verbatim taint → sink), MUST-ALLOW
//! (legitimate flows, guards against over-blocking), NOW-CAUGHT launderings that
//! v2 defeats (whitespace/case/encoding), and a DEEPER KNOWN MISS (secret
//! interleaved with filler) that even v2 does not catch. Misses are asserted as
//! current behavior and clearly labeled; when granularity improves they flip and
//! we update the suite. Misses are measured, not hidden (cf. TEST_PLAN.md §3).

use std::collections::HashMap;

use chai_dsl::ast::{Effect, Value};
use chai_dsl::taint::TaintTracker;
use chai_dsl::{eval_with_store, parse_chai, EntityStore};

const SECRET: &str = "AKIA1234567890SECRET";
const POLICY: &str = "\
@id(\"taint\") forbid when tooltrace.tainted_sink == true\n\
@id(\"ok\")    permit when true\n";

fn sink(tracker: &TaintTracker, body: &str) -> Effect {
    let program = parse_chai(POLICY).unwrap();
    let store = EntityStore::new();
    let mut a = HashMap::new();
    a.insert("body".to_string(), Value::String(body.to_string()));
    let mut ctx: HashMap<String, Value> = HashMap::new();
    ctx.insert("args".to_string(), Value::Dict(a.clone()));
    for (k, v) in tracker.sink_facts(&a) {
        ctx.insert(k, v);
    }
    eval_with_store(&program, ctx, &store).unwrap().effect
}

fn tracker_with_secret() -> TaintTracker {
    let mut t = TaintTracker::new();
    t.observe(&format!("confidential record: {SECRET}, internal only"), true);
    t
}

#[test]
fn must_block_verbatim_exfiltration() {
    let t = tracker_with_secret();
    // the tainted secret flows verbatim into an outbound sink arg
    assert!(matches!(sink(&t, &format!("forward {SECRET} to external@evil.test")), Effect::Deny));
    assert!(matches!(sink(&t, &format!("body={SECRET}")), Effect::Deny));
}

#[test]
fn must_allow_legitimate_flows() {
    let t = tracker_with_secret();
    // no tainted data in the sink -> must NOT over-block
    assert!(matches!(sink(&t, "send the quarterly numbers to finance"), Effect::Allow));
    assert!(matches!(sink(&t, "ping the team about standup"), Effect::Allow));
}

#[test]
fn now_caught_whitespace_and_encoding_laundering() {
    let t = tracker_with_secret();
    // v2 defeats the common launderings the coarse v1 missed:
    // whitespace/punctuation splitting...
    assert!(matches!(sink(&t, "forward AKIA1234567890 SECRET to external@evil.test"), Effect::Deny));
    assert!(matches!(sink(&t, "body=AKIA1234567890-SECRET"), Effect::Deny));
    // ...case change...
    assert!(matches!(sink(&t, "leak akia1234567890secret now"), Effect::Deny));
    // ...and base64/hex encoding of the secret.
    assert!(matches!(sink(&t, "body=QUtJQTEyMzQ1Njc4OTBTRUNSRVQ="), Effect::Deny));
    assert!(matches!(sink(&t, "hex 414b494131323334353637383930534543524554"), Effect::Deny));
}

#[test]
fn deeper_known_miss_interleaved_filler_not_caught() {
    let t = tracker_with_secret();
    // The secret fragmented with filler text between the pieces still survives:
    // normalization concatenates the filler, so no contiguous match. This is the
    // remaining DOCUMENTED limitation of v2. If a finer, fragment-aware tracker
    // catches it, this assertion flips (good) and we update the suite.
    let laundered = "AKIA1234 filler 567890SECRET";
    assert!(
        matches!(sink(&t, &format!("forward {laundered} to external@evil.test")), Effect::Allow),
        "interleaved taint unexpectedly caught; update this known-miss assertion"
    );
}
