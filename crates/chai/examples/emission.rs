//! Streaming emission enforcement end-to-end.
//!
//! Simulates an LLM producing output chunk-by-chunk. Each chunk arrives with
//! injected alignment facts (the AFC layer, stubbed here). The ESP policy
//! decides per prefix and the EmissionEnforcer drives emit / buffer / redact /
//! drop, demonstrating the fail-closed invariant: unsafe content is never
//! released to the sink.

use chai_dsl::ast::Value;
use chai_dsl::{parse_chai, EmissionEnforcer, EmitAction, EntityStore};
use std::collections::HashMap;

fn dlp(pii: f64, secrets: bool) -> HashMap<String, Value> {
    let mut d = HashMap::new();
    d.insert("pii".to_string(), Value::Float(pii));
    d.insert("secrets".to_string(), Value::Bool(secrets));
    let mut f = HashMap::new();
    f.insert("dlp_facts".to_string(), Value::Dict(d));
    f
}

fn main() {
    // ESP policy, ordered, deny-overrides, fail-closed by default.
    let policy = "\
@id(\"secret-guard\") deny when dlp_facts.secrets == true
@id(\"pii-deny\") deny when dlp_facts.pii > 0.8
@id(\"pii-redact\") redact when dlp_facts.pii > 0.5
@id(\"pii-defer\") defer when dlp_facts.pii > 0.3
@id(\"clean\") permit when dlp_facts.pii < 0.3
";
    let program = parse_chai(policy).unwrap();
    let store = EntityStore::new();
    let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

    // (chunk, facts): a stream whose risk rises over time.
    let stream = [
        ("Here is the summary. ", dlp(0.05, false)),
        ("The contact is ", dlp(0.35, false)),     // mild PII -> defer
        ("john at ", dlp(0.45, false)),            // still deferring
        ("example.com. ", dlp(0.60, false)),       // crosses redact band
        ("His SSN is ", dlp(0.92, false)),         // high PII -> deny
        ("123-45-6789", dlp(0.4, true)),           // secret -> deny
    ];

    println!("=== Streaming emission ===\n");
    println!("{:<22} | {:<14} | action", "chunk", "facts(pii,sec)");
    println!("{}", "-".repeat(64));

    let mut released = String::new();
    for (chunk, facts) in stream {
        let pii = if let Some(Value::Dict(d)) = facts.get("dlp_facts") {
            if let Some(Value::Float(p)) = d.get("pii") { *p } else { 0.0 }
        } else { 0.0 };
        let sec = matches!(
            facts.get("dlp_facts"),
            Some(Value::Dict(d)) if matches!(d.get("secrets"), Some(Value::Bool(true)))
        );

        let action = enf.step(chunk, facts);
        match &action {
            EmitAction::Emit(t) => released.push_str(t),
            EmitAction::Redact(t) => released.push_str(t),
            _ => {}
        }
        println!("{:<22} | pii={:<4} sec={:<5} | {:?}", format!("{:?}", chunk), pii, sec, action);
    }
    let _ = enf.finish();

    println!("\n--- what reached the sink ---");
    println!("{:?}", released);

    println!("\n--- audit trail (one decision per chunk) ---");
    for (i, d) in enf.history().iter().enumerate() {
        println!("  step {i}: {:?}: {}", d.effect, d.reason);
    }

    // Fail-closed checks.
    assert!(!released.contains("SSN"), "denied content must never reach the sink");
    assert!(!released.contains("123-45-6789"), "secret must never reach the sink");
    println!("\n✓ fail-closed invariant held: no denied/secret content was released");

    seal_on_presence();
    approve_transition();
}

/// Seal-on-presence (updated_plan §1.2). A chunk that trips BOTH a `deny` and a
/// `require_human` rule is dropped under the deny verdict AND seals the stream for
/// review, so more-alarming evidence never yields a weaker stream-level response
/// than `require_human` alone. Once sealed, every later chunk is dropped.
fn seal_on_presence() {
    println!("\n\n=== Seal-on-presence (deny + require_human) ===\n");
    let policy = "\
@id(\"secret\") deny          when dlp_facts.secrets == true
@id(\"harm\")   require_human when safety_facts.harm > 0.5
";
    let program = parse_chai(policy).unwrap();
    let store = EntityStore::new();
    let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

    // Facts carrying both a secret (deny) and harm (require_human).
    let mut both = dlp(0.1, true);
    let mut safety = HashMap::new();
    safety.insert("harm".to_string(), Value::Float(0.9));
    both.insert("safety_facts".to_string(), Value::Dict(safety));

    let a1 = enf.step("leak + harm", both);
    println!("  chunk 1 (secret AND harm): {a1:?}   sealed={}", enf.is_halted());
    // Deny wins the verdict (chunk dropped), require_human presence seals the stream.
    assert_eq!(a1, EmitAction::Drop);
    assert!(enf.is_halted(), "require_human presence must seal even when deny wins");

    let a2 = enf.step("anything after", dlp(0.0, false));
    println!("  chunk 2 (after seal):     {a2:?}");
    assert_eq!(a2, EmitAction::Drop, "a sealed stream releases nothing further");
    println!("\n✓ deny dropped the chunk AND require_human sealed the stream");
}

/// The Approve transition (updated_plan §1.3). `defer` buffers a chunk; it is
/// released only by a later re-decision under new (approval) facts whose verdict
/// authorizes release. So `defer` is not a delayed drop: an approved buffer is
/// emitted, an unapproved one dies at end of stream.
fn approve_transition() {
    println!("\n\n=== Approve transition (defer -> approve -> release) ===\n");
    let policy = "\
@id(\"approved\") permit when review.stage == \"approved\"
@id(\"hold\")     defer  when review.stage == \"hold\"
";
    let program = parse_chai(policy).unwrap();
    let store = EntityStore::new();

    let review = |stage: &str| {
        let mut r = HashMap::new();
        r.insert("stage".to_string(), Value::String(stage.to_string()));
        let mut f = HashMap::new();
        f.insert("review".to_string(), Value::Dict(r));
        f
    };

    let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());
    let held = enf.step("draft answer for the customer", review("hold"));
    println!("  stream chunk (stage=hold):  {held:?}   (buffered, nothing released)");
    assert_eq!(held, EmitAction::Buffer);

    // A human approves: re-decide the buffered chunk under new facts.
    let released = enf.approve(review("approved"));
    println!("  approve (stage=approved):   {released:?}");
    assert_eq!(released, EmitAction::Emit("draft answer for the customer".into()));

    // Contrast: an unapproved buffer is dropped at end of stream.
    let mut enf2 = EmissionEnforcer::new(&program, &store, HashMap::new());
    enf2.step("never approved", review("hold"));
    let end = enf2.finish();
    println!("  (unapproved buffer) finish: {end:?}   (fail-closed drop)");
    assert_eq!(end, EmitAction::Drop);
    println!("\n✓ approved buffer released; unapproved buffer dropped at end of stream");
}
