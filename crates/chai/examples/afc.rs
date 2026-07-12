//! Full three-layer pipeline: AFC -> ESP -> Emission, on a streaming output.
//!
//! Unlike examples/emission.rs (which injected facts by hand), here the facts
//! are *computed* by the AFC over the growing output prefix. This is the
//! `Chai -> AFC -> ESP -> Emission` flow end to end, with the inference layer
//! (AFC) cleanly separated from the control layer (ESP/Emission).

use chai_dsl::{parse_chai, Afc, EmissionEnforcer, EmitAction, EntityStore};
use std::collections::HashMap;

fn main() {
    // ESP policy over AFC-produced facts.
    let policy = "\
@id(\"secret\")    deny when dlp_facts.secrets_found == true
@id(\"pii-high\")  deny when dlp_facts.pii_confidence > 0.8
@id(\"pii-mid\")   redact when dlp_facts.pii_confidence > 0.4
@id(\"grounded\")  permit when grounding_facts.has_citations == true
@id(\"clean\")     permit when dlp_facts.pii_confidence < 0.4 and safety_facts.harm < 0.4
";
    let program = parse_chai(policy).unwrap();
    let store = EntityStore::new();
    let afc = Afc::with_default_detectors();
    let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

    // The model emits these chunks one at a time.
    let chunks = [
        "According to [Smith 2020], ",
        "the result is clear. ",
        "Contact the author by email ",
        "or share your SSN ",
        "and password: hunter2",
    ];

    println!("=== AFC -> ESP -> Emission (facts computed, not injected) ===\n");
    let mut prefix = String::new();
    let mut released = String::new();

    for (t, chunk) in chunks.iter().enumerate() {
        prefix.push_str(chunk);
        // AFC computes F_t over the prefix so far.
        let bundle = afc.compute(&prefix, t as u64);
        let facts = bundle.to_context();
        // ESP + Emission consume the facts.
        let action = enf.step(chunk, facts);
        match &action {
            EmitAction::Emit(s) | EmitAction::Redact(s) => released.push_str(s),
            _ => {}
        }

        // Show the AFC evidence that drove this step.
        let pii = bundle_pii(&bundle);
        println!("t={t}: {:?}", chunk);
        println!("      AFC: pii_confidence={pii:.2} (method=dlp.keyword)  -> {:?}", action);
    }
    let _ = enf.finish();

    println!("\n--- reached the sink ---\n{:?}", released);

    println!("\n--- decision audit (ESP) ---");
    for (i, d) in enf.history().iter().enumerate() {
        println!("  t={i}: {:?}: {}", d.effect, d.reason);
    }

    assert!(!released.contains("SSN") && !released.to_lowercase().contains("hunter2"));
    println!("\n✓ fail-closed: PII / secret never reached the sink (facts came from AFC)");
}

fn bundle_pii(b: &chai_dsl::FactBundle) -> f64 {
    use chai_dsl::ast::Value;
    match b.to_context().get("dlp_facts") {
        Some(Value::Dict(d)) => match d.get("pii_confidence") {
            Some(Value::Float(f)) => *f,
            _ => 0.0,
        },
        _ => 0.0,
    }
}
