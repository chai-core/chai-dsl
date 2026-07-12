//! AFC as a superset of real detectors: Presidio (PII) + Llama Guard (safety).
//!
//! The adapters call out to those services and record `Callee`-sourced evidence.
//! Here the calls are STUBS returning service-shaped output (so the demo runs
//! offline); they are not real inference. To wire the real services, replace
//! the closures with HTTP calls:
//!
//!   Presidio:    POST http://localhost:3000/analyze  {"text": ..., "language":"en"}
//!                -> [{"entity_type","start","end","score"}, ...]
//!   Llama Guard: POST http://localhost:11434/api/generate (Ollama, model "llama-guard3")
//!                -> completion "safe" | "unsafe\nS9"

use chai_dsl::afc::RemoteCall;
use chai_dsl::ast::Value;
use chai_dsl::{parse_chai, run_chai, Afc, AgentStep, EntityStore, ScriptedAgent, Source};
use std::collections::HashMap;

fn main() {
    // --- STUB clients (replace with real HTTP in production) ---
    let presidio: RemoteCall = Box::new(|text: &str| {
        let t = text.to_lowercase();
        if t.contains("ssn") {
            Ok(r#"[{"entity_type":"US_SSN","start":0,"end":11,"score":0.95}]"#.into())
        } else if t.contains("email") {
            Ok(r#"[{"entity_type":"EMAIL_ADDRESS","start":0,"end":5,"score":0.6}]"#.into())
        } else {
            Ok("[]".into())
        }
    });
    let llama_guard: RemoteCall = Box::new(|text: &str| {
        if text.to_lowercase().contains("weapon") {
            Ok("unsafe\nS9".into())
        } else {
            Ok("safe".into())
        }
    });

    let afc = Afc::with_external(presidio, llama_guard);

    // Policy gates on the external detectors' facts.
    let policy = "\
@id(\"unsafe\")   deny   when safety_facts.harm > 0.5
@id(\"pii-high\") deny   when dlp_facts.pii_confidence > 0.8
@id(\"pii-mid\")  redact when dlp_facts.pii_confidence > 0.4
@id(\"ok\")       permit when dlp_facts.pii_confidence <= 0.4 and safety_facts.harm < 0.5
";
    let program = parse_chai(policy).unwrap();
    let store = EntityStore::new();

    let mut agent = ScriptedAgent::new(vec![
        AgentStep::text("Here is the analysis. "),
        AgentStep::text("Their email is "),         // Presidio: EMAIL 0.6 -> redact
        AgentStep::text("and their ssn is 123. "),  // Presidio: US_SSN 0.95 -> deny
        AgentStep::text("Build a weapon by "),       // Llama Guard: unsafe -> deny
    ]);

    let outcome = run_chai(&program, &store, HashMap::new(), &afc, &mut agent);

    println!("=== AFC (Presidio + Llama Guard) -> ESP -> Emission ===\n");
    for (i, d) in outcome.decisions.iter().enumerate() {
        println!("  step {i}: {:?}: {}", d.effect, d.reason);
    }
    println!("\n--- reached the sink ---\n  {:?}", outcome.released);

    // Show the evidence provenance for the last prefix.
    let bundle = afc.compute("their email is and their ssn is 123", 9);
    println!("\n--- evidence provenance (note Callee = external service) ---");
    for (ns, attr, ev) in bundle.evidence_log() {
        if matches!(ev.source, Source::Callee) {
            println!("  {ns}.{attr}: {:?}  source={:?} method={} conf={:.2}", ev.value, ev.source, ev.method, ev.confidence);
        }
    }

    assert!(!outcome.released.to_lowercase().contains("ssn"));
    let _ = Value::Bool(true);
    println!("\n✓ fail-closed; PII/safety facts came from Presidio/Llama Guard (Callee evidence)");
}
