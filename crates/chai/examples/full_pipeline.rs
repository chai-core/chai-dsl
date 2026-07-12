//! The complete three-layer system, end to end:
//!   Chai (agent) -> AFC (facts) -> ESP (policy) -> Emission (enforcement)
//!
//! A scripted agent stands in for an LLM. Subject (trust tier) and alignment
//! facts are both gated by ordinary ESP rules. Nothing unsafe reaches the sink.

use chai_dsl::afc::ToolCall;
use chai_dsl::ast::Value;
use chai_dsl::{parse_chai, run_chai, Afc, AgentStep, EntityStore, ScriptedAgent};
use std::collections::HashMap;

fn main() {
    // ESP policy: subject gate + DLP/grounding/risk gates, deny-overrides.
    let policy = "\
@id(\"untrusted\")  forbid when subject.trust_tier < 2
@id(\"secret\")     deny when dlp_facts.secrets_found == true
@id(\"high-risk\")  deny when risk_facts.overall_risk > 0.5
@id(\"sensitive\")  redact when dlp_facts.pii_confidence > 0.4
@id(\"grounded\")   permit when grounding_facts.has_citations == true
@id(\"clean\")      permit when dlp_facts.pii_confidence < 0.4
";
    let program = parse_chai(policy).unwrap();
    let store = EntityStore::new();
    let afc = Afc::with_default_detectors();

    // Subject s: a trust-tier-3 agent.
    let mut subject = HashMap::new();
    subject.insert("trust_tier".to_string(), Value::Int(3));
    let mut ctx = HashMap::new();
    ctx.insert("subject".to_string(), Value::Dict(subject));

    // The "LLM" output, chunk by chunk, with tool actions.
    let mut agent = ScriptedAgent::new(vec![
        AgentStep::text("Per [Doe 2021], the trend holds. ").with_tool("web.search", true),
        AgentStep::text("Background details follow. "),
        AgentStep::text("The contact email is jdoe@acme.com "), // pii rises -> redact, span masked
        AgentStep::text("and the ssn is 123-45-6789 "),         // pii high -> redact, span masked
        AgentStep { text: "password: hunter2".into(), tools: vec![ToolCall { name: "vault.read".into(), ok: false }] }, // secret -> deny/drop
    ]);

    let outcome = run_chai(&program, &store, ctx, &afc, &mut agent);

    println!("=== Full pipeline: Chai -> AFC -> ESP -> Emission ===\n");
    println!("--- ESP decision audit (per agent step) ---");
    for (i, d) in outcome.decisions.iter().enumerate() {
        println!("  step {i}: {:?}: {}", d.effect, d.reason);
    }
    println!("\n--- tools the agent attempted (tooltrace) ---\n  {:?}", outcome.tools_seen);
    println!("\n--- what reached the sink ---\n  {:?}", outcome.released);

    // The actual PII *values* and the secret must never reach the sink. The
    // redact obligation masks the spans (the prose survives; the values do not),
    // and the secret chunk is denied outright.
    assert!(!outcome.released.contains("jdoe@acme.com"), "email leaked");
    assert!(!outcome.released.contains("123-45-6789"), "ssn leaked");
    assert!(!outcome.released.to_lowercase().contains("hunter2"), "secret leaked");
    // Redaction visibly happened: the masked spans are present.
    assert!(
        outcome.released.contains("[EMAIL]") && outcome.released.contains("[SSN]"),
        "expected masked spans in the released text"
    );
    println!("\n✓ fail-closed across the whole stack: PII masked, secret dropped");
}
