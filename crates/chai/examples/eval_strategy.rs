//! Two evaluation strategies on the *same* rules, plus @id audit trails.
//!
//! Demonstrates the flexibility (and the footgun) of offering both
//! deny-override (Cedar, safe default) and first-match (ipfw/firewall).

use chai_dsl::ast::Value;
use chai_dsl::{eval_with_strategy, parse_chai, EntityStore, EvalStrategy};
use std::collections::HashMap;

fn bob() -> HashMap<String, Value> {
    let mut c = HashMap::new();
    c.insert("principal".to_string(), Value::EntityUid("User::bob".to_string()));
    c
}

fn main() {
    let store = EntityStore::new();

    // Same two named rules; order: specific permit BEFORE broad deny.
    let policy = "\
@id(\"permit-bob\") permit when principal == User::\"bob\"
@id(\"deny-all\") deny when true
";
    let program = parse_chai(policy).unwrap();

    println!("=== Same rules, two strategies (principal = User::\"bob\") ===");
    println!("  @id(\"permit-bob\") permit when principal == User::\"bob\"");
    println!("  @id(\"deny-all\")   deny when true\n");

    for strategy in [EvalStrategy::DenyOverride, EvalStrategy::FirstMatch] {
        let d = eval_with_strategy(&program, bob(), &store, strategy).unwrap();
        println!("{:<13} -> {:?}   decided by {:?}", format!("{:?}", strategy), d.effect, d.rule_trace);
    }
    println!(
        "\n  deny-override: broad deny always wins -> Deny (order-independent, safe)\n  \
         first-match:   permit-bob comes first -> Allow (order = priority; deny-all shadowed)\n"
    );

    // Full determining-set reporting: multiple forbids both fire.
    let policy2 = "\
@id(\"deny-pii\") deny when dlp.pii > 0.5
@id(\"deny-secret\") deny when dlp.secret == true
@id(\"allow-rest\") permit when true
";
    let program2 = parse_chai(policy2).unwrap();
    let mut ctx = HashMap::new();
    let mut dlp = HashMap::new();
    dlp.insert("pii".to_string(), Value::Float(0.9));
    dlp.insert("secret".to_string(), Value::Bool(true));
    ctx.insert("dlp".to_string(), Value::Dict(dlp));

    let d = eval_with_strategy(&program2, ctx, &store, EvalStrategy::DenyOverride).unwrap();
    println!("=== Full determining-set (deny-override) ===");
    println!("  pii=0.9, secret=true");
    println!("  decision: {:?}", d.effect);
    println!("  reason:   {}", d.reason);
    println!("  trace:    {:?}  (all contributing forbids, not just the first)", d.rule_trace);
}
