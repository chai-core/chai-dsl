//! PAM paradigm: Aria's refund gate as a stack of tagged sub-checks.
//!
//! A guard passes when every `required`/`requisite` check passes and, if any
//! `sufficient` check is present, at least one of them passes. This is the shape
//! of a PAM (Pluggable Authentication Modules) stack, proven order-independent
//! and fail-closed in `formal/ChaiProofs/PamGuard.lean`.
//!
//! Run: cargo run --example pam_gate

use chai_dsl::ast::{ChaiProgram, Expr, Value};
use chai_dsl::entity::EntityStore;
use chai_dsl::evaluator::Evaluator;
use chai_dsl::pam::{eval_guard, Flag};
use chai_dsl::parser::parse_chai;
use std::collections::HashMap;

/// Parse one boolean condition into an AST node for the guard.
fn cond(expr: &str) -> Expr {
    match parse_chai(&format!("permit when {expr}\n")).unwrap() {
        ChaiProgram::SingleLineRules(rules) => rules[0].condition.clone().unwrap(),
        _ => unreachable!("single-line rule"),
    }
}

/// Build a request context for one scenario.
fn ctx(trust: i64, tainted: bool, role: &str, amount: i64) -> HashMap<String, Value> {
    let mut c = HashMap::new();
    c.insert(
        "subject".to_string(),
        Value::Dict(HashMap::from([
            ("trust_tier".to_string(), Value::Int(trust)),
            ("role".to_string(), Value::String(role.to_string())),
        ])),
    );
    c.insert(
        "tooltrace".to_string(),
        Value::Dict(HashMap::from([("tainted_sink".to_string(), Value::Bool(tainted))])),
    );
    c.insert(
        "args".to_string(),
        Value::Dict(HashMap::from([("amount".to_string(), Value::Int(amount))])),
    );
    c
}

fn main() {
    let store = EntityStore::new();

    // Aria may issue a refund when:
    //   required   the agent is trusted        subject.trust_tier >= 2
    //   required   the request is not tainted  tooltrace.tainted_sink == false
    //   sufficient a senior agent always may    subject.role == "senior"
    //   sufficient or the refund is small       args.amount <= 100
    let guard = [
        (Flag::Required, cond("subject.trust_tier >= 2")),
        (Flag::Required, cond("tooltrace.tainted_sink == false")),
        (Flag::Sufficient, cond("subject.role == \"senior\"")),
        (Flag::Sufficient, cond("args.amount <= 100")),
    ];

    println!("=== Aria's refund gate as a PAM stack ===");
    println!("  required:   subject.trust_tier >= 2");
    println!("  required:   tooltrace.tainted_sink == false");
    println!("  sufficient: subject.role == \"senior\"");
    println!("  sufficient: args.amount <= 100\n");

    let scenarios = [
        ("junior, untainted, $50 refund", ctx(3, false, "support", 50)),
        ("junior, untainted, $9999 refund", ctx(3, false, "support", 9999)),
        ("senior, untainted, $9999 refund", ctx(3, false, "senior", 9999)),
        ("junior, TAINTED, $50 refund", ctx(3, true, "support", 50)),
        ("untrusted (tier 1), $50 refund", ctx(1, false, "support", 50)),
    ];

    for (name, context) in scenarios {
        let ev = Evaluator::new(&store).with_context(context);
        let verdict = if eval_guard(&guard, &ev) { "PASS" } else { "DENY" };
        println!("  [{verdict}] {name}");
    }
    println!(
        "\n  A required check fails the whole guard (untrusted, tainted). When a\n  \
         sufficient group exists, one member must pass (a large refund needs the\n  \
         senior role). Order among the checks never changes the verdict."
    );
}
