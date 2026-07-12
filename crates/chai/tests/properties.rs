//! Property-based tests (proptest) for invariants that must hold for ALL inputs,
//! mirroring Cedar's use of property testing.

use chai_dsl::ast::{ChaiProgram, Effect, Value};
use chai_dsl::{eval, parse_chai};
use proptest::prelude::*;
use std::collections::HashMap;

/// A context of dlp/safety facts with arbitrary numeric values.
fn arb_context() -> impl Strategy<Value = HashMap<String, Value>> {
    (0.0f64..1.0, 0.0f64..1.0, any::<bool>()).prop_map(|(pii, harm, secret)| {
        let mut dlp = HashMap::new();
        dlp.insert("pii".to_string(), Value::Float(pii));
        dlp.insert("secret".to_string(), Value::Bool(secret));
        let mut safety = HashMap::new();
        safety.insert("harm".to_string(), Value::Float(harm));
        let mut ctx = HashMap::new();
        ctx.insert("dlp_facts".to_string(), Value::Dict(dlp));
        ctx.insert("safety_facts".to_string(), Value::Dict(safety));
        ctx
    })
}

/// Parser fuzz over a grammar-aware alphabet; generates plausible policy text
/// (operators, keywords, punctuation) so it actually exercises the parser rather
/// than bouncing off the first byte. Must never panic.
fn arb_policyish() -> impl Strategy<Value = String> {
    let tok = prop_oneof![
        Just("permit"), Just("forbid"), Just("deny"), Just("redact"), Just("when"),
        Just("and"), Just("or"), Just("not"), Just("=="), Just("<"), Just(">="),
        Just("in"), Just("("), Just(")"), Just("["), Just("]"), Just("=="),
        Just("dlp_facts.pii"), Just("subject.trust_tier"), Just("User::\"a\""),
        Just("0.5"), Just("true"), Just("ip(\"127.0.0.1\")"), Just("\n"), Just(" "),
        Just("@id(\"r\")"), Just("decimal(\"0.5\")"),
    ];
    proptest::collection::vec(tok, 0..40).prop_map(|v| v.concat())
}

proptest! {
    /// Never panic on arbitrary (raw or grammar-shaped) input.
    #[test]
    fn parser_never_panics(s in prop_oneof![".*", arb_policyish()]) {
        let _ = parse_chai(&s);
    }

    /// Monotonicity of forbid: appending `forbid when true` to ANY policy can
    /// only make the decision a Deny; a forbid can never be shadowed into an
    /// allow. (This would fail if deny-override resolution were wrong.)
    #[test]
    fn forbid_is_absorbing(ctx in arb_context(), pii_gate in 0.0f64..1.0) {
        let base = format!("permit when dlp_facts.pii < {pii_gate}\nredact when safety_facts.harm > 0.5\n");
        let with_forbid = format!("{base}forbid when true\n");
        let prog = parse_chai(&with_forbid).unwrap();
        let d = eval(&prog, ctx).unwrap();
        prop_assert!(matches!(d.effect, Effect::Deny), "forbid must absorb to Deny, got {:?}", d.effect);
    }

    /// When exactly one rule can match, first-match and deny-override must agree
    /// (they only differ when multiple rules match).
    #[test]
    fn strategies_agree_on_single_match(pii in 0.0f64..1.0) {
        use chai_dsl::evaluator::eval_with_strategy;
        use chai_dsl::{EntityStore, EvalStrategy};
        // Exactly one rule whose condition depends on pii.
        let prog = parse_chai("permit when dlp_facts.pii < 0.5\n").unwrap();
        let mut dlp = HashMap::new();
        dlp.insert("pii".to_string(), Value::Float(pii));
        let mut ctx = HashMap::new();
        ctx.insert("dlp_facts".to_string(), Value::Dict(dlp));
        let store = EntityStore::new();
        let a = eval_with_strategy(&prog, ctx.clone(), &store, EvalStrategy::DenyOverride).unwrap();
        let b = eval_with_strategy(&prog, ctx, &store, EvalStrategy::FirstMatch).unwrap();
        prop_assert_eq!(format!("{:?}", a.effect), format!("{:?}", b.effect));
    }

    /// Fail-closed: an empty policy denies for ANY context.
    #[test]
    fn empty_policy_always_denies(ctx in arb_context()) {
        let program = ChaiProgram::SingleLineRules(vec![]);
        let d = eval(&program, ctx).unwrap();
        prop_assert!(matches!(d.effect, Effect::Deny));
    }
}
