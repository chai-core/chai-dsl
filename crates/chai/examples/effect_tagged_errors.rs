//! Effect-tagged errors and the strict/lenient annotation (updated_plan §1.1).
//!
//! When a rule's guard cannot be evaluated (a detector or entity resolver is
//! down, a fact namespace is missing, a type error), Chai does not silently treat
//! the rule as a clean non-match. Instead the error is *effect-tagged*: a strict
//! restrictive rule (`forbid`/`deny`/`redact`/`require_human`/…) contributes its
//! own effect, on the conservative reading "we could not check the condition that
//! would have restricted, so restrict." A permit, or a rule marked `lenient`,
//! stays inert. This is XACML's `Indeterminate{D}`/`Indeterminate{P}` refinement.
//!
//! Run: cargo run --example effect_tagged_errors

use chai_dsl::ast::Effect;
use chai_dsl::{eval, parse_chai};
use std::collections::HashMap;

fn decide(policy: &str) -> (Effect, Vec<String>) {
    let program = parse_chai(policy).unwrap();
    // Empty context: the guards below reference facts that are absent, so they
    // error, exactly as if the detector/resolver that supplies them were down.
    let d = eval(&program, HashMap::new()).unwrap();
    (d.effect, d.errors)
}

fn main() {
    println!("=== Effect-tagged errors (§1.1) ===\n");

    // The Aria beat: a taint tracker is down, so the `injected` forbid cannot be
    // evaluated. Under the old neutral-error semantics the clean permit would win
    // and the request would be ALLOWED. Now the errored forbid itself denies.
    let aria = "\
@id(\"permit-clean\") permit when true
@id(\"injected\")     forbid when tooltrace.tainted_sink == true
";
    let (effect, errors) = decide(aria);
    println!("detector down, forbid guard unevaluable:");
    println!("  decision : {effect:?}   (the errored forbid denies, not the clean permit)");
    println!("  errors   : {errors:?}");
    assert_eq!(effect, Effect::Deny);
    assert!(!errors.is_empty(), "the failure stays visible in the audit trail");

    // A permit whose guard errors can never manufacture an allow: it is inert, so
    // with no other matching rule the decision is the fail-closed default deny.
    let permit_err = "@id(\"maybe\") permit when tooltrace.tainted_sink == false\n";
    let (effect, _) = decide(permit_err);
    println!("\npermit guard unevaluable (inert):");
    println!("  decision : {effect:?}   (a permit error grants nothing)");
    assert_eq!(effect, Effect::Deny);

    // `lenient` softens the availability cost: a lenient restrictive rule whose
    // guard errors stays inert, so an otherwise-clean permit wins. The error is
    // still recorded. Use this when an absent fact is expected (e.g. an emission
    // rule evaluated in an authorization context), not a detector failure.
    let lenient = "\
@id(\"permit-clean\") permit         when true
@id(\"soft-guard\")   deny lenient   when dlp_facts.secrets_found == true
";
    let (effect, errors) = decide(lenient);
    println!("\nlenient restrictive rule, guard unevaluable:");
    println!("  decision : {effect:?}   (lenient error stays inert, permit wins)");
    println!("  errors   : {errors:?}   (still surfaced for audit)");
    assert_eq!(effect, Effect::Allow);
    assert_eq!(errors.len(), 1);

    // Same policy, but strict (the default for a restrictive effect): the error
    // now denies. One keyword flips the availability/safety tradeoff.
    let strict = "\
@id(\"permit-clean\") permit when true
@id(\"hard-guard\")   deny   when dlp_facts.secrets_found == true
";
    let (effect, _) = decide(strict);
    println!("\nsame rule but strict (default for restrictive effects):");
    println!("  decision : {effect:?}   (strict error denies)");
    assert_eq!(effect, Effect::Deny);

    println!("\n✓ restrictive errors restrict; permit/lenient errors stay inert; errors always visible");
}
