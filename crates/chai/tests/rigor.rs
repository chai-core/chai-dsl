//! Boundary and invariant tests: the cases most likely to expose bugs.

use chai_dsl::ast::{Effect, Value};
use chai_dsl::{eval, eval_with_store, parse_chai, Entity, EntityStore, EvalStrategy};
use chai_dsl::evaluator::eval_with_strategy;
use std::collections::HashMap;

fn allows(src: &str) -> bool {
    let p = parse_chai(src).unwrap();
    matches!(eval(&p, HashMap::new()).unwrap().effect, Effect::Allow)
}

#[test]
fn ip_cidr_boundaries() {
    // network and broadcast addresses are in /24; the next subnet is not.
    assert!(allows("permit when ip(\"192.168.0.0\").isInRange(ip(\"192.168.0.0/24\"))\n"));
    assert!(allows("permit when ip(\"192.168.0.255\").isInRange(ip(\"192.168.0.0/24\"))\n"));
    assert!(!allows("permit when ip(\"192.168.1.0\").isInRange(ip(\"192.168.0.0/24\"))\n"));
    // /32 is an exact match; /0 matches everything.
    assert!(allows("permit when ip(\"10.0.0.1\").isInRange(ip(\"10.0.0.1/32\"))\n"));
    assert!(!allows("permit when ip(\"10.0.0.2\").isInRange(ip(\"10.0.0.1/32\"))\n"));
    assert!(allows("permit when ip(\"8.8.8.8\").isInRange(ip(\"0.0.0.0/0\"))\n"));
    assert!(allows("permit when ip(\"127.0.0.1\").isLoopback()\n"));
    assert!(!allows("permit when ip(\"8.8.8.8\").isLoopback()\n"));
}

#[test]
fn ipv6_equality_is_normalized() {
    // "::1" and its fully-expanded form are the SAME address; equality must
    // not be a naive string compare. (This is the bug the weak tests missed.)
    assert!(allows("permit when ip(\"::1\") == ip(\"0:0:0:0:0:0:0:1\")\n"));
    assert!(!allows("permit when ip(\"::1\") == ip(\"::2\")\n"));
}

#[test]
fn ip_address_formats() {
    // --- IPv4 classification ---
    assert!(allows("permit when ip(\"127.0.0.1\").isIpv4()\n"));
    assert!(!allows("permit when ip(\"127.0.0.1\").isIpv6()\n"));
    assert!(allows("permit when ip(\"224.0.0.1\").isMulticast()\n"));
    assert!(!allows("permit when ip(\"8.8.8.8\").isMulticast()\n"));
    // CIDR-qualified loopback still classifies as loopback (prefix is stripped).
    assert!(allows("permit when ip(\"127.0.0.1/8\").isLoopback()\n"));

    // --- IPv6 classification ---
    assert!(allows("permit when ip(\"::1\").isIpv6()\n"));
    assert!(!allows("permit when ip(\"::1\").isIpv4()\n"));
    assert!(allows("permit when ip(\"::1\").isLoopback()\n"));
    assert!(allows("permit when ip(\"ff02::1\").isMulticast()\n"));

    // --- IPv6 equality across textual forms ---
    // compressed vs fully-expanded
    assert!(allows("permit when ip(\"2001:db8::1\") == ip(\"2001:0db8:0000:0000:0000:0000:0000:0001\")\n"));
    // uppercase vs lowercase hex
    assert!(allows("permit when ip(\"2001:DB8::1\") == ip(\"2001:db8::1\")\n"));

    // --- IPv6 CIDR ranges ---
    assert!(allows("permit when ip(\"2001:db8::1\").isInRange(ip(\"2001:db8::/32\"))\n"));
    assert!(!allows("permit when ip(\"2001:db9::1\").isInRange(ip(\"2001:db8::/32\"))\n"));
    assert!(allows("permit when ip(\"::1\").isInRange(ip(\"::1/128\"))\n"));

    // --- malformed strings must not panic; methods are false, not true ---
    assert!(!allows("permit when ip(\"not-an-ip\").isLoopback()\n"));
    assert!(!allows("permit when ip(\"999.999.999.999\").isIpv4()\n"));
    assert!(!allows("permit when ip(\"8.8.8.8\").isInRange(ip(\"garbage\"))\n"));

    // --- cross-version comparisons are not equal ---
    assert!(!allows("permit when ip(\"127.0.0.1\") == ip(\"::1\")\n"));
}

#[test]
fn decimal_precision_and_edges() {
    // 0.75 and 0.7500 are equal; trailing-zero precision must not matter.
    assert!(allows("permit when decimal(\"0.75\") == decimal(\"0.7500\")\n"));
    // boundary: >= is inclusive at equality.
    assert!(allows("permit when decimal(\"0.75\").greaterThanOrEqual(decimal(\"0.75\"))\n"));
    assert!(!allows("permit when decimal(\"0.75\").greaterThan(decimal(\"0.75\"))\n"));
    // negatives order correctly.
    assert!(allows("permit when decimal(\"-1.5\").lessThan(decimal(\"-1.0\"))\n"));
    // more than 4 fractional digits is invalid -> condition errors -> fail-closed deny.
    assert!(!allows("permit when decimal(\"0.123456\").greaterThan(decimal(\"0.0\"))\n"));
}

#[test]
fn decimal_formats_and_overflow() {
    // all four comparison methods
    assert!(allows("permit when decimal(\"1.0\").lessThan(decimal(\"2.0\"))\n"));
    assert!(allows("permit when decimal(\"1.0\").lessThanOrEqual(decimal(\"1.0\"))\n"));
    assert!(allows("permit when decimal(\"2.0\").greaterThan(decimal(\"1.0\"))\n"));
    assert!(allows("permit when decimal(\"2.0\").greaterThanOrEqual(decimal(\"2.0\"))\n"));
    // equality forms: integer vs decimal, negative zero vs zero
    assert!(allows("permit when decimal(\"1.0\") == decimal(\"1\")\n"));
    assert!(allows("permit when decimal(\"-0.0\") == decimal(\"0.0\")\n"));
    // exactly 4 fractional digits is valid; 5 is not (errors -> fail-closed)
    assert!(allows("permit when decimal(\"0.1234\").greaterThan(decimal(\"0.1233\"))\n"));
    assert!(!allows("permit when decimal(\"0.12345\").greaterThan(decimal(\"0.0\"))\n"));
    assert!(allows("permit when decimal(\"5\") == decimal(\"5.0\")\n"));
    // a huge value must be REJECTED (overflow), never panic -> fail-closed deny
    assert!(!allows("permit when decimal(\"99999999999999999\").greaterThan(decimal(\"0.0\"))\n"));
    // malformed -> deny, no panic
    assert!(!allows("permit when decimal(\"abc\").greaterThan(decimal(\"0.0\"))\n"));
    assert!(!allows("permit when decimal(\"1.2.3\").greaterThan(decimal(\"0.0\"))\n"));
}

#[test]
fn hierarchy_diamond_and_self() {
    // a -> {b, c}; b -> d; c -> d  (a diamond). `a in d` must hold via either path.
    let mut s = EntityStore::new();
    s.insert(Entity::new("D::d"));
    s.insert(Entity::new("B::b").parent("D::d"));
    s.insert(Entity::new("C::c").parent("D::d"));
    s.insert(Entity::new("A::a").parent("B::b").parent("C::c"));

    let p = parse_chai("permit when resource in D::\"d\"\n").unwrap();
    let mut ctx = HashMap::new();
    ctx.insert("resource".into(), Value::EntityUid("A::a".into()));
    assert!(matches!(eval_with_store(&p, ctx, &s).unwrap().effect, Effect::Allow));

    // reflexive: a in a.
    let p = parse_chai("permit when resource in A::\"a\"\n").unwrap();
    let mut ctx = HashMap::new();
    ctx.insert("resource".into(), Value::EntityUid("A::a".into()));
    assert!(matches!(eval_with_store(&p, ctx, &s).unwrap().effect, Effect::Allow));

    // not a descendant: d is NOT in a.
    let p = parse_chai("permit when resource in A::\"a\"\n").unwrap();
    let mut ctx = HashMap::new();
    ctx.insert("resource".into(), Value::EntityUid("D::d".into()));
    assert!(matches!(eval_with_store(&p, ctx, &s).unwrap().effect, Effect::Deny));
}

#[test]
fn most_restrictive_lattice_ordering() {
    // When several effects match, the MOST restrictive wins:
    // deny > require_human > defer > redact > downgrade > allow.
    let store = EntityStore::new();
    let eval_pol = |src: &str| {
        let p = parse_chai(src).unwrap();
        format!("{:?}", eval_with_store(&p, HashMap::new(), &store).unwrap().effect)
    };
    // redact beats permit
    assert_eq!(eval_pol("redact when true\npermit when true\n"), "Redact");
    // defer beats redact
    assert_eq!(eval_pol("defer when true\nredact when true\npermit when true\n"), "Defer");
    // deny beats everything
    assert_eq!(eval_pol("deny when true\ndefer when true\nredact when true\npermit when true\n"), "Deny");
}

#[test]
fn first_match_vs_deny_override_diverge() {
    // permit-then-deny: deny-override denies (forbid wins); first-match allows.
    let p = parse_chai("permit when true\nforbid when true\n").unwrap();
    let store = EntityStore::new();
    let dov = eval_with_strategy(&p, HashMap::new(), &store, EvalStrategy::DenyOverride).unwrap();
    let fm = eval_with_strategy(&p, HashMap::new(), &store, EvalStrategy::FirstMatch).unwrap();
    assert!(matches!(dov.effect, Effect::Deny));
    assert!(matches!(fm.effect, Effect::Allow));
}

#[test]
fn condition_error_is_fail_closed_and_recorded() {
    // A type error in a condition must deny AND record the error, never silently
    // pass or silently deny.
    let p = parse_chai("permit when \"abc\" < 5\n").unwrap();
    let d = eval(&p, HashMap::new()).unwrap();
    assert!(matches!(d.effect, Effect::Deny));
    assert_eq!(d.errors.len(), 1);
}

// --- §1.1 effect-tagged errors -------------------------------------------------

#[test]
fn errored_forbid_contributes_deny() {
    // A `forbid` whose guard cannot be evaluated (the detector/tracker is down)
    // must itself deny: we could not check the condition that would have
    // restricted, so we restrict. The error is still recorded for audit.
    let p = parse_chai("forbid when \"abc\" < 5\n").unwrap();
    let d = eval(&p, HashMap::new()).unwrap();
    assert!(matches!(d.effect, Effect::Deny));
    assert_eq!(d.errors.len(), 1);
    // The forbid rule is the reason, not merely an unmatched default.
    assert!(d.reason_codes.iter().any(|c| c == "forbid_overrides"));
}

#[test]
fn errored_forbid_beats_healthy_permit() {
    // The Aria beat: an errored restrictive rule must override an otherwise-clean
    // permit. Under the old neutral-Err semantics this would have allowed.
    let p = parse_chai("permit when true\nforbid when \"abc\" < 5\n").unwrap();
    let d = eval(&p, HashMap::new()).unwrap();
    assert!(matches!(d.effect, Effect::Deny), "errored forbid must override a clean permit");
    assert_eq!(d.errors.len(), 1);
}

#[test]
fn errored_require_human_seals_via_presence() {
    // A `require_human` guard that errors contributes RequireHuman (strict
    // default), so the decision flags seal-on-presence even if it isn't the
    // winning verdict.
    let p = parse_chai("require_human when \"abc\" < 5\n").unwrap();
    let d = eval(&p, HashMap::new()).unwrap();
    assert!(matches!(d.effect, Effect::RequireHuman));
    assert!(d.require_human_present);
    assert_eq!(d.errors.len(), 1);
}

#[test]
fn permit_error_stays_inert() {
    // A permit whose guard errors grants nothing; with no other rule, default deny.
    let p = parse_chai("permit when \"abc\" < 5\n").unwrap();
    let d = eval(&p, HashMap::new()).unwrap();
    assert!(matches!(d.effect, Effect::Deny));
    // Inert: it is the *default* deny, not a forbid_overrides deny.
    assert!(d.reason_codes.iter().any(|c| c == "default_deny"));
}

#[test]
fn lenient_annotation_makes_restrictive_error_inert() {
    // `deny lenient` softens the availability cost: its error no longer forces a
    // deny, so an otherwise-clean permit wins. The error is still recorded.
    let strict = parse_chai("permit when true\ndeny when \"abc\" < 5\n").unwrap();
    assert!(matches!(eval(&strict, HashMap::new()).unwrap().effect, Effect::Deny));

    let lenient = parse_chai("permit when true\ndeny lenient when \"abc\" < 5\n").unwrap();
    let d = eval(&lenient, HashMap::new()).unwrap();
    assert!(matches!(d.effect, Effect::Allow), "lenient deny error must stay inert");
    assert_eq!(d.errors.len(), 1, "the error is still surfaced");
}

#[test]
fn strict_annotation_on_permit_still_grants_nothing() {
    // `permit strict` cannot manufacture an allow from an error: a permit error is
    // inert regardless of annotation (there is no restriction to conservatively
    // apply).
    let p = parse_chai("permit strict when \"abc\" < 5\n").unwrap();
    let d = eval(&p, HashMap::new()).unwrap();
    assert!(matches!(d.effect, Effect::Deny));
}

// --- §3.2 evidence tiers -------------------------------------------------------

fn ctx_with_tier(root: &str, tier: &str, key: &str, val: Value) -> HashMap<String, Value> {
    let mut inner = HashMap::new();
    inner.insert(key.to_string(), val);
    let mut c = HashMap::new();
    c.insert(root.to_string(), Value::Dict(inner));
    let mut tiers = HashMap::new();
    tiers.insert(root.to_string(), Value::String(tier.to_string()));
    c.insert("__tiers".to_string(), Value::Dict(tiers));
    c
}

#[test]
fn attested_gate_blocks_measured_and_derived_evidence() {
    // A permit `requires attested` must never fire from measured/derived evidence.
    let p = parse_chai("permit requires attested when approval.valid == true\n").unwrap();

    // Measured (the default when unmarked): gate fails -> default deny.
    let mut plain = HashMap::new();
    let mut appr = HashMap::new();
    appr.insert("valid".to_string(), Value::Bool(true));
    plain.insert("approval".to_string(), Value::Dict(appr));
    assert!(matches!(eval(&p, plain).unwrap().effect, Effect::Deny),
        "unmarked (measured) evidence must not satisfy a requires-attested permit");

    // Explicitly measured / derived: still blocked.
    let measured = ctx_with_tier("approval", "measured", "valid", Value::Bool(true));
    assert!(matches!(eval(&p, measured).unwrap().effect, Effect::Deny));
    let derived = ctx_with_tier("approval", "derived", "valid", Value::Bool(true));
    assert!(matches!(eval(&p, derived).unwrap().effect, Effect::Deny));
}

#[test]
fn attested_gate_allows_attested_evidence() {
    // With a signature-verified (attested) approval fact, the gated permit fires.
    let p = parse_chai("permit requires attested when approval.valid == true\n").unwrap();
    let attested = ctx_with_tier("approval", "attested", "valid", Value::Bool(true));
    assert!(matches!(eval(&p, attested).unwrap().effect, Effect::Allow),
        "attested evidence must satisfy the gate");
}

#[test]
fn requires_measured_is_the_floor() {
    // `requires measured` is the floor; ordinary detector evidence satisfies it.
    let p = parse_chai("permit requires measured when dlp_facts.ok == true\n").unwrap();
    let c = ctx_with_tier("dlp_facts", "measured", "ok", Value::Bool(true));
    assert!(matches!(eval(&p, c).unwrap().effect, Effect::Allow));
}
