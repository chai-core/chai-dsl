//! §0.1 fault injection: an entity-resolver backend that is unreachable or times
//! out must fail CLOSED. A resolver outage during evaluation of an `in`/entity
//! expression becomes the `Err` outcome for that rule (the same path as a
//! detector failure), never a silent `false`/`None`.
//!
//! These are cases 8-9 of the enforcement-link fault matrix: an unreachable
//! resolver on a restrictive rule (must deny) and on a permit-gated-by-membership
//! rule (must not grant).

use chai_dsl::ast::{Effect, Value};
use chai_dsl::error::ChaiError;
use chai_dsl::{eval_with_store, parse_chai, EntityResolver};
use std::collections::HashMap;

/// A resolver that models an unreachable/timed-out backend: every lookup errors.
struct FailingResolver;

impl EntityResolver for FailingResolver {
    fn attr(&self, _uid: &str, _name: &str) -> Result<Option<Value>, ChaiError> {
        Err(ChaiError::ResolverUnavailable("backend unreachable".into()))
    }
    fn has_attr(&self, _uid: &str, _name: &str) -> Result<bool, ChaiError> {
        Err(ChaiError::ResolverUnavailable("backend unreachable".into()))
    }
    fn is_in(&self, _descendant: &str, _ancestor: &str) -> Result<bool, ChaiError> {
        Err(ChaiError::ResolverUnavailable("backend timed out".into()))
    }
}

fn ctx_with_resource(uid: &str) -> HashMap<String, Value> {
    let mut c = HashMap::new();
    c.insert("resource".into(), Value::EntityUid(uid.into()));
    c.insert("principal".into(), Value::EntityUid("User::alice".into()));
    c
}

#[test]
fn case8_unreachable_resolver_on_forbid_denies() {
    // A `forbid ... in ...` guard whose membership cannot be resolved must itself
    // deny. Under the old infallible resolver this returned `false`, the forbid
    // silently did not fire, and the request could be ALLOWED: a fail-open bug.
    let p = parse_chai(
        "permit when true\nforbid when resource in Blocked::\"list\"\n",
    )
    .unwrap();
    let d = eval_with_store(&p, ctx_with_resource("Doc::secret"), &FailingResolver).unwrap();
    assert!(matches!(d.effect, Effect::Deny), "unreachable resolver must fail closed to deny");
    assert!(!d.errors.is_empty(), "the resolver outage must be surfaced");
    assert!(d.errors.iter().any(|e| e.contains("Resolver unavailable")));
}

#[test]
fn case9_timed_out_resolver_on_permit_grants_nothing() {
    // A permit gated by membership cannot fire when the resolver times out; with
    // no other matching rule the decision is the fail-closed default deny.
    let p = parse_chai("permit when principal in Group::\"admin\"\n").unwrap();
    let d = eval_with_store(&p, ctx_with_resource("Doc::x"), &FailingResolver).unwrap();
    assert!(matches!(d.effect, Effect::Deny), "a resolver outage must never grant access");
    assert!(!d.errors.is_empty(), "the resolver outage must be surfaced");
}

#[test]
fn attr_resolver_failure_is_fail_closed() {
    // An attribute lookup against an unreachable backend errors the rule rather
    // than resolving to a missing/false attribute.
    let p = parse_chai(
        "permit when true\nforbid when resource.sensitivity == \"high\"\n",
    )
    .unwrap();
    let d = eval_with_store(&p, ctx_with_resource("Doc::x"), &FailingResolver).unwrap();
    assert!(matches!(d.effect, Effect::Deny), "attr outage on a forbid must fail closed");
    assert!(!d.errors.is_empty());
}
