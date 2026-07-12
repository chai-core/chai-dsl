//! §3.3 monotone session state + endorsement.
//!
//! Two things: (1) a budget guard reads monotone session state and the runtime
//! charges only within-cap releases, so the cumulative released spend stays within
//! the cap (mirrors Budget.lean::spend_bounded); (2) endorsement composes the
//! Approve transition (§1.3) with the attested evidence tier (§3.2): a buffered
//! chunk is released only under a re-decision whose facts include a *valid,
//! attested* approval, and an expired approval fails closed like missing evidence.

use chai_dsl::ast::{Effect, Value};
use chai_dsl::{eval, parse_chai, EmissionEnforcer, EmitAction, EntityStore, SessionBudget};
use std::collections::HashMap;

// --- Budget guard: released spend stays within the cap -------------------------

#[test]
fn budget_guard_bounds_cumulative_spend() {
    // A spend request is allowed only if it keeps the running spend within the cap.
    let policy = "\
forbid when session.spend + args.amount > session.cap
permit when true
";
    let program = parse_chai(policy).unwrap();
    let mut budget = SessionBudget::new(100);

    // A stream of requested charges; the guard decides, the budget charges on allow.
    let requests = [60_i64, 60, 40, 1];
    let mut released = Vec::new();
    for amount in requests {
        let mut ctx = HashMap::new();
        budget.inject(&mut ctx);
        let mut args = HashMap::new();
        args.insert("amount".to_string(), Value::Int(amount));
        ctx.insert("args".to_string(), Value::Dict(args));

        let allowed = matches!(eval(&program, ctx).unwrap().effect, Effect::Allow);
        if allowed {
            // The guard said it is within cap; charge it.
            assert!(budget.try_charge(amount), "guard allowed but charge breached cap");
            released.push(amount);
        }
        // Invariant after every step: spend never exceeds the cap.
        assert!(budget.spend() <= budget.cap());
    }

    // 60 ok, 60 denied (would be 120), 40 ok (=100), 1 denied.
    assert_eq!(released, vec![60, 40]);
    assert_eq!(budget.spend(), 100);
}

// --- Endorsement: attested-gated Approve release -------------------------------

fn approval_facts(valid: bool, attested: bool) -> HashMap<String, Value> {
    let mut appr = HashMap::new();
    appr.insert("valid".to_string(), Value::Bool(valid));
    let mut f = HashMap::new();
    f.insert("approval".to_string(), Value::Dict(appr));
    let mut tiers = HashMap::new();
    tiers.insert(
        "approval".to_string(),
        Value::String(if attested { "attested" } else { "measured" }.to_string()),
    );
    f.insert("__tiers".to_string(), Value::Dict(tiers));
    f
}

// The `defer` is a streaming-plane rule whose `review` fact is absent by design at
// approval time, so it is `lenient` (its error there stays inert; during streaming
// the fact is present and it fires normally).
const ENDORSE_POLICY: &str = "\
permit requires attested when approval.valid == true
defer lenient when review.stage == \"hold\"
";

fn review_hold() -> HashMap<String, Value> {
    let mut r = HashMap::new();
    r.insert("stage".to_string(), Value::String("hold".to_string()));
    let mut f = HashMap::new();
    f.insert("review".to_string(), Value::Dict(r));
    f
}

#[test]
fn approve_releases_only_under_valid_attested_approval() {
    let program = parse_chai(ENDORSE_POLICY).unwrap();
    let store = EntityStore::new();
    let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

    // Stream the draft: held pending review.
    assert_eq!(enf.step("refund $500", review_hold()), EmitAction::Buffer);

    // Approve with a valid, attested approval -> released.
    assert_eq!(
        enf.approve(approval_facts(true, true)),
        EmitAction::Emit("refund $500".into())
    );
}

#[test]
fn approve_rejects_unattested_approval() {
    // A valid-looking but *unattested* (measured) approval fact must not release:
    // the `requires attested` gate blocks the permit, so the re-decision defaults
    // to deny and the buffered content is dropped, fail-closed.
    let program = parse_chai(ENDORSE_POLICY).unwrap();
    let store = EntityStore::new();
    let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

    assert_eq!(enf.step("refund $500", review_hold()), EmitAction::Buffer);
    // Measured approval -> gate fails -> unauthorized -> dropped, never released.
    assert_eq!(enf.approve(approval_facts(true, false)), EmitAction::Drop);
    assert_eq!(enf.finish(), EmitAction::Drop);
}

#[test]
fn expired_approval_fails_closed() {
    // Expiry is an ordinary comparison against a trusted clock fact. An expired
    // (invalid) approval reads as `valid == false`, so the permit does not fire and
    // the release fails closed, exactly like a missing approval.
    let program = parse_chai(ENDORSE_POLICY).unwrap();
    let d = eval(&program, approval_facts(false, true)).unwrap();
    assert!(matches!(d.effect, Effect::Deny), "expired/invalid approval must not grant");
}
