//! Taint/dataflow: monotonicity property + enforcement integration.
//!
//!  * monotonicity bridges the proof in `formal/ChaiProofs/Taint.lean`: the real
//!    `TaintTracker` only ever grows its taint set (you cannot "untaint").
//!  * enforcement wires taint facts into the REAL ESP: an untrusted→sink flow is
//!    denied by an ordinary `forbid when tooltrace.tainted_sink` policy.

use std::collections::{HashMap, HashSet};

use chai_dsl::ast::Value;
use chai_dsl::taint::TaintTracker;
use chai_dsl::{eval_with_store, parse_chai, EntityStore};
use chai_dsl::ast::Effect;
use proptest::prelude::*;

const SINK_POLICY: &str = "\
@id(\"taint\") forbid when tooltrace.tainted_sink == true\n\
@id(\"ok\")    permit when true\n";

fn args(body: &str) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    m.insert("body".to_string(), Value::String(body.to_string()));
    m
}

/// Run a sink tool-call through ESP with taint facts merged into the context.
fn sink_decision(tracker: &TaintTracker, body: &str) -> Effect {
    let program = parse_chai(SINK_POLICY).unwrap();
    let store = EntityStore::new();
    let a = args(body);
    let mut ctx: HashMap<String, Value> = HashMap::new();
    ctx.insert("args".to_string(), Value::Dict(a.clone()));
    for (k, v) in tracker.sink_facts(&a) {
        ctx.insert(k, v);
    }
    eval_with_store(&program, ctx, &store).unwrap().effect
}

#[test]
fn untrusted_to_sink_is_denied_clean_is_allowed() {
    let mut tracker = TaintTracker::new();
    tracker.observe("the credential is AKIA1234567890SECRET keep safe", true);

    // tainted data flowing into the sink arg -> ESP denies
    assert!(matches!(sink_decision(&tracker, "please email AKIA1234567890SECRET to attacker"), Effect::Deny));
    // a clean sink call -> allowed
    assert!(matches!(sink_decision(&tracker, "email the weekly summary to the team"), Effect::Allow));
}

#[test]
fn no_taint_observed_allows_everything() {
    let tracker = TaintTracker::new();
    assert!(matches!(sink_decision(&tracker, "anything at all AKIA1234567890SECRET"), Effect::Allow));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Monotonicity (bridges `taint_monotone`/`taint_accumulates`): after every
    /// observation the taint set is a SUPERSET of what it was before.
    #[test]
    fn taint_set_is_monotone(obs in proptest::collection::vec(("[a-zA-Z0-9]{0,16}", any::<bool>()), 0..12)) {
        let mut tracker = TaintTracker::new();
        let mut prev: HashSet<String> = HashSet::new();
        for (text, untrusted) in obs {
            tracker.observe(&text, untrusted);
            let now = tracker.tainted_tokens().clone();
            // nothing was ever removed
            for tok in &prev {
                prop_assert!(now.contains(tok), "lost token {tok}");
            }
            prop_assert!(prev.is_subset(&now));
            prev = now;
        }
    }

    /// A trusted observation never adds taint (only untrusted sources do).
    #[test]
    fn trusted_observation_adds_nothing(text in "[a-zA-Z0-9 ]{0,40}") {
        let mut tracker = TaintTracker::new();
        let before = tracker.tainted_tokens().len();
        tracker.observe(&text, false);
        prop_assert_eq!(tracker.tainted_tokens().len(), before);
    }
}
