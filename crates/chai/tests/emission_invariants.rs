//! Property test: the REAL Emission runtime obeys the invariants proven in Lean
//! (`formal/ChaiProofs/Emission.lean`). The Lean proofs are about a model of
//! `EmissionEnforcer::step`; these 2000 randomized runs check the actual Rust
//! code exhibits the same guarantees, empirically bridging the
//! "correspondence by inspection" gap between the model and the implementation.
//!
//! Invariants checked (Lean theorem ↔ assertion):
//!   * `release_effect`    : Emit ⟹ effect ∈ {Allow, Downgrade}; Redact ⟹ Redact.
//!   * `sealed_stream`     : after the first seal, every action is Drop.
//!   * `seal_on_presence`  : a step whose decision carries a require_human outcome
//!                           seals the stream, even when a deny wins the verdict.
//!   * `finish_no_release` : finish() never Emits/Redacts.

use chai_dsl::ast::{Effect, Value};
use chai_dsl::{parse_chai, EmissionEnforcer, EmitAction, EntityStore};
use proptest::prelude::*;
use std::collections::HashMap;

const KW: &[&str] = &["permit", "deny", "forbid", "redact", "defer", "downgrade", "require_human"];

fn facts(pii: f64) -> HashMap<String, Value> {
    let mut dlp = HashMap::new();
    dlp.insert("pii".to_string(), Value::Float(pii));
    let mut f = HashMap::new();
    f.insert("dlp_facts".to_string(), Value::Dict(dlp));
    f
}

fn policy_text(rules: &[(usize, u8)]) -> String {
    rules
        .iter()
        .map(|&(k, t)| format!("{} when dlp_facts.pii > {:.1}\n", KW[k % KW.len()], t as f64 / 10.0))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn emission_obeys_lean_proven_invariants(
        rules in proptest::collection::vec((0usize..KW.len(), 0u8..=10), 1..5),
        piis in proptest::collection::vec(0u8..=10, 1..8),
    ) {
        let program = parse_chai(&policy_text(&rules)).unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

        let actions: Vec<EmitAction> =
            piis.iter().map(|&p| enf.step("chunk", facts(p as f64 / 10.0))).collect();
        // Each history entry is (winning effect, require_human present?).
        let hist: Vec<(Effect, bool)> =
            enf.history().iter().map(|d| (d.effect.clone(), d.require_human_present)).collect();

        // A halted step returns Drop early WITHOUT recording history (emission.rs:70),
        // so we consume `hist` only for steps that actually evaluated.
        let mut hidx = 0usize;
        let mut halted = false;
        for a in &actions {
            if halted {
                // sealed_stream: once halted, every later action is Drop.
                prop_assert_eq!(a, &EmitAction::Drop, "action after halt was not Drop");
                continue;
            }
            let (eff, rh_present) = &hist[hidx];
            hidx += 1;
            // release_effect: an action releasing text matches an authorizing effect.
            match a {
                EmitAction::Emit(_) =>
                    prop_assert!(matches!(eff, Effect::Allow | Effect::Downgrade), "Emit but effect {:?}", eff),
                EmitAction::Redact(_) =>
                    prop_assert!(matches!(eff, Effect::Redact), "Redact but effect {:?}", eff),
                EmitAction::Buffer =>
                    prop_assert!(matches!(eff, Effect::Defer)),
                EmitAction::RequireHuman =>
                    prop_assert!(matches!(eff, Effect::RequireHuman)),
                EmitAction::Drop => {}
            }
            // seal_on_presence: any require_human outcome seals the stream, whether
            // it won the verdict (RequireHuman action) or was overridden by a deny.
            if *rh_present {
                halted = true;
            }
        }
        prop_assert_eq!(hidx, hist.len(), "history entries left unconsumed");
        prop_assert_eq!(halted, enf.is_halted());

        // finish_no_release: end-of-stream flush never emits buffered content.
        prop_assert!(matches!(enf.finish(), EmitAction::Drop), "finish released content");
    }
}
