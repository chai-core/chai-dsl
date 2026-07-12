//! DRT starter (D3): differentially test the production decision resolution against
//! a faithful transcription of the proven Lean fold in
//! `formal/ChaiProofs/Core.lean` (`decision` / `Decision.lean`).
//!
//! This is the first, decision-layer step of the Lean-to-Rust bridge. It generates
//! random multi-rule policies, evaluates them through the real engine (`parse_chai`
//! + `eval_with_store`), and checks the verdict against the spec oracle below.
//!
//! Scope of v1 (deliberately minimal): matched/unmatched rules over the full effect
//! chain. Error outcomes (guards that fault) and the emission machine are out of
//! scope here; they are the next DRT stages.

use chai_dsl::ast::Effect;
use chai_dsl::{eval_with_store, parse_chai, EntityStore};
use std::collections::HashMap;

/// (keyword, restrictiveness rank). Ranks mirror `Effect::rank` in `src/ast.rs`
/// (Allow=0 .. Deny/Forbid=5). `forbid` and `deny` share rank 5 and both resolve to
/// `Deny`, exactly as the Lean model collapses `Forbid` into `deny`.
const EFFECTS: &[(&str, u8)] = &[
    ("permit", 0),
    ("downgrade", 1),
    ("redact", 2),
    ("defer", 3),
    ("require_human", 4),
    ("deny", 5),
    ("forbid", 5),
];

fn effect_of_rank(r: u8) -> Effect {
    match r {
        0 => Effect::Allow,
        1 => Effect::Downgrade,
        2 => Effect::Redact,
        3 => Effect::Defer,
        4 => Effect::RequireHuman,
        _ => Effect::Deny,
    }
}

/// The spec oracle: the Lean `decision` fold. The verdict is `effectOfRank(max)`
/// over the matched rules; with nothing matched, the fail-closed default is `Deny`.
fn oracle(matched_ranks: &[u8]) -> Effect {
    match matched_ranks.iter().copied().max() {
        Some(r) => effect_of_rank(r),
        None => Effect::Deny,
    }
}

/// Tiny deterministic LCG so the run is reproducible without a `rand` dependency.
struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

#[test]
fn drt_decision_matches_lean_fold() {
    let mut rng = Lcg(0x0123_4567_89ab_cdef);
    let store = EntityStore::new();
    let cases = 5000;

    for _ in 0..cases {
        let n_rules = 1 + rng.below(6) as usize; // 1..=6 rules
        let mut src = String::new();
        let mut matched_ranks: Vec<u8> = Vec::new();

        for i in 0..n_rules {
            let (kw, rank) = EFFECTS[rng.below(EFFECTS.len() as u64) as usize];
            let matched = rng.below(2) == 1;
            let cond = if matched { "true" } else { "false" };
            src.push_str(&format!("@id(\"r{i}\") {kw} when {cond}\n"));
            if matched {
                matched_ranks.push(rank);
            }
        }

        let program = parse_chai(&src).expect("policy should parse");
        let decision = eval_with_store(&program, HashMap::new(), &store).expect("eval should succeed");
        let expected = oracle(&matched_ranks);

        assert_eq!(
            decision.effect, expected,
            "engine disagreed with the Lean fold\npolicy:\n{src}matched_ranks={matched_ranks:?}"
        );
    }
}
