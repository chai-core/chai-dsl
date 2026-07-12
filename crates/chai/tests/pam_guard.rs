//! Functional suite for the PAM guard combinator (`src/pam.rs`).
//!
//! Two layers above the unit tests in `src/pam.rs`:
//!  1. EXHAUSTIVE truth-table differential vs an INDEPENDENT oracle: every guard
//!     up to length 4 over {required,requisite,sufficient,optional}×{pass,fail}
//!     (4681 guards) is a *complete* check of the verdict logic.
//!  2. Proof-bridging property tests: the real `passes` obeys each theorem in
//!     `formal/ChaiProofs/PamGuard.lean` over thousands of random guards.

use chai_dsl::pam::{passes, Flag};
use proptest::prelude::*;

const FLAGS: [Flag; 4] = [Flag::Required, Flag::Requisite, Flag::Sufficient, Flag::Optional];

/// Independent reference for the verdict, written as a single-pass accumulator,
/// deliberately structured differently from `passes`'s any/all form, so it's a
/// genuine second implementation.
fn ref_passes(stack: &[(Flag, bool)]) -> bool {
    let (mut has_gate, mut mandatory_all, mut has_suff, mut suff_pass) = (false, true, false, false);
    for (f, ok) in stack {
        match f {
            Flag::Required | Flag::Requisite => {
                has_gate = true;
                if !ok {
                    mandatory_all = false;
                }
            }
            Flag::Sufficient => {
                has_gate = true;
                has_suff = true;
                if *ok {
                    suff_pass = true;
                }
            }
            Flag::Optional => {}
        }
    }
    has_gate && mandatory_all && (!has_suff || suff_pass)
}

/// Enumerate every guard of exactly `len` over the 8 (flag, bool) entries.
fn all_guards(len: u32, mut visit: impl FnMut(&[(Flag, bool)])) {
    let entries: Vec<(Flag, bool)> =
        FLAGS.iter().flat_map(|&f| [(f, false), (f, true)]).collect();
    let n = entries.len() as u64; // 8
    let total = n.pow(len);
    let mut buf = Vec::with_capacity(len as usize);
    for mut code in 0..total {
        buf.clear();
        for _ in 0..len {
            buf.push(entries[(code % n) as usize]);
            code /= n;
        }
        visit(&buf);
    }
}

#[test]
fn exhaustive_vs_independent_oracle() {
    let mut count = 0u64;
    for len in 0..=4 {
        all_guards(len, |g| {
            assert_eq!(passes(g), ref_passes(g), "verdict mismatch on {g:?}");
            count += 1;
        });
    }
    assert_eq!(count, 1 + 8 + 64 + 512 + 4096); // 4681 guards, all checked
}

// --- proptest strategies ---

fn flag_strat() -> impl Strategy<Value = Flag> {
    prop_oneof![Just(Flag::Required), Just(Flag::Requisite), Just(Flag::Sufficient), Just(Flag::Optional)]
}
fn guard_strat() -> impl Strategy<Value = Vec<(Flag, bool)>> {
    proptest::collection::vec((flag_strat(), any::<bool>()), 0..8)
}

/// Deterministic Fisher-Yates so we can assert over a genuine arbitrary perm.
fn shuffle(mut v: Vec<(Flag, bool)>, mut seed: u64) -> Vec<(Flag, bool)> {
    for i in (1..v.len()).rev() {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = (seed >> 33) as usize % (i + 1);
        v.swap(i, j);
    }
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// passes_perm: order-independence (the safe variant's headline; would FAIL
    /// for faithful PAM, so this also pins the design choice).
    #[test]
    fn prop_order_independent(g in guard_strat(), seed in any::<u64>()) {
        prop_assert_eq!(passes(&g), passes(&shuffle(g.clone(), seed)));
    }

    /// not_passes_nil + all-optional: fail-closed.
    #[test]
    fn prop_no_gate_denies(g in proptest::collection::vec((Just(Flag::Optional), any::<bool>()), 0..6)) {
        prop_assert!(!passes(&g));
    }

    /// mandatory_fail_denies: any failed required/requisite ⇒ deny.
    #[test]
    fn prop_mandatory_fail_denies(g in guard_strat()) {
        if g.iter().any(|(f, ok)| f.is_mandatory() && !ok) {
            prop_assert!(!passes(&g));
        }
    }

    /// required_requisite_same_class: swapping requisite↔required never changes
    /// the verdict.
    #[test]
    fn prop_requisite_equiv_required(g in guard_strat()) {
        let relabel = |from: Flag, to: Flag| -> Vec<(Flag, bool)> {
            g.iter().map(|&(f, ok)| (if f == from { to } else { f }, ok)).collect()
        };
        prop_assert_eq!(passes(&g), passes(&relabel(Flag::Requisite, Flag::Required)));
        prop_assert_eq!(passes(&g), passes(&relabel(Flag::Required, Flag::Requisite)));
    }

    /// Cross-check the whole verdict against the independent oracle on random
    /// guards too (covers lengths beyond the exhaustive bound).
    #[test]
    fn prop_matches_oracle(g in guard_strat()) {
        prop_assert_eq!(passes(&g), ref_passes(&g));
    }
}
