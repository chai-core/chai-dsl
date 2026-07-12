# Formal proofs (`formal/`)

Mechanized Lean 4 proofs of the **deterministic decision core** of the Chai
runtime: the most-restrictive-wins resolution in `src/evaluator.rs::eval_rules`
(lines 416-496) and the security invariants the `three_layer` spec states for it.

## Build

```sh
cd formal
~/.elan/bin/lake build        # or `lake build` if elan is on PATH
```

No Mathlib dependency, Lean 4 core only, so it builds in seconds. Toolchain is
pinned in `lean-toolchain` (Lean 4.31.0). Install Lean via
[`elan`](https://github.com/leanprover/elan) if needed.

## What is proven

Seven files, 77 theorems; all compile with **no `sorry`/`admit`/`native_decide`**;
the only axioms are `propext` and `Quot.sound` (Lean's standard foundations; verify
with `#print axioms`).

### `ChaiProofs/Decision.lean`: the ESP decision algebra

| Theorem | Invariant (from `three_layer` §Security Invariants / `CLAUDE.md`) |
|---|---|
| `decision_perm` | **Deterministic enforcement**: the decision depends only on the *multiset* of rule outcomes, never their order. This is the `DenyOverride` "order-independent, no rule can be shadowed by ordering" guarantee. |
| `decision_nil` | No rule matched ⇒ `Deny` (fail-closed default, evaluator.rs:481-495). |
| `allow_needs_matched_allow` | **Fail-closed emission**: an `ALLOW` decision can only arise from an *explicit* matched allow rule; there is no other path to emission (an error can never manufacture an allow). |
| `no_match_or_error_denies` | A run whose outcomes are all non-matches or inert (permit/lenient) errors decides `Deny`. |
| `restrictive_error_restricts` | **Effect-tagged errors** (§1.1): a strict restrictive `Err(e)` (`e ≠ allow`) contributes its effect; a failed `forbid` denies. |
| `permit_error_inert` | A permit/lenient error contributes nothing, so it never changes the decision. |
| `decision_witness` | Every contributing verdict is carried by some outcome, so a denial is auditable to a concrete rule (generalizes `allow_needs_matched_allow`). |
| `forbid_overrides` | Any matched `Deny`/`Forbid` forces `Deny`, regardless of what else matched. |
| `cedar_reduction` | On permit/forbid-only policies, our lattice computes **exactly Cedar deny-overrides**: `Allow` iff some permit matched and no forbid matched. |
| `score_le_cons`, `deny_stable` | Matched-evidence is monotone; once a forbid matches, nothing added relaxes the `Deny`. |
| `obligations_perm` / `obligations_complete` | **§3.1 obligations**: the accumulated release-transform set is permutation-invariant, and every matched releasing rule at-or-below the verdict contributes (SSN+labels both apply). |
| `attested_gate_sound` | **§3.2 tiers**: a `requires attested` rule never fires from measured/derived evidence. |

### `ChaiProofs/Emission.lean`: the streaming enforcement state machine

| Theorem | Invariant (`src/emission.rs`, `three_layer` §Streaming Enforcement) |
|---|---|
| `sealed_stream` | Halt is absorbing: after the first `RequireHuman`, every action over any remaining stream is `Drop`. |
| `release_effect` | Nothing reaches the sink unless the effect was `Allow`/`Downgrade`/`Redact` and the stream was not halted. |
| `finish_no_release` | End-of-stream flush never emits buffered (unapproved) content. |
| `seal_on_presence_perm` | **Seal-on-presence** (§1.2): the seal predicate is a membership test on the outcomes, hence permutation-invariant; a `require_human` outcome seals even when a deny wins the verdict (`deny_with_seal_drops_and_seals`). |
| `approve_release_effect` | **Approve transition** (§1.3): a buffered chunk is released only under a fresh authorizing re-decision on the approval facts (`approve_seals_on_presence` carries the seal). |
| `stream_transparency` | A stream that decides `Allow` on every live chunk emits every chunk (nothing suppressed): the transparency half of the soundness/transparency pair. |
| `verbatim_release_needs_allow` | The exact (untransformed) bytes reach the sink only under `Allow`; `Redact`/`Downgrade` release a transformed payload. |
| `release_needs_matched_allow` | **End-to-end ESP∘Emission**: on permit/forbid-only policies, content reaches the sink only when an *explicit permit rule matched* the request. |

The Rust runtime is additionally checked against these invariants empirically by
`tests/emission_invariants.rs` (2000 randomized `EmissionEnforcer` runs).

### `ChaiProofs/FirstMatch.lean`: the opt-in firewall / ACL mode

| Theorem | Guarantee |
|---|---|
| `firstmatch_nil` | The empty program denies (fail-closed baseline). |
| `firstmatch_permit_error_skips` / `firstmatch_restrictive_error_decides` | Effect-tagged errors stated for first-match too: a permit/lenient error is skipped; a strict restrictive error decides its effect (`firstmatch_errored_deny_denies`). |
| `firstmatch_all_skip_denies` | If no rule contributes, first-match falls through to the fail-closed default. |

### `ChaiProofs/Budget.lean`: monotone session budgets (§3.3)

| Theorem | Guarantee |
|---|---|
| `charge_bounded` / `charge_monotone` | One release-and-charge stays within cap and never lowers spend. |
| `spend_bounded` | **Cumulative released spend never exceeds the cap** over any request stream (the emission-calculus shape on a cost monoid). Mirrored by `src/session.rs::SessionBudget`. |
| `escrow_compose` | Local sub-budget bounds compose to a global bound (the scale-out / escrow path). |

### `ChaiProofs/Lookahead.lean`: k-lookahead atomicity (§1.4)

| Theorem | Guarantee |
|---|---|
| `window_blocks` / `substring_atomic` | If any chunk in a *k*-window is non-`Allow`, the window is withheld: a substring within any *k* consecutive chunks is **never partially released**. |
| `clean_window_releases` | A fully-clean window releases verbatim (windowed transparency). |

### `ChaiProofs/Taint.lean`: dataflow / taint

| Theorem | Guarantee |
|---|---|
| `session_monotone` | Taint only grows: once tainted, data stays tainted for the rest of the session (no "untainting"). |
| `tainted_sink_denied` | A tainted sink is denied regardless of any permits (via `forbid_overrides`). |
| `clean_sink_inert` | A non-tainted sink is inert: the decision is exactly the rest of the policy. |

Bridged to the real `TaintTracker` by `tests/taint_props.rs` (monotonicity
property) and `tests/exfiltration.rs` (adversarial, with an honest known-miss).
*Labeling* is heuristic/tested; only the monotone state + enforcement are proven.

### `ChaiProofs/PamGuard.lean`: the PAM-style guard combinator (safe variant)

A two-level design: PAM-tagged sub-conditions (`required`/`requisite`/
`sufficient`/`optional`) compose the *guard* of a rule; passing rules' effects
still resolve via the `Decision.lean` lattice. The **safe** reading makes the
guard an order-independent AND/OR formula.

| Theorem | Guarantee |
|---|---|
| `passes_perm` | **Order-independent**: guard verdict is invariant under rule-stack permutation. |
| `not_passes_nil` | Fail-closed: empty / all-`optional` guard never passes. |
| `mandatory_fail_denies` | A failed `required`/`requisite` denies the guard, wherever it sits. |
| `sufficient_present_none_pass_denies` | If a `sufficient` group exists but none pass, the guard is denied. |
| `required_requisite_same_class` | `requisite` ≡ `required` in verdict (they differ only in intent under purity). |

## Scope and honesty

The Lean model is a **faithful abstraction of `eval_rules`**: the
correspondence (Rust effect/outcome/resolution ↔ Lean `Effect`/`Outcome`/
`decision`) is documented line-by-line in the file header and argued **by
inspection** rather than by mechanized extraction. A verified extraction from
Rust to Lean is out of scope.

This covers the **control core** (the decision algebra). It does **not** prove
the parser, the expression evaluator, or the AFC detectors; those are validated
empirically by differential testing against Cedar (`tests/differential.rs`) and
by the z3 analysis (`src/smt.rs`). The split is deliberate: probabilistic /
language-level components are tested; the deterministic enforcement lattice they
feed into is proven.
