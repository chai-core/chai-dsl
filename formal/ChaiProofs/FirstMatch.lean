import ChaiProofs.Decision

/-!
# Mechanized first-match (firewall / ACL) resolution

`Decision.lean` mechanizes the default `DenyOverride` strategy. This companion
mechanizes the alternate `FirstMatch` strategy (`eval_rules_first_match` in
`crates/chai-core/src/evaluator.rs`): rules in order, the first *contributing* rule decides, empty
or all-skipped denies. This makes contribution bullet 5 true, the first-match
mode is now inside the proven core, not merely implemented and tested.

## Correspondence to the Rust implementation (by inspection)

* `Outcome`            ↔ the per-rule branch (reused from `Decision.lean`).
* `Outcome.decided`    ↔ whether a rule contributes and, if so, its effect. Under
                         effect-tagged errors (§1.1) a *strict restrictive* error
                         contributes its effect (`errored e`, `e ≠ allow`), a
                         permit/lenient error is skipped (`errored .allow`),
                         mirroring `Rule::error_contributes`.
* `firstMatch`         ↔ the ordered loop in `eval_rules_first_match`
                         (evaluator.rs): the first contributing rule returns, else
                         the fail-closed default `Deny`.
-/

namespace ChaiProofs

/-- A first-match rule's contribution: `some e` if it decides (a match, or a
    strict restrictive error), else `none` (a non-match or an inert permit/lenient
    error, which is skipped). `Forbid` and `Deny` already share `.deny`. -/
def Outcome.decided : Outcome → Option Effect
  | .matched e => some e
  | .errored e => if e = .allow then none else some e
  | .unmatched => none

/-- First-match resolution: the first contributing rule decides; an empty or
    all-skipped program is the fail-closed default `Deny`. -/
def firstMatch : List Outcome → Effect
  | [] => .deny
  | o :: os => match o.decided with
      | some e => e
      | none => firstMatch os

/-- **`firstmatch_nil`.** The empty program denies (fail-closed baseline). -/
theorem firstmatch_nil : firstMatch [] = .deny := rfl

/-- A non-matching (or inert) head is skipped. -/
theorem firstmatch_skip_unmatched (os : List Outcome) :
    firstMatch (Outcome.unmatched :: os) = firstMatch os := by
  simp [firstMatch, Outcome.decided]

/-- **`firstmatch_err_skip`.** A permit/lenient error at the head is skipped, just
    as it is inert under deny-overrides (§1.1). -/
theorem firstmatch_permit_error_skips (os : List Outcome) :
    firstMatch (Outcome.errored .allow :: os) = firstMatch os := by
  simp [firstMatch, Outcome.decided]

/-- **`firstmatch_err_decides`.** A strict restrictive error at the head decides
    its own effect (fail-closed): the same effect-tagged treatment as
    deny-overrides, now stated for first-match too. -/
theorem firstmatch_restrictive_error_decides {e : Effect} (h : e ≠ .allow)
    (os : List Outcome) : firstMatch (Outcome.errored e :: os) = e := by
  simp [firstMatch, Outcome.decided, h]

/-- Corollary: a failed forbid at the head denies under first-match as well. -/
theorem firstmatch_errored_deny_denies (os : List Outcome) :
    firstMatch (Outcome.errored .deny :: os) = .deny :=
  firstmatch_restrictive_error_decides (by decide) os

/-- **All-skipped ⇒ Deny.** If no rule contributes, first-match falls through to
    the fail-closed default. -/
theorem firstmatch_all_skip_denies :
    ∀ l : List Outcome, (∀ o ∈ l, o.decided = none) → firstMatch l = .deny
  | [], _ => rfl
  | o :: os, h => by
      have ho : o.decided = none := h o (List.mem_cons.2 (Or.inl rfl))
      simp only [firstMatch, ho]
      exact firstmatch_all_skip_denies os (fun x hx => h x (List.mem_cons.2 (Or.inr hx)))

end ChaiProofs
