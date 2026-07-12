import ChaiProofs.Decision

/-!
# Mechanized taint / dataflow theorems

Companion to `Decision.lean`. Mechanizes the two properties the dataflow design
in `crates/chai-core/src/taint.rs` (and `TEST_PLAN.md §3`) relies on:

1. **Monotonicity**, a session's taint set only ever GROWS. You cannot "untaint"
   data to sneak it past a sink check. This is the architecture's evidence-
   monotonicity invariant for the taint namespace.
2. **Enforcement soundness**, a *tainted* sink is denied regardless of any
   permits (via `forbid_overrides`), and a *clean* sink is inert (defers to the
   rest of the policy). This connects taint to the already-proven decision core.

Scope/honesty: this proves the monotone state + the enforcement-given-the-fact.
The *labeling* (which tokens are tainted, whether an argument carries taint) is
the heuristic, **tested** part (`crates/chai-core/src/taint.rs`, `tests/exfiltration.rs`), not
claimed here.
-/

namespace ChaiProofs

/-- Abstract tainted tokens. -/
abbrev Token := Nat

/-- Observe one tool result: an untrusted source contributes its tokens to the
    taint set; a trusted source changes nothing (faithful to
    `TaintTracker::observe`). -/
def observe (taint toks : List Token) (untrusted : Bool) : List Token :=
  match untrusted with
  | true => toks ++ taint
  | false => taint

/-- One observation never removes a tainted token (monotone step). -/
theorem observe_monotone {x : Token} {taint toks : List Token} {u : Bool}
    (h : x ∈ taint) : x ∈ observe taint toks u := by
  cases u with
  | true => exact List.mem_append.2 (Or.inr h)
  | false => exact h

/-- Fold `observe` over a whole session of `(tokens, untrusted?)` steps. -/
def session : List Token → List (List Token × Bool) → List Token
  | taint, [] => taint
  | taint, (toks, u) :: rest => session (observe taint toks u) rest

/-- **Monotonicity.** Anything tainted stays tainted for the rest of the session,
    no step can remove it. -/
theorem session_monotone {x : Token} :
    ∀ (steps : List (List Token × Bool)) (taint : List Token),
      x ∈ taint → x ∈ session taint steps
  | [], _, h => h
  | (toks, u) :: rest, taint, h => by
      show x ∈ session (observe taint toks u) rest
      exact session_monotone rest (observe taint toks u) (observe_monotone h)

/-- The taint-forbid rule's outcome on a sink: a `matched deny` when the sink's
    argument carries taint, otherwise inert (`unmatched`). Models the policy
    `forbid when tooltrace.tainted_sink == true`. -/
def taintRule : Bool → Outcome
  | true => Outcome.matched .deny
  | false => Outcome.unmatched

/-- **Tainted sink is denied**, regardless of any permits in `rest` (it is just
    `forbid_overrides` applied to the taint rule). -/
theorem tainted_sink_denied (rest : List Outcome) :
    decision (taintRule true :: rest) = .deny :=
  forbid_overrides (List.mem_cons.2 (Or.inl rfl))

/-- **Clean sink is inert**, a non-tainted sink contributes nothing; the decision
    is exactly what the rest of the policy says. (Renamed from `clean_sink_defers`:
    the old name collided with the `Defer` effect, which this theorem is not about.) -/
theorem clean_sink_inert (rest : List Outcome) :
    decision (taintRule false :: rest) = decision rest := by
  unfold decision
  have h : score (taintRule false :: rest) = score rest := by
    rw [score_cons]
    show Nat.max 0 (score rest) = score rest
    exact nat_max_eq_right (Nat.zero_le _)
  rw [h]

end ChaiProofs
