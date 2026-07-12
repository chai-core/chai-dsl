/-!
# Monotone session budgets (updated_plan §3.3)

Session state is a join-semilattice a guard may read, e.g.
`forbid when session.spend + args.amount > cap`. The security-relevant quantity is
cumulative *spend*, which only grows. This file mechanizes the budget as a cost
monoid over `Nat` and proves the streaming-calculus property applied to it: the
released spend never exceeds the cap, and a global bound follows from local bounds
when a budget is split across enforcers (the escrow / scale-out story).

Correspondence to the Rust implementation (`crates/chai/src/session.rs::SessionBudget`, by
inspection): `charge` is `SessionBudget::try_charge` (release-and-charge iff within
cap, else deny and leave spend unchanged); `runBudget` folds it over a request
stream, exactly the enforcer loop.
-/

namespace ChaiProofs

/-- One release-and-charge step: release the request of cost `a` and add it to the
    spend only when doing so stays within `cap`; otherwise deny and leave the spend
    unchanged. This is `SessionBudget::try_charge`. -/
def charge (cap s a : Nat) : Nat := if s + a ≤ cap then s + a else s

/-- A charge never pushes the spend over the cap. -/
theorem charge_bounded (cap s a : Nat) (h : s ≤ cap) : charge cap s a ≤ cap := by
  unfold charge
  split
  · assumption
  · exact h

/-- The spend is monotone: a charge never decreases it. -/
theorem charge_monotone (cap s a : Nat) : s ≤ charge cap s a := by
  unfold charge
  split
  · exact Nat.le_add_right s a
  · exact Nat.le_refl s

/-- Fold the charge over a stream of request costs (the enforcer loop). -/
def runBudget (cap : Nat) : Nat → List Nat → Nat
  | s, [] => s
  | s, a :: as => runBudget cap (charge cap s a) as

/-- **`spend_bounded`.** Starting from a spend within the cap, the cumulative
    released spend after any stream of requests never exceeds the cap. This is the
    emission-calculus fail-closed shape applied to a cost monoid: a request whose
    charge would breach the cap is denied, so the bound is preserved by construction. -/
theorem spend_bounded (cap : Nat) (amts : List Nat) (s : Nat) (h : s ≤ cap) :
    runBudget cap s amts ≤ cap := by
  induction amts generalizing s with
  | nil => exact h
  | cons a as ih => exact ih (charge cap s a) (charge_bounded cap s a h)

/-- The spend is monotone across a whole stream (never decreases). -/
theorem run_monotone (cap : Nat) (amts : List Nat) (s : Nat) :
    s ≤ runBudget cap s amts := by
  induction amts generalizing s with
  | nil => exact Nat.le_refl s
  | cons a as ih => exact Nat.le_trans (charge_monotone cap s a) (ih (charge cap s a))

/-! ## Escrow / scale-out: a global bound from local bounds

If a global budget `B` is split into sub-budgets `b₁,…,bₙ` with `∑ bᵢ ≤ B`, then
each enforcer keeping its local spend within its `bᵢ` keeps the total spend within
`B`. Single-enforcer / session-pinned is the default; escrow is the scale-out path. -/

/-- Sub-budgets, each a `(cap, spend)` pair. -/
abbrev Budgets := List (Nat × Nat)

/-- If every pair's spend is within its cap, the total spend is within the total
    cap. (Explicit recursion so the per-element hypothesis threads to sub-lists.) -/
theorem sum_snd_le_sum_fst :
    ∀ (bs : Budgets), (∀ p ∈ bs, p.2 ≤ p.1) →
      (bs.map Prod.snd).sum ≤ (bs.map Prod.fst).sum
  | [], _ => by simp
  | p :: ps, h => by
      simp only [List.map_cons, List.sum_cons]
      exact Nat.add_le_add
        (h p (List.mem_cons.2 (Or.inl rfl)))
        (sum_snd_le_sum_fst ps (fun q hq => h q (List.mem_cons.2 (Or.inr hq))))

/-- **`escrow_compose`.** If every sub-budget keeps its spend within its cap and the
    sub-caps sum to at most the global cap, the total spend is within the global
    cap. Single-enforcer / session-pinned is the default; escrow is the scale-out
    path where local `spend_bounded` proofs compose to a global bound. -/
theorem escrow_compose (bs : Budgets) (globalCap : Nat)
    (hsplit : (bs.map Prod.fst).sum ≤ globalCap)
    (hlocal : ∀ p ∈ bs, p.2 ≤ p.1) :
    (bs.map Prod.snd).sum ≤ globalCap :=
  Nat.le_trans (sum_snd_le_sum_fst bs hlocal) hsplit

end ChaiProofs
