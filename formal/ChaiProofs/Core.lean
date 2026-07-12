import ChaiProofs.Decision

/-!
# The parametric decision core: chai-core as one engine, chai and Cedar as instances

`Decision.lean` mechanizes the decision algebra over the *concrete* six-effect
lattice. This file (D1 of `popl_plan.md`) shows that lattice was never essential:
the whole determinism / fail-closed / witness spine depends only on a **finite
effect chain**. We factor it out as `EffectChain`, port the spine generically,
then recover two instances:

* `chaiChain`  (n = 6) — the concrete `ChaiProofs.Effect`. Its `EffectChain` laws
  are *literally the lemmas already proved in `Decision.lean`* (reuse, not copy).
* `cedarChain` (n = 2) — permit/forbid. `cedar_reduction` is then a corollary of
  the generic lemmas at n = 2, not a separate proof.

This is the mechanized form of the C1 claim: chai-core is the method; chai and
Cedar are instances. The concrete six-effect development in `Decision.lean` is
kept as-is; nothing here disturbs it.
-/

namespace ChaiProofs.Core

/-- A finite, totally ordered chain of effects: the only structure the decision
    core actually uses. `rank` labels effects into `{1,…,n}`; `effectOfRank` is its
    inverse on that range and sends `0` (nothing matched) to the fail-closed `top`. -/
structure EffectChain where
  E : Type
  decEq : DecidableEq E
  n : Nat
  rank : E → Nat
  effectOfRank : Nat → E
  top : E
  two_le_n : 2 ≤ n
  rank_pos : ∀ e, 1 ≤ rank e
  rank_le_n : ∀ e, rank e ≤ n
  effectOfRank_rank : ∀ e, effectOfRank (rank e) = e
  rank_effectOfRank : ∀ m, 1 ≤ m → m ≤ n → rank (effectOfRank m) = m
  effectOfRank_zero : effectOfRank 0 = top
  rank_top : rank top = n

attribute [instance] EffectChain.decEq

namespace EffectChain

variable (C : EffectChain)

/-- The least effect (`allow`/`permit`): the release identity. Derived, not a field. -/
def bot : C.E := C.effectOfRank 1

theorem bot_eq : C.bot = C.effectOfRank 1 := rfl

/-- `rank` is injective (it has a left inverse `effectOfRank`). -/
theorem rank_injective {a b : C.E} (h : C.rank a = C.rank b) : a = b := by
  have ha := C.effectOfRank_rank a
  have hb := C.effectOfRank_rank b
  rw [← ha, ← hb, h]

theorem rank_bot : C.rank C.bot = 1 := by
  rw [C.bot_eq]
  exact C.rank_effectOfRank 1 (Nat.le_refl 1) (by have := C.two_le_n; omega)

theorem bot_ne_top : C.bot ≠ C.top := by
  intro h
  have hr := congrArg C.rank h
  rw [C.rank_bot, C.rank_top] at hr
  have := C.two_le_n; omega

end EffectChain

/-- One rule's outcome, over an arbitrary chain (mirrors `Decision.Outcome`). -/
inductive Outcome (C : EffectChain) where
  | matched : C.E → Outcome C
  | unmatched : Outcome C
  | errored : C.E → Outcome C

/-- Contribution to the score. A restrictive error (`errored e`, `e ≠ bot`)
    contributes its rank; a permit/lenient error (`errored bot`) contributes `0`.
    An error can never manufacture a `bot`. -/
def Outcome.contrib {C : EffectChain} : Outcome C → Nat
  | .matched e => C.rank e
  | .unmatched => 0
  | .errored e => if e = C.bot then 0 else C.rank e

theorem Outcome.contrib_le_n {C : EffectChain} (o : Outcome C) : o.contrib ≤ C.n := by
  cases o with
  | matched e => exact C.rank_le_n e
  | unmatched => exact Nat.zero_le _
  | errored e =>
      simp only [Outcome.contrib]
      by_cases he : e = C.bot
      · rw [if_pos he]; exact Nat.zero_le _
      · rw [if_neg he]; exact C.rank_le_n e

/-! ## Nat.max helpers (omega treats Nat.max as opaque) -/

private theorem nmax_eq_left {a b : Nat} (h : b ≤ a) : Nat.max a b = a :=
  Nat.le_antisymm (Nat.max_le.2 ⟨Nat.le_refl a, h⟩) (Nat.le_max_left a b)
private theorem nmax_eq_right {a b : Nat} (h : a ≤ b) : Nat.max a b = b :=
  Nat.le_antisymm (Nat.max_le.2 ⟨h, Nat.le_refl b⟩) (Nat.le_max_right a b)
private theorem nmax_left_comm (a b c : Nat) :
    Nat.max a (Nat.max b c) = Nat.max b (Nat.max a c) := by
  apply Nat.le_antisymm
  · apply Nat.max_le.2
    refine ⟨Nat.le_trans (Nat.le_max_left a c) (Nat.le_max_right b _), ?_⟩
    exact Nat.max_le.2 ⟨Nat.le_max_left b _, Nat.le_trans (Nat.le_max_right a c) (Nat.le_max_right b _)⟩
  · apply Nat.max_le.2
    refine ⟨Nat.le_trans (Nat.le_max_left b c) (Nat.le_max_right a _), ?_⟩
    exact Nat.max_le.2 ⟨Nat.le_max_left a _, Nat.le_trans (Nat.le_max_right b c) (Nat.le_max_right a _)⟩

/-! ## Score and decision -/

def score {C : EffectChain} (l : List (Outcome C)) : Nat :=
  l.foldr (fun o acc => Nat.max o.contrib acc) 0

@[simp] theorem score_nil {C : EffectChain} : score ([] : List (Outcome C)) = 0 := rfl
@[simp] theorem score_cons {C : EffectChain} (o : Outcome C) (l : List (Outcome C)) :
    score (o :: l) = Nat.max o.contrib (score l) := rfl

def decision {C : EffectChain} (l : List (Outcome C)) : C.E := C.effectOfRank (score l)

/-- Fail-closed baseline: an empty run denies (decides `top`). -/
theorem decision_nil {C : EffectChain} : decision ([] : List (Outcome C)) = C.top := by
  show C.effectOfRank (score ([] : List (Outcome C))) = C.top
  simp only [score_nil]; exact C.effectOfRank_zero

/-! ## Determinism / order-independence -/

theorem score_perm {C : EffectChain} {l₁ l₂ : List (Outcome C)} (h : l₁.Perm l₂) :
    score l₁ = score l₂ := by
  induction h with
  | nil => rfl
  | cons x _ ih => simp [score_cons, ih]
  | swap x y l => simp only [score_cons]; exact nmax_left_comm y.contrib x.contrib (score l)
  | trans _ _ ih₁ ih₂ => exact ih₁.trans ih₂

theorem decision_perm {C : EffectChain} {l₁ l₂ : List (Outcome C)} (h : l₁.Perm l₂) :
    decision l₁ = decision l₂ := by unfold decision; rw [score_perm h]

/-! ## Score is an achieved upper bound -/

theorem contrib_le_score {C : EffectChain} {o : Outcome C} {l : List (Outcome C)} (h : o ∈ l) :
    o.contrib ≤ score l := by
  induction l with
  | nil => cases h
  | cons a t ih =>
      rcases List.mem_cons.1 h with rfl | h'
      · simp only [score_cons]; exact Nat.le_max_left _ _
      · simp only [score_cons]; exact Nat.le_trans (ih h') (Nat.le_max_right _ _)

theorem score_le {C : EffectChain} {l : List (Outcome C)} {b : Nat}
    (h : ∀ o ∈ l, o.contrib ≤ b) : score l ≤ b := by
  induction l with
  | nil => simp only [score_nil]; exact Nat.zero_le b
  | cons a t ih =>
      have ha : a.contrib ≤ b := h a (List.mem_cons.2 (Or.inl rfl))
      have ht : score t ≤ b := ih (fun o ho => h o (List.mem_cons.2 (Or.inr ho)))
      simp only [score_cons]; exact Nat.max_le.2 ⟨ha, ht⟩

theorem exists_contrib_eq_score {C : EffectChain} :
    ∀ (l : List (Outcome C)), 0 < score l → ∃ o ∈ l, o.contrib = score l
  | [], h => by simp [score_nil] at h
  | a :: t, h => by
      rcases Nat.le_total (score t) a.contrib with hle | hle
      · exact ⟨a, List.mem_cons.2 (Or.inl rfl), by
          simp only [score_cons]; exact (nmax_eq_left hle).symm⟩
      · have htpos : 0 < score t := by
          simp only [score_cons] at h; rw [nmax_eq_right hle] at h; exact h
        obtain ⟨o, hot, hoc⟩ := exists_contrib_eq_score t htpos
        exact ⟨o, List.mem_cons.2 (Or.inr hot), by
          simp only [score_cons]; rw [nmax_eq_right hle]; exact hoc⟩

/-- **`decision_witness`.** Any non-trivial decision has a witnessing rule whose
    contribution equals the verdict's rank. -/
theorem decision_witness {C : EffectChain} {l : List (Outcome C)} (h : 0 < score l) :
    ∃ o ∈ l, o.contrib = C.rank (decision l) := by
  obtain ⟨o, ho, hoc⟩ := exists_contrib_eq_score l h
  refine ⟨o, ho, ?_⟩
  have hn : score l ≤ C.n := score_le (fun o _ => o.contrib_le_n)
  rw [hoc]; unfold decision; exact (C.rank_effectOfRank (score l) h hn).symm

/-! ## Top-overrides and fail-closed emission (generic forbid-overrides / allow-needs-allow) -/

/-- **`top_overrides`.** Any matched `top` forces the verdict to `top`, regardless
    of order or what else matched. At `cedarChain` this is Cedar's forbid-overrides. -/
theorem top_overrides {C : EffectChain} {l : List (Outcome C)}
    (h : Outcome.matched C.top ∈ l) : decision l = C.top := by
  have hcontrib : (Outcome.matched C.top).contrib = C.n := by
    simp only [Outcome.contrib]; exact C.rank_top
  have hge : C.n ≤ score l := by
    have hh := contrib_le_score h; omega
  have hle : score l ≤ C.n := score_le (fun o _ => o.contrib_le_n)
  have hs : score l = C.n := Nat.le_antisymm hle hge
  unfold decision; rw [hs]
  apply C.rank_injective
  rw [C.rank_effectOfRank C.n (by have := C.two_le_n; omega) (Nat.le_refl _), C.rank_top]

/-- The only outcome with contribution `1` is a matched `bot`: an error or a
    non-match can never produce a `bot`. -/
theorem contrib_eq_one {C : EffectChain} {o : Outcome C} (h : o.contrib = 1) :
    o = Outcome.matched C.bot := by
  cases o with
  | matched e =>
      simp only [Outcome.contrib] at h
      have : e = C.bot := C.rank_injective (by rw [h, C.rank_bot])
      rw [this]
  | unmatched => simp only [Outcome.contrib] at h; exact absurd h (by decide)
  | errored e =>
      simp only [Outcome.contrib] at h
      by_cases he : e = C.bot
      · rw [if_pos he] at h; exact absurd h (by decide)
      · rw [if_neg he] at h
        exact absurd (C.rank_injective (by rw [h, C.rank_bot])) he

/-- The verdict is `bot` exactly when the score is `1`. (`bot ≠ top` rules out the
    score-`0` default.) -/
theorem decision_eq_bot_iff_score_one {C : EffectChain} {l : List (Outcome C)} :
    decision l = C.bot ↔ score l = 1 := by
  constructor
  · intro h
    have hle : score l ≤ C.n := score_le (fun o _ => o.contrib_le_n)
    unfold decision at h
    rcases Nat.eq_zero_or_pos (score l) with h0 | hpos
    · rw [h0, C.effectOfRank_zero] at h
      exact absurd h.symm C.bot_ne_top
    · have hr := congrArg C.rank h
      rw [C.rank_effectOfRank (score l) hpos hle, C.rank_bot] at hr
      exact hr
  · intro h
    unfold decision; rw [h]; exact C.bot_eq.symm

/-- **`bot_needs_matched_bot`.** A `bot` verdict can only arise from an explicit
    matched `bot` rule. At `cedarChain` this is Cedar's "allow needs a permit". -/
theorem bot_needs_matched_bot {C : EffectChain} {l : List (Outcome C)}
    (h : decision l = C.bot) : Outcome.matched C.bot ∈ l := by
  have hs : score l = 1 := decision_eq_bot_iff_score_one.1 h
  obtain ⟨o, ho, hoc⟩ := exists_contrib_eq_score l (by omega)
  rw [hs] at hoc
  rw [← contrib_eq_one hoc]; exact ho

/-! ## The rest of the algebra, generically (completing the W2 fold) -/

/-- A restrictive error contributes exactly its rank. -/
theorem errored_contrib {C : EffectChain} {e : C.E} (h : e ≠ C.bot) :
    (Outcome.errored e).contrib = C.rank e := by
  simp [Outcome.contrib, h]

/-- **`permit_error_inert`.** A permit/lenient error (`errored bot`) leaves the
    score, hence the verdict, unchanged. -/
theorem permit_error_inert {C : EffectChain} (l : List (Outcome C)) :
    score (Outcome.errored C.bot :: l) = score l := by
  have h0 : (Outcome.errored C.bot).contrib = 0 := by simp [Outcome.contrib]
  simp only [score_cons, h0]
  exact nmax_eq_right (Nat.zero_le _)

/-- **`restrictive_error_restricts`.** A restrictive error can only tighten. -/
theorem restrictive_error_restricts {C : EffectChain} {l : List (Outcome C)} {e : C.E}
    (hmem : Outcome.errored e ∈ l) (hne : e ≠ C.bot) : C.rank e ≤ score l := by
  have := contrib_le_score hmem
  rwa [errored_contrib hne] at this

/-- **`no_contrib_denies`.** Nothing contributes ⇒ the fail-closed top. -/
theorem no_contrib_denies {C : EffectChain} {l : List (Outcome C)}
    (h : ∀ o ∈ l, o.contrib = 0) : decision l = C.top := by
  have hz : score l ≤ 0 := score_le (fun o ho => Nat.le_of_eq (h o ho))
  have hs : score l = 0 := Nat.le_zero.1 hz
  unfold decision; rw [hs]; exact C.effectOfRank_zero

/-- **`no_match_or_error_denies`.** Non-matches and inert errors only ⇒ top. -/
theorem no_match_or_error_denies {C : EffectChain} {l : List (Outcome C)}
    (h : ∀ o ∈ l, o = Outcome.unmatched ∨ o = Outcome.errored C.bot) :
    decision l = C.top :=
  no_contrib_denies (by
    intro o ho; rcases h o ho with rfl | rfl <;> simp [Outcome.contrib])

/-- **`errored_top_denies`.** A restrictive error at `top` forces `top`. -/
theorem errored_top_denies {C : EffectChain} {l : List (Outcome C)}
    (h : Outcome.errored C.top ∈ l) : decision l = C.top := by
  have htop_ne : C.top ≠ C.bot := fun heq => C.bot_ne_top heq.symm
  have hge : C.n ≤ score l := by
    have := restrictive_error_restricts h htop_ne; rwa [C.rank_top] at this
  have hle : score l ≤ C.n := score_le (fun o _ => o.contrib_le_n)
  have hs : score l = C.n := Nat.le_antisymm hle hge
  unfold decision; rw [hs]
  apply C.rank_injective
  rw [C.rank_effectOfRank C.n (by have := C.two_le_n; omega) (Nat.le_refl _), C.rank_top]

/-- Adding an outcome never lowers the score. -/
theorem score_le_cons {C : EffectChain} (o : Outcome C) (l : List (Outcome C)) :
    score l ≤ score (o :: l) := by
  simp only [score_cons]; exact Nat.le_max_right _ _

/-- **`top_stable`.** Once a `top` is matched, adding outcomes keeps the verdict `top`. -/
theorem top_stable {C : EffectChain} {l : List (Outcome C)} (o : Outcome C)
    (h : Outcome.matched C.top ∈ l) : decision (o :: l) = C.top :=
  top_overrides (List.mem_cons.2 (Or.inr h))

/-! ## Instance 1: chai (n = 6). The laws ARE the Decision.lean lemmas. -/

/-- chai's six effects as an `EffectChain`. Every field is discharged by a lemma
    already proved in `Decision.lean`, which is the point: no new proof burden. -/
def chaiChain : EffectChain where
  E := Effect
  decEq := inferInstance
  n := 6
  rank := Effect.rank
  effectOfRank := effectOfRank
  top := .deny
  two_le_n := by decide
  rank_pos := by intro e; cases e <;> decide
  rank_le_n := by intro e; cases e <;> decide
  effectOfRank_rank := effectOfRank_rank
  rank_effectOfRank := fun m h1 h6 => rank_effectOfRank h1 h6
  effectOfRank_zero := rfl
  rank_top := rfl

/-- Sanity: the generic engine at `chaiChain` inherits fail-closed default-deny. -/
theorem chai_default_deny : decision ([] : List (Outcome chaiChain)) = Effect.deny :=
  decision_nil

/-! ### Bridge: the generic engine at `chaiChain` IS the concrete `Decision` engine.

This is what makes the split substance rather than renaming: mapping the concrete
`ChaiProofs.Outcome` into the generic `Outcome chaiChain`, the generic `decision`
computes *exactly* the concrete `ChaiProofs.decision`. -/

/-- The concrete outcomes embed into the generic ones at `chaiChain` (identity on
    constructors, since `chaiChain.E = Effect`). -/
def ofDecisionOutcome : ChaiProofs.Outcome → Outcome chaiChain
  | .matched e => .matched e
  | .unmatched => .unmatched
  | .errored e => .errored e

theorem chai_contrib_agrees (o : ChaiProofs.Outcome) :
    (ofDecisionOutcome o).contrib = o.contrib := by
  cases o <;> rfl

theorem chai_score_agrees (l : List ChaiProofs.Outcome) :
    score (l.map ofDecisionOutcome) = ChaiProofs.score l := by
  induction l with
  | nil => rfl
  | cons a t ih =>
      simp only [List.map_cons, score_cons, ChaiProofs.score_cons, chai_contrib_agrees, ih]

/-- **`chai_decision_agrees`.** The generic engine at `chaiChain`, on the embedded
    outcomes, returns the very same verdict as the concrete six-effect `decision` in
    `Decision.lean`. The concrete development is therefore an instance of this one. -/
theorem chai_decision_agrees (l : List ChaiProofs.Outcome) :
    decision (l.map ofDecisionOutcome) = ChaiProofs.decision l := by
  unfold decision ChaiProofs.decision
  rw [chai_score_agrees]
  rfl

/-! ## Instance 2: Cedar (n = 2). cedar_reduction is a corollary of the spine. -/

inductive C2 where
  | permit | forbid
deriving DecidableEq, Repr

def C2.rank : C2 → Nat
  | .permit => 1
  | .forbid => 2

def c2OfRank : Nat → C2
  | 1 => .permit
  | _ => .forbid

/-- Cedar's permit/forbid as the minimal (n = 2) `EffectChain`. -/
def cedarChain : EffectChain where
  E := C2
  decEq := inferInstance
  n := 2
  rank := C2.rank
  effectOfRank := c2OfRank
  top := .forbid
  two_le_n := by decide
  rank_pos := by intro e; cases e <;> decide
  rank_le_n := by intro e; cases e <;> decide
  effectOfRank_rank := by intro e; cases e <;> rfl
  rank_effectOfRank := by
    intro m h1 h2
    rcases m with _ | _ | _ | m
    · omega
    · rfl
    · rfl
    · omega
  effectOfRank_zero := rfl
  rank_top := rfl

theorem cedar_default_deny : decision ([] : List (Outcome cedarChain)) = C2.forbid :=
  decision_nil

/-- **Reduction to Cedar deny-overrides.** On permit/forbid-only runs, the generic
    engine at `cedarChain` decides `permit` (its `bot`) iff some permit matched and
    no forbid matched. This is `Decision.cedar_reduction` recovered as a corollary
    of `bot_needs_matched_bot` + `top_overrides` at n = 2, not a fresh proof. -/
theorem cedar_reduction {l : List (Outcome cedarChain)}
    (hc : ∀ o ∈ l, o = Outcome.unmatched
        ∨ o = Outcome.matched cedarChain.bot
        ∨ o = Outcome.matched cedarChain.top) :
    decision l = cedarChain.bot ↔
      (Outcome.matched cedarChain.bot ∈ l ∧ Outcome.matched cedarChain.top ∉ l) := by
  constructor
  · intro h
    refine ⟨bot_needs_matched_bot h, fun hd => ?_⟩
    rw [top_overrides hd] at h
    exact cedarChain.bot_ne_top h.symm
  · rintro ⟨hbot, htop⟩
    have hbound : ∀ o ∈ l, o.contrib ≤ 1 := by
      intro o ho
      rcases hc o ho with rfl | rfl | rfl
      · simp [Outcome.contrib]
      · simp [Outcome.contrib, cedarChain.rank_bot]
      · exact absurd ho htop
    have hle : score l ≤ 1 := score_le hbound
    have hge : 1 ≤ score l := by
      have h1 : (Outcome.matched cedarChain.bot).contrib = 1 := by
        simp [Outcome.contrib, cedarChain.rank_bot]
      have := contrib_le_score hbot; omega
    exact decision_eq_bot_iff_score_one.2 (Nat.le_antisymm hle hge)

end ChaiProofs.Core
