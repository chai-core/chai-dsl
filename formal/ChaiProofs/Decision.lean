/-!
# Mechanized core theorems for the ESP decision algebra

This file mechanizes, in Lean 4, the **deterministic decision core** of the
Chai/ESP runtime: the most-restrictive-wins resolution that `eval_rules`
performs in `crates/chai-core/src/evaluator.rs` (function `eval_rules`, lines 416-496). These are
the security invariants stated in the `three_layer` spec (§"Security
Invariants"): *fail-closed emission*, *deterministic enforcement*, and the
reduction to Cedar deny-overrides claimed in `CLAUDE.md`.

## Correspondence to the Rust implementation

The Lean model below is an abstraction of `eval_rules`. The correspondence is
argued by inspection (it is **not** a mechanized extraction):

* `Effect`            ↔ `ast::Effect`. `Forbid` and `Deny` both map to `.deny`
                        (evaluator.rs:435 buckets them together).
* `Outcome`           ↔ the per-rule branch of `eval_rule` inside the loop
                        (evaluator.rs:433-445):
                        `Ok(true)` with effect `e` ↦ `matched e`,
                        `Ok(false)` ↦ `unmatched`,
                        `Err _`     ↦ `errored` (recorded, never grants, :443).
* `decision`          ↔ the bucket-and-resolve block (evaluator.rs:449-495):
                        the most-restrictive non-empty bucket wins; if none
                        matched, the fail-closed default is `Deny` (:481-495).

The restrictiveness order `DENY > REQUIRE_HUMAN > DEFER > REDACT > DOWNGRADE >
ALLOW` is exactly the lattice documented at evaluator.rs:449-450.

What is proven: order-independence (determinism), fail-closed emission (allow
requires an explicit allow rule; errors/no-match never emit), forbid-overrides,
and the reduction to Cedar deny-overrides for permit/forbid-only policies.

What is *not* proven here: the parser, the expression evaluator, and the AFC
detectors. Those remain validated by differential testing against Cedar and by
the z3 analysis, this file covers the control core they feed into.
-/

namespace ChaiProofs

/-- The emission decision lattice (evaluator.rs:449-450). -/
inductive Effect where
  | allow | downgrade | redact | defer | requireHuman | deny
deriving DecidableEq, Repr

/-- Restrictiveness rank; higher = more restrictive, matching the resolution
    order in `eval_rules`. Rank `0` is reserved for "no contribution"
    (unmatched/errored), so every real effect has rank ≥ 1. -/
def Effect.rank : Effect → Nat
  | .allow        => 1
  | .downgrade    => 2
  | .redact       => 3
  | .defer        => 4
  | .requireHuman => 5
  | .deny         => 6

/-- Inverse of `rank` on `{1,…,6}`. Rank `0` (nothing matched) maps to the
    fail-closed default `.deny`, so BOTH "a forbid matched" (rank 6) and "no
    rule matched" (rank 0) yield `.deny`, exactly as eval_rules does. -/
def effectOfRank : Nat → Effect
  | 1 => .allow
  | 2 => .downgrade
  | 3 => .redact
  | 4 => .defer
  | 5 => .requireHuman
  | _ => .deny

@[simp] theorem effectOfRank_rank (e : Effect) : effectOfRank e.rank = e := by
  cases e <;> rfl

/-- On the live range `{1,…,6}`, `rank` is a left inverse of `effectOfRank`. -/
theorem rank_effectOfRank {n : Nat} (h1 : 1 ≤ n) (h6 : n ≤ 6) :
    (effectOfRank n).rank = n := by
  rcases n with _|_|_|_|_|_|_|n
  · omega
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · omega

/-- A single rule's evaluation outcome, mirroring the three `eval_rule` branches.
    **Effect-tagged errors** (§1.1): `errored` now carries the erroring rule's
    effect, exactly the XACML `Indeterminate` refinement. This mirrors
    `crates/chai-core/src/evaluator.rs`: on `Err`, a *strict restrictive* rule (`Rule::error_contributes`
    true) is bucketed by its effect and modelled here as `errored e` with
    `e ≠ allow`; a permit or `lenient` rule is inert and modelled as
    `errored .allow` (contribution `0`). -/
inductive Outcome where
  | matched : Effect → Outcome
  | unmatched : Outcome
  | errored : Effect → Outcome
deriving DecidableEq, Repr

/-- An outcome's contribution to the decision. A matched rule contributes its
    effect's rank; an unmatched rule contributes `0`. A strict restrictive error
    (`errored e`, `e ≠ allow`) contributes its effect's rank, "we could not check
    the condition that would have restricted, so restrict." A permit/lenient error
    (`errored .allow`) contributes `0`: an error can never *manufacture* an allow. -/
def Outcome.contrib : Outcome → Nat
  | .matched e => e.rank
  | .unmatched => 0
  | .errored e => if e = .allow then 0 else e.rank

theorem Outcome.contrib_le_six (o : Outcome) : o.contrib ≤ 6 := by
  cases o with
  | matched e => cases e <;> decide
  | unmatched => decide
  | errored e => cases e <;> decide

/-- The score of a policy run: the maximum contribution over all rule outcomes
    (`0` if none contribute). This is "the most-restrictive matched bucket". -/
def score (l : List Outcome) : Nat :=
  l.foldr (fun o acc => Nat.max o.contrib acc) 0

@[simp] theorem score_nil : score [] = 0 := rfl
@[simp] theorem score_cons (o : Outcome) (l : List Outcome) :
    score (o :: l) = Nat.max o.contrib (score l) := rfl

-- `omega` treats `Nat.max` as opaque, so we resolve maxima with these helpers.
theorem nat_max_eq_left {a b : Nat} (h : b ≤ a) : Nat.max a b = a :=
  Nat.le_antisymm (Nat.max_le.2 ⟨Nat.le_refl a, h⟩) (Nat.le_max_left a b)
theorem nat_max_eq_right {a b : Nat} (h : a ≤ b) : Nat.max a b = b :=
  Nat.le_antisymm (Nat.max_le.2 ⟨h, Nat.le_refl b⟩) (Nat.le_max_right a b)

theorem nat_max_left_comm (a b c : Nat) :
    Nat.max a (Nat.max b c) = Nat.max b (Nat.max a c) := by
  apply Nat.le_antisymm
  · apply Nat.max_le.2
    refine ⟨Nat.le_trans (Nat.le_max_left a c) (Nat.le_max_right b _), ?_⟩
    exact Nat.max_le.2 ⟨Nat.le_max_left b _, Nat.le_trans (Nat.le_max_right a c) (Nat.le_max_right b _)⟩
  · apply Nat.max_le.2
    refine ⟨Nat.le_trans (Nat.le_max_left b c) (Nat.le_max_right a _), ?_⟩
    exact Nat.max_le.2 ⟨Nat.le_max_left a _, Nat.le_trans (Nat.le_max_right b c) (Nat.le_max_right a _)⟩

/-- **The ESP decision** for a policy run (evaluator.rs:449-495). -/
def decision (l : List Outcome) : Effect := effectOfRank (score l)

/-! ## Default-deny (fail-closed baseline) -/

/-- No rule matched ⇒ `Deny` (evaluator.rs:481-495). -/
theorem decision_nil : decision [] = .deny := rfl

/-! ## Determinism / order-independence (the `DenyOverride` invariant) -/

/-- `score` is invariant under permutation of the outcome list. -/
theorem score_perm {l₁ l₂ : List Outcome} (h : l₁.Perm l₂) : score l₁ = score l₂ := by
  induction h with
  | nil => rfl
  | cons x _ ih => simp [score_cons, ih]
  | swap x y l =>
      simp only [score_cons]
      exact nat_max_left_comm y.contrib x.contrib (score l)
  | trans _ _ ih₁ ih₂ => exact ih₁.trans ih₂

/-- **Deterministic enforcement.** The decision depends only on the *multiset* of
    rule outcomes, never on their order, so no rule can be shadowed by ordering
    (`three_layer` §Security Invariants; `CLAUDE.md` "order-independent"). -/
theorem decision_perm {l₁ l₂ : List Outcome} (h : l₁.Perm l₂) :
    decision l₁ = decision l₂ := by
  unfold decision; rw [score_perm h]

/-! ## Score is an achieved upper bound over contributions -/

theorem contrib_le_score {o : Outcome} {l : List Outcome} (h : o ∈ l) :
    o.contrib ≤ score l := by
  induction l with
  | nil => cases h
  | cons a t ih =>
      rcases List.mem_cons.1 h with rfl | h'
      · simp only [score_cons]; exact Nat.le_max_left _ _
      · simp only [score_cons]; exact Nat.le_trans (ih h') (Nat.le_max_right _ _)

theorem score_le {l : List Outcome} {b : Nat} (h : ∀ o ∈ l, o.contrib ≤ b) :
    score l ≤ b := by
  induction l with
  | nil => simp only [score_nil]; exact Nat.zero_le b
  | cons a t ih =>
      have ha : a.contrib ≤ b := h a (List.mem_cons.2 (Or.inl rfl))
      have ht : score t ≤ b := ih (fun o ho => h o (List.mem_cons.2 (Or.inr ho)))
      simp only [score_cons]; exact Nat.max_le.2 ⟨ha, ht⟩

/-- If the score is positive, some outcome achieves it (the winning rule). -/
theorem exists_contrib_eq_score :
    ∀ (l : List Outcome), 0 < score l → ∃ o ∈ l, o.contrib = score l
  | [], h => by simp [score_nil] at h
  | a :: t, h => by
      rcases Nat.le_total (score t) a.contrib with hle | hle
      · refine ⟨a, List.mem_cons.2 (Or.inl rfl), ?_⟩
        simp only [score_cons]; exact (nat_max_eq_left hle).symm
      · have htpos : 0 < score t := by
          simp only [score_cons] at h; rw [nat_max_eq_right hle] at h; exact h
        obtain ⟨o, hot, hoc⟩ := exists_contrib_eq_score t htpos
        refine ⟨o, List.mem_cons.2 (Or.inr hot), ?_⟩
        simp only [score_cons]; rw [nat_max_eq_right hle]; exact hoc

/-! ## Fail-closed emission -/

theorem effectOfRank_eq_allow_iff (n : Nat) : effectOfRank n = .allow ↔ n = 1 := by
  constructor
  · intro h
    rcases n with _ | _ | _ | _ | _ | _ | n
    · simp [effectOfRank] at h
    · rfl
    all_goals simp [effectOfRank] at h
  · rintro rfl; rfl

theorem contrib_eq_one {o : Outcome} (h : o.contrib = 1) : o = .matched .allow := by
  cases o with
  | matched e => cases e <;> simp_all [Outcome.contrib, Effect.rank]
  | unmatched => simp [Outcome.contrib] at h
  -- An error can never have contribution 1: a permit/lenient error contributes 0,
  -- and a restrictive error's rank is ≥ 2. So an `allow` never arises from an error.
  | errored e => cases e <;> simp_all [Outcome.contrib, Effect.rank]

/-- **Fail-closed emission.** The runtime emits a prefix only when the decision is
    `ALLOW` (`three_layer` §Streaming Enforcement). This theorem shows an `ALLOW`
    decision can only arise from an *explicit* matched allow rule, there is no
    other path to emission. -/
theorem allow_needs_matched_allow {l : List Outcome} (h : decision l = .allow) :
    Outcome.matched .allow ∈ l := by
  have hscore : score l = 1 := (effectOfRank_eq_allow_iff (score l)).1 h
  obtain ⟨o, ho, hoc⟩ := exists_contrib_eq_score l (by omega)
  rw [hscore] at hoc
  rw [← contrib_eq_one hoc]; exact ho

/-- **Nothing that contributes ⇒ Deny.** If every outcome contributes `0` (no
    match, and only inert permit/lenient errors), the decision is the fail-closed
    default `Deny`. -/
theorem no_contrib_denies {l : List Outcome}
    (h : ∀ o ∈ l, o.contrib = 0) : decision l = .deny := by
  have : score l ≤ 0 := score_le (fun o ho => Nat.le_of_eq (h o ho))
  have : score l = 0 := by omega
  unfold decision; rw [this]; rfl

/-- **Errors and non-matches never emit.** If every rule either did not match or
    is an inert (permit/lenient) error, the decision is `Deny`. This is the
    effect-tagged generalization of the old `no_match_or_error_denies`: a
    *restrictive* error is no longer inert (see `restrictive_error_restricts`). -/
theorem no_match_or_error_denies {l : List Outcome}
    (h : ∀ o ∈ l, o = .unmatched ∨ o = .errored .allow) : decision l = .deny :=
  no_contrib_denies (by
    intro o ho; rcases h o ho with rfl | rfl <;> simp [Outcome.contrib])

/-! ## §1.1 Effect-tagged errors: restrictive errors restrict, permit errors are inert -/

/-- A strict restrictive error contributes exactly its effect's rank. -/
theorem errored_contrib {e : Effect} (h : e ≠ .allow) :
    (Outcome.errored e).contrib = e.rank := by
  simp [Outcome.contrib, h]

/-- **`permit_error_inert`.** A permit's (or a `lenient` rule's) error contributes
    nothing, so prepending it leaves the score, hence the decision, unchanged. -/
theorem permit_error_inert (l : List Outcome) :
    score (Outcome.errored .allow :: l) = score l := by
  simp [score_cons, Outcome.contrib]

/-- **`restrictive_error_restricts`.** A strict restrictive error `errored e`
    (`e ≠ allow`) contributes its effect `e` to the score, so it can only tighten
    the decision, never relax it. -/
theorem restrictive_error_restricts {l : List Outcome} {e : Effect}
    (hmem : Outcome.errored e ∈ l) (hne : e ≠ .allow) : e.rank ≤ score l := by
  have := contrib_le_score hmem
  rwa [errored_contrib hne] at this

/-- **Corollary: a failed forbid forces Deny.** If evaluating a `forbid`/`deny`
    rule's guard errors under strict semantics, the run denies, the conservative
    reading of an unverifiable restriction (this is what makes the abstract's
    "a timeout must never produce an allow" claim *true* of the mechanized
    semantics, not just of the all-failed case). -/
theorem errored_deny_denies {l : List Outcome} (h : Outcome.errored .deny ∈ l) :
    decision l = .deny := by
  have h6 : (6 : Nat) ≤ score l := by
    have := restrictive_error_restricts h (by decide); simpa [Effect.rank] using this
  have h6' : score l ≤ 6 := score_le (fun o _ => o.contrib_le_six)
  have : score l = 6 := by omega
  unfold decision; rw [this]; rfl

/-! ## Forbid-overrides and the reduction to Cedar deny-overrides -/

/-- **Forbid overrides everything.** Any matched `Deny`/`Forbid` rule forces a
    `Deny` decision, regardless of what else matched (evaluator.rs:453-454). -/
theorem forbid_overrides {l : List Outcome} (h : Outcome.matched .deny ∈ l) :
    decision l = .deny := by
  have h6 : (6 : Nat) ≤ score l := by
    have := contrib_le_score h; simpa [Outcome.contrib, Effect.rank] using this
  have h6' : score l ≤ 6 := score_le (fun o _ => o.contrib_le_six)
  have : score l = 6 := by omega
  unfold decision; rw [this]; rfl

/-- A run is in the *Cedar fragment* if every outcome is a matched `permit`
    (`allow`) or `forbid` (`deny`), or a non-match, no streaming-only effects and
    no guard errors. (Cedar's core; the effect-tagged error case is the XACML
    `Indeterminate` extension, covered by the theorems above.) -/
def cedarFragment (l : List Outcome) : Prop :=
  ∀ o ∈ l, o = .unmatched ∨ o = .matched .allow ∨ o = .matched .deny

/-- **Reduction to Cedar deny-overrides.** On permit/forbid-only policies, our
    lattice computes exactly Cedar's semantics: `Allow` iff some permit matched
    and no forbid matched; otherwise `Deny` (`CLAUDE.md` invariant). -/
theorem cedar_reduction {l : List Outcome} (hc : cedarFragment l) :
    decision l = .allow ↔
      (Outcome.matched .allow ∈ l ∧ Outcome.matched .deny ∉ l) := by
  constructor
  · intro h
    refine ⟨allow_needs_matched_allow h, fun hd => ?_⟩
    rw [forbid_overrides hd] at h; cases h
  · rintro ⟨hallow, hdeny⟩
    -- No matched deny ⇒ in the Cedar fragment every contribution is ≤ 1.
    have hbound : ∀ o ∈ l, o.contrib ≤ 1 := by
      intro o ho
      rcases hc o ho with rfl | rfl | rfl
      · simp [Outcome.contrib]                    -- unmatched
      · simp [Outcome.contrib, Effect.rank]       -- matched allow → rank 1
      · exact absurd ho hdeny                      -- matched deny excluded
    have hle : score l ≤ 1 := score_le hbound
    have hge : 1 ≤ score l := by
      have := contrib_le_score hallow; simpa [Outcome.contrib, Effect.rank] using this
    have : score l = 1 := by omega
    unfold decision; rw [this]; rfl

/-! ## Monotonicity of evidence (score only tightens as rules are added)

NOTE on honesty: at the *decision* level there is no naive "more rules ⇒ more
restrictive", because the empty run is already maximally restrictive (default
`Deny`), adding a matched `allow` *relaxes* `Deny`→`Allow`. The true monotone
quantity is the matched-evidence `score`, and the security-relevant consequence
is `forbid_overrides` above: once a forbid matches, nothing added can relax it. -/

/-- Adding a rule outcome never lowers the matched-evidence score. -/
theorem score_le_cons (o : Outcome) (l : List Outcome) : score l ≤ score (o :: l) := by
  simp only [score_cons]; exact Nat.le_max_right _ _

/-- Once a forbid is present, adding any further outcomes keeps the decision
    `Deny` (a direct corollary of `forbid_overrides`). -/
theorem deny_stable {l : List Outcome} (o : Outcome) (h : Outcome.matched .deny ∈ l) :
    decision (o :: l) = .deny :=
  forbid_overrides (List.mem_cons.2 (Or.inr h))

/-! ## §2.1 Every non-trivial decision has a witnessing rule -/

/-- **`decision_witness`.** If any rule contributed (`0 < score l`), some outcome
    in the run carries the winning effect: its contribution equals the decision's
    rank. This generalizes `allow_needs_matched_allow` to *every* effect, so the
    runtime can attach the witnessing rule id to any verdict and a denial is
    auditable to a concrete rule. -/
theorem decision_witness {l : List Outcome} (h : 0 < score l) :
    ∃ o ∈ l, o.contrib = (decision l).rank := by
  obtain ⟨o, ho, hoc⟩ := exists_contrib_eq_score l h
  refine ⟨o, ho, ?_⟩
  have h6 : score l ≤ 6 := score_le (fun o _ => o.contrib_le_six)
  rw [hoc]; unfold decision; exact (rank_effectOfRank h h6).symm

/-! ## §2.5 The seal predicate is permutation-invariant

The emission runtime seals the stream whenever a `require_human` outcome is
present (§1.2 seal-on-presence). The seal is a *membership* predicate on the
outcome list, so, like the decision itself, it does not depend on rule order. -/

/-- Whether an outcome is a `require_human` verdict (matched or strictly errored). -/
def Outcome.isRequireHuman : Outcome → Prop
  | .matched .requireHuman => True
  | .errored .requireHuman => True
  | _ => False

/-- Seal-on-presence: some outcome in the run is a `require_human`. -/
def sealOn (l : List Outcome) : Prop := ∃ o ∈ l, o.isRequireHuman

/-- **`seal_on_presence_perm`.** The seal predicate is permutation-invariant, so
    the seal-change of §1.2 keeps the order-independence story intact. -/
theorem seal_on_presence_perm {l₁ l₂ : List Outcome} (h : l₁.Perm l₂) :
    sealOn l₁ ↔ sealOn l₂ := by
  unfold sealOn
  constructor
  · rintro ⟨o, ho, hrh⟩; exact ⟨o, h.mem_iff.1 ho, hrh⟩
  · rintro ⟨o, ho, hrh⟩; exact ⟨o, h.mem_iff.2 ho, hrh⟩

/-! ## §3.1 Verdict + obligations

`decide` returns the verdict (the chain join, unchanged, so every proof above
stands). The **obligation set** is the transforms accumulated from the matched
releasing rules at-or-below the verdict. This fixes the silent-drop flaw: a chunk
matching both `redact` and `downgrade` has *both* transforms applied, not only the
winning one. `Allow` is identity and is excluded (`Effect.releasing` below is the
non-identity releasing effects). -/

/-- The non-identity releasing effects (the ones that carry a transform). -/
def Effect.releasing : Effect → Prop
  | .downgrade => True
  | .redact => True
  | _ => False

/-- `e` is an accumulated obligation of `os`: some rule matched with a non-identity
    releasing effect `e` that is at-or-below the verdict. Mirrors
    `Decision.transforms`. -/
def isObligation (os : List Outcome) (e : Effect) : Prop :=
  Outcome.matched e ∈ os ∧ e.releasing ∧ e.rank ≤ (decision os).rank

/-- **`obligations_perm`.** The obligation set is permutation-invariant: it is a
    membership test plus the (order-independent) verdict, so accumulating transforms
    keeps `decision_perm`'s order-independence. -/
theorem obligations_perm {l₁ l₂ : List Outcome} (h : l₁.Perm l₂) (e : Effect) :
    isObligation l₁ e ↔ isObligation l₂ e := by
  unfold isObligation
  rw [decision_perm h]
  constructor
  · rintro ⟨hm, hr, hle⟩; exact ⟨h.mem_iff.1 hm, hr, hle⟩
  · rintro ⟨hm, hr, hle⟩; exact ⟨h.mem_iff.2 hm, hr, hle⟩

/-- **`obligations_complete`.** Every matched releasing rule at-or-below the verdict
    contributes its transform to the obligation set. So nothing that should be
    applied to the release is dropped (the SSN+labels leak cannot recur). -/
theorem obligations_complete {os : List Outcome} {e : Effect}
    (hm : Outcome.matched e ∈ os) (hr : e.releasing)
    (hle : e.rank ≤ (decision os).rank) : isObligation os e :=
  ⟨hm, hr, hle⟩

/-- The verdict's own transform is an obligation whenever the verdict is a
    non-identity releasing effect: `redact`/`downgrade` always apply themselves. -/
theorem verdict_is_obligation {os : List Outcome}
    (hm : Outcome.matched (decision os) ∈ os) (hr : (decision os).releasing) :
    isObligation os (decision os) :=
  ⟨hm, hr, Nat.le_refl _⟩

/-! ## §3.2 Evidence tiers

Facts carry a provenance tier: *measured* (detector output), *derived* (runtime-
computed), or *attested* (signature-verified). A per-rule minimum-tier annotation
gates a guard, so a `permit requires attested` cannot fire from weaker evidence.
Signature verification thereby joins the trusted base. -/

inductive Tier where
  | measured | derived | attested
deriving DecidableEq, Repr

/-- Tiers are ordered by trust: measured < derived < attested. -/
def Tier.rank : Tier → Nat
  | .measured => 0
  | .derived  => 1
  | .attested => 2

/-- A tier gate passes when the evidence meets the required tier. The `evidence`
    tier is the *weakest* the guard rests on (the min over the facts it reads). -/
def gatePasses (required evidence : Tier) : Prop := required.rank ≤ evidence.rank

/-- The gate is sound: it passes only when the evidence is at least the required
    tier. -/
theorem gate_sound {required evidence : Tier} (h : gatePasses required evidence) :
    required.rank ≤ evidence.rank := h

/-- **`attested_gate_sound`.** A rule annotated `requires attested` never fires from
    measured or derived evidence: the gate passes only when the evidence is itself
    attested (signature-verified). -/
theorem attested_gate_sound {evidence : Tier} (h : evidence ≠ .attested) :
    ¬ gatePasses .attested evidence := by
  cases evidence <;> simp_all [gatePasses, Tier.rank]

end ChaiProofs
