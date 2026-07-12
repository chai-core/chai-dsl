import ChaiProofs.Decision

/-!
# Mechanized PAM-style guard combinator (safe, order-independent variant)

A *guard* is a stack of tagged sub-conditions that gates a single rule's effect.
This is the two-level design: the combinator here collapses a guard to pass/fail;
passing rules' effects still resolve via the `Decision.lean` lattice (unchanged).

Control tags follow Linux-PAM, but we take the **safe** reading (recommended over
faithful PAM): a `sufficient` success NEVER bypasses a mandatory check, so the
guard is a clean, order-independent AND/OR formula:

    pass  ⟺  (stack has a gate)                 -- fail-closed: no all-optional/empty pass
          ∧  (every required/requisite passes)   -- the AND anchors
          ∧  (no sufficient present ∨ some sufficient passes)   -- the OR group
                                                  -- optional: recorded, never gating

Faithful PAM (a `sufficient` short-circuits past later `required`s) is also
expressible but is order-DEPENDENT, we deliberately don't take it (same footgun
as first-match; see the first-match discussion).

Example guard for `permit`:
    required:   subject.identity_verified
    requisite:  not safety_facts.harm
    sufficient: risk_facts.score < 0.3
    sufficient: subject.human_approved
    optional:   grounding_facts.cited
  ⟹ identity_verified ∧ (¬harm) ∧ (risk<0.3 ∨ human_approved)
-/

namespace ChaiProofs

/-- PAM control tags. -/
inductive Flag
  | required | requisite | sufficient | optional
deriving DecidableEq, Repr

/-- A `gate` tag contributes to the verdict (everything but `optional`). -/
def Flag.isGate : Flag → Prop
  | .optional => False
  | _ => True

/-- A `mandatory` tag must pass (`required` and `requisite`, verdict-identical
    in our pure setting; they differ only operationally in real PAM). -/
def Flag.isMandatory : Flag → Prop
  | .required | .requisite => True
  | _ => False

def Flag.isSufficient : Flag → Prop
  | .sufficient => True
  | _ => False

/-- A guard: an (unordered, by `passes_perm`) stack of `(tag, did-it-pass)`. -/
abbrev Guard := List (Flag × Bool)

/-- The guard verdict, the safe AND/OR reading above. -/
def passes (g : Guard) : Prop :=
  (∃ e ∈ g, e.1.isGate) ∧
  (∀ e ∈ g, e.1.isMandatory → e.2 = true) ∧
  ((∀ e ∈ g, ¬ e.1.isSufficient) ∨ (∃ e ∈ g, e.1.isSufficient ∧ e.2 = true))

/-! ## Fail-closed -/

/-- An empty (or all-`optional`) guard never passes, no gate is present. -/
theorem not_passes_nil : ¬ passes ([] : Guard) := by
  rintro ⟨⟨e, he, _⟩, _, _⟩; simp at he

/-! ## Determinism / order-independence (the safe variant's headline) -/

theorem passes_perm {g h : Guard} (hp : g.Perm h) : passes g ↔ passes h := by
  have fwd : ∀ {a b : Guard}, a.Perm b → passes a → passes b := by
    intro a b hab hpa
    obtain ⟨hg, hm, hs⟩ := hpa
    refine ⟨?_, ?_, ?_⟩
    · obtain ⟨e, he, hge⟩ := hg; exact ⟨e, (hab.mem_iff).1 he, hge⟩
    · intro e he hman; exact hm e ((hab.mem_iff).2 he) hman
    · rcases hs with hno | hex
      · exact Or.inl (fun e he => hno e ((hab.mem_iff).2 he))
      · obtain ⟨e, he, hp'⟩ := hex; exact Or.inr ⟨e, (hab.mem_iff).1 he, hp'⟩
  exact ⟨fwd hp, fwd hp.symm⟩

/-! ## Mandatory dominance and the OR group -/

/-- A failed `required`/`requisite` denies the guard, wherever it sits. -/
theorem mandatory_fail_denies {g : Guard} {e : Flag × Bool}
    (he : e ∈ g) (hman : e.1.isMandatory) (hfail : e.2 = false) : ¬ passes g := by
  rintro ⟨_, hm, _⟩
  have hp := hm e he hman
  rw [hfail] at hp
  exact absurd hp (by decide)

/-- If the guard contains a `sufficient` but none of them pass, it is denied. -/
theorem sufficient_present_none_pass_denies {g : Guard} {e : Flag × Bool}
    (he : e ∈ g) (hsuf : e.1.isSufficient)
    (hnone : ∀ s ∈ g, s.1.isSufficient → s.2 = false) : ¬ passes g := by
  rintro ⟨_, _, hs⟩
  rcases hs with hno | ⟨s, hsg, hssuf, hspass⟩
  · exact hno e he hsuf
  · have := hnone s hsg hssuf; rw [this] at hspass; exact absurd hspass (by decide)

/-! ## `requisite` ≡ `required` (the purity equivalence)

In our pure, side-effect-free setting `required` and `requisite` are
verdict-identical: they share the exact classification `passes` reasons about
(both `isGate`, both `isMandatory`, neither `isSufficient`). So no theorem can
distinguish them, they are interchangeable for the decision, differing only in
intent/readability. -/
theorem required_requisite_same_class :
    (Flag.required.isGate ↔ Flag.requisite.isGate) ∧
    (Flag.required.isMandatory ↔ Flag.requisite.isMandatory) ∧
    (Flag.required.isSufficient ↔ Flag.requisite.isSufficient) := by
  refine ⟨?_, ?_, ?_⟩ <;> simp [Flag.isGate, Flag.isMandatory, Flag.isSufficient]

end ChaiProofs
