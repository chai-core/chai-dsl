import ChaiProofs.Decision

/-!
# Mechanized fail-closed theorems for the Emission state machine

Companion to `Decision.lean`. This mechanizes the streaming enforcement runtime
`EmissionEnforcer::step` / `finish` in `crates/chai-core/src/emission.rs` (lines 68-128), the
deterministic *control* half of streaming emission, and proves its fail-closed
invariants (emission.rs:12-16, `three_layer` §Streaming Enforcement).

## Correspondence to the Rust implementation (by inspection)

* `EState`            ↔ the security-relevant part of `EmissionEnforcer`:
                        `buffered` = "is there unapproved buffered prefix"
                        (`!buffer.is_empty()`), `halted` = the `halted` flag.
* `Action`            ↔ `EmitAction`. NOTE `Downgrade` produces `EmitAction::Emit`
                        of downgraded text (emission.rs:110-114), so BOTH `allow`
                        and `downgrade` map to `Action.emit`, exactly as the code.
* `step`              ↔ `EmissionEnforcer::step` (emission.rs:68-116): the halted
                        short-circuit (:70) then the per-effect match (:85-115).
* `finish`            ↔ `EmissionEnforcer::finish` (emission.rs:120-128): always
                        drops; buffered-but-unapproved content is never emitted.

`releasesAny` models "this action puts text on the sink" (`Emit`/`Redact`); the
fail-closed claims are about when that can be `true`.
-/

namespace ChaiProofs

inductive Action
  | emit | buffer | redact | drop | requireHuman
deriving DecidableEq, Repr

/-- Does this action release any text to the sink? (`Emit`/`Redact` do.) -/
def Action.releasesAny : Action → Bool
  | .emit => true
  | .redact => true
  | _ => false

/-- Security-relevant emission state. -/
structure EState where
  buffered : Bool
  halted : Bool
deriving DecidableEq, Repr

/-- One streaming step, faithful to `EmissionEnforcer::step`. -/
def step (st : EState) (e : Effect) : Action × EState :=
  match st.halted with
  | true => (Action.drop, st)                                   -- sealed: emit nothing
  | false =>
    match e with
    | .allow        => (Action.emit, { st with buffered := false })
    | .defer        => (Action.buffer, { st with buffered := true })
    | .redact       => (Action.redact, { st with buffered := false })
    | .deny         => (Action.drop, { st with buffered := false })  -- drops buffer too
    | .requireHuman => (Action.requireHuman, { st with halted := true })
    | .downgrade    => (Action.emit, { st with buffered := false })

/-- End-of-stream flush: always drop (unapproved buffer is never emitted). -/
def finish (st : EState) : Action × EState := (Action.drop, { st with buffered := false })

/-! ## Halt is absorbing, a sealed stream emits nothing further -/

theorem halt_drop {st : EState} {e : Effect} (h : st.halted = true) :
    (step st e).1 = Action.drop := by
  simp [step, h]

theorem halt_absorbing {st : EState} {e : Effect} (h : st.halted = true) :
    (step st e).2.halted = true := by
  simp [step, h]

/-- Once halted, EVERY action over any remaining effect stream is `drop`. -/
def steps : EState → List Effect → (List Action × EState)
  | st, [] => ([], st)
  | st, e :: es =>
      ((step st e).1 :: (steps (step st e).2 es).1, (steps (step st e).2 es).2)

theorem sealed_stream :
    ∀ (es : List Effect) (st : EState), st.halted = true →
      ∀ a ∈ (steps st es).1, a = Action.drop
  | [], st, _ => by intro a ha; simp [steps] at ha
  | e :: es, st, h => by
      intro a ha
      simp only [steps] at ha
      rcases List.mem_cons.1 ha with rfl | hrest
      · exact halt_drop h
      · exact sealed_stream es (step st e).2 (halt_absorbing h) a hrest

/-! ## Fail-closed: release requires an authorizing effect (and not halted) -/

/-- `Emit` happens only for `allow` or `downgrade`, and only when not halted. -/
theorem emit_implies {st : EState} {e : Effect} (h : (step st e).1 = Action.emit) :
    st.halted = false ∧ (e = .allow ∨ e = .downgrade) := by
  cases hh : st.halted with
  | true => rw [halt_drop hh] at h; cases h
  | false => refine ⟨rfl, ?_⟩; cases e <;> simp_all [step]

/-- Nothing is released to the sink unless the effect was a releasing one
    (`allow`/`downgrade`/`redact`) and the stream was not halted. This is the
    core fail-closed invariant (emission.rs:12-14). -/
theorem release_effect {st : EState} {e : Effect}
    (h : (step st e).1.releasesAny = true) :
    st.halted = false ∧ (e = .allow ∨ e = .downgrade ∨ e = .redact) := by
  cases hh : st.halted with
  | true => rw [halt_drop hh] at h; cases h
  | false => refine ⟨rfl, ?_⟩; cases e <;> simp_all [step, Action.releasesAny]

/-- `finish` never releases buffered content (emission.rs:120-128). -/
theorem finish_no_release (st : EState) : (finish st).1.releasesAny = false := rfl

/-! ## End-to-end: ESP ∘ Emission only releases on an explicit permit

Composing with `Decision.lean`: feed Emission the effect ESP computes from a
policy run (`decision l`). On permit/forbid-only policies, the runtime puts text
on the sink ONLY when an explicit permit rule matched, no other path emits. -/

/-- In the Cedar fragment, ESP yields exactly `allow` or `deny`. -/
theorem cedar_decision_allow_or_deny {l : List Outcome} (hc : cedarFragment l) :
    decision l = .allow ∨ decision l = .deny := by
  by_cases hd : Outcome.matched .deny ∈ l
  · exact Or.inr (forbid_overrides hd)
  · by_cases ha : Outcome.matched .allow ∈ l
    · exact Or.inl ((cedar_reduction hc).2 ⟨ha, hd⟩)
    · refine Or.inr (no_match_or_error_denies ?_)
      intro o ho
      -- In the (error-free) Cedar fragment, with no matched allow and no matched
      -- deny, every outcome is a non-match.
      rcases hc o ho with rfl | rfl | rfl
      · exact Or.inl rfl        -- unmatched
      · exact absurd ho ha       -- matched allow excluded
      · exact absurd ho hd       -- matched deny excluded

/-- **End-to-end fail-closed (ESP ∘ Emission).** With a permit/forbid-only policy,
    the streaming runtime releases content to the sink only when an *explicit*
    permit rule matched the request. -/
theorem release_needs_matched_allow {st : EState} {l : List Outcome}
    (hc : cedarFragment l) (h : (step st (decision l)).1.releasesAny = true) :
    Outcome.matched .allow ∈ l := by
  obtain ⟨_, hcases⟩ := release_effect h
  have hdec : decision l = .allow := by
    rcases cedar_decision_allow_or_deny hc with hAllow | hDeny
    · exact hAllow
    · rcases hcases with h1 | h1 | h1 <;> rw [h1] at hDeny <;> cases hDeny
  exact allow_needs_matched_allow hdec

/-! ## §1.2 Seal-on-presence

`step` seals only on the *winning* effect `.requireHuman`. The runtime, however,
seals whenever a `require_human` outcome is *present*, even when a `deny` wins the
join (`crates/chai-core/src/emission.rs`, the `seal` flag). `stepSeal` threads that presence flag;
the chunk-level action is unchanged (so `release_effect` still governs release),
but the stream seals on presence. -/

/-- `step` augmented with the seal-on-presence flag `rhPresent`
    (`decision.require_human_present`). The action is exactly `step`'s; only the
    halt bit additionally reflects presence. -/
def stepSeal (st : EState) (e : Effect) (rhPresent : Bool) : Action × EState :=
  let r := step st e
  (r.1, { r.2 with halted := r.2.halted || rhPresent })

/-- Seal-on-presence leaves the released action unchanged: the same
    `release_effect` fail-closed invariant governs what reaches the sink. -/
theorem stepSeal_action (st : EState) (e : Effect) (b : Bool) :
    (stepSeal st e b).1 = (step st e).1 := by simp [stepSeal]

/-- A present `require_human` outcome seals the stream, whatever the verdict. -/
theorem stepSeal_seals (st : EState) (e : Effect) :
    (stepSeal st e true).2.halted = true := by simp [stepSeal]

/-- **The secret+harm case.** A chunk that trips both `deny` (winning verdict) and
    `require_human` drops the chunk *and* seals the stream, so more-alarming
    evidence never yields a weaker stream-level response than `require_human`
    alone. -/
theorem deny_with_seal_drops_and_seals (st : EState) (hns : st.halted = false) :
    (stepSeal st .deny true).1 = Action.drop ∧ (stepSeal st .deny true).2.halted = true := by
  refine ⟨?_, ?_⟩
  · rw [stepSeal_action]; simp [step, hns]
  · exact stepSeal_seals st .deny

/-! ## §1.3 The Approve transition

`defer` buffers a chunk; `finish` drops it. The **Approve transition** re-decides
the buffered prefix under new facts `F'` (the approval facts) and releases it only
under an authorizing (releasing) effect, so a buffered release still requires an
authorizing decision, now on the approval facts. Structurally it is `stepSeal`
applied to the buffered chunk (so the approve path carries seal-on-presence too,
exactly as `EmissionEnforcer::approve` does), gated on there being a buffer and the
stream not being sealed, so the same `release_effect` invariant transfers.

NOTE on the redact over-approximation: this model treats `redact` as always
releasing (`Action.redact`), whereas `EmissionEnforcer::{step,approve}` drop when
the span-masker localizes nothing (`masked == combined`). The Rust releases a
*subset* of what the model does, so the implication-shaped release theorems below
still hold of the code. -/

/-- Re-decide and release the buffered chunk, carrying the seal-on-presence flag
    `rhPresent` just like `EmissionEnforcer::approve`. Releases nothing if the
    stream is sealed or there is nothing buffered. -/
def approve (st : EState) (e : Effect) (rhPresent : Bool) : Action × EState :=
  match st.halted, st.buffered with
  | false, true => stepSeal st e rhPresent
  | _, _ => (Action.drop, st)

/-- **Approve release still needs an authorizing decision.** A buffered chunk
    reaches the sink only when the stream was live, something was buffered, and the
    re-decision under the approval facts is a releasing effect
    (`allow`/`downgrade`/`redact`). `finish_no_release` is unchanged: an unapproved
    buffer still dies at end of stream. -/
theorem approve_release_effect {st : EState} {e : Effect} {rh : Bool}
    (h : (approve st e rh).1.releasesAny = true) :
    st.halted = false ∧ st.buffered = true ∧ (e = .allow ∨ e = .downgrade ∨ e = .redact) := by
  cases hh : st.halted with
  | true => simp [approve, hh, Action.releasesAny] at h
  | false =>
    cases hb : st.buffered with
    | false => simp [approve, hh, hb, Action.releasesAny] at h
    | true =>
      simp only [approve, hh, hb, stepSeal_action] at h
      obtain ⟨_, hcases⟩ := release_effect h
      exact ⟨rfl, rfl, hcases⟩

/-- **Approve carries seal-on-presence.** A present `require_human` outcome on the
    re-decision seals the stream even on the approve path, matching
    `EmissionEnforcer::approve` (which is what closes the model↔code gap that a
    plain-`step` approve would leave). -/
theorem approve_seals_on_presence (st : EState) (e : Effect)
    (hns : st.halted = false) (hbuf : st.buffered = true) :
    (approve st e true).2.halted = true := by
  simp only [approve, hns, hbuf]
  exact stepSeal_seals st e

/-! ## §2.3 Stream transparency and §2.4 verbatim-release payload -/

/-- **`stream_transparency`.** If every chunk of a stream decides `Allow` (and the
    stream starts live), every action is `emit`: nothing is suppressed, redacted,
    buffered, or dropped. Together with `verbatim_release_needs_allow` below (the
    `Allow` payload is the verbatim chunk), the output equals the input, in order.
    This is the transparency half of the soundness/transparency pair from the
    enforcement-monitor literature. -/
theorem stream_transparency :
    ∀ (es : List Effect) (st : EState), st.halted = false →
      (∀ e ∈ es, e = .allow) → ∀ a ∈ (steps st es).1, a = Action.emit
  | [], _, _, _ => by intro a ha; simp [steps] at ha
  | e :: es, st, hns, hall => by
      intro a ha
      have he : e = .allow := hall e (List.mem_cons.2 (Or.inl rfl))
      subst he
      simp only [steps] at ha
      rcases List.mem_cons.1 ha with rfl | hrest
      · simp [step, hns]
      · have hns' : (step st .allow).2.halted = false := by simp [step, hns]
        exact stream_transparency es (step st .allow).2 hns'
          (fun e' he' => hall e' (List.mem_cons.2 (Or.inr he'))) a hrest

/-! ## §W3 Stream-level soundness (toward the edit-automaton characterization)

`release_effect` is per-step. Its whole-stream lift below says the enforcer puts
text on the sink only at positions whose effect was releasing. Together with
`stream_transparency` (a valid all-`allow` stream passes through unchanged) this is
the soundness/transparency pair that characterizes the enforcer as a sound,
transparent edit automaton. The exact class placement (suppression + buffering give
it edit power beyond a truncation automaton) is the continuing W3 work. -/

/-- **`stream_soundness`.** Every releasing action in the output stream is witnessed
    by a releasing effect (`allow`/`downgrade`/`redact`) in the input stream: the
    enforcer never releases text the policy did not authorize somewhere. -/
theorem stream_soundness :
    ∀ (es : List Effect) (st : EState) (a : Action),
      a ∈ (steps st es).1 → a.releasesAny = true →
      ∃ e ∈ es, e = .allow ∨ e = .downgrade ∨ e = .redact
  | [], _, a, ha, _ => by simp [steps] at ha
  | e :: es, st, a, ha, hr => by
      simp only [steps] at ha
      rcases List.mem_cons.1 ha with rfl | hrest
      · obtain ⟨_, hcases⟩ := release_effect hr
        exact ⟨e, List.mem_cons.2 (Or.inl rfl), hcases⟩
      · obtain ⟨e', he', hc'⟩ := stream_soundness es (step st e).2 a hrest hr
        exact ⟨e', List.mem_cons.2 (Or.inr he'), hc'⟩

/-- Release payload class: `allow` releases the chunk **verbatim**;
    `downgrade`/`redact` release a **transformed** payload; other effects release
    nothing. Parameterizing `Emit` by payload (`Emit(x)` vs `Emit(δ(x))`). -/
inductive Payload where
  | verbatim | transformed
deriving DecidableEq, Repr

def emitPayload : Effect → Option Payload
  | .allow     => some .verbatim
  | .downgrade => some .transformed
  | .redact    => some .transformed
  | _          => none

/-- **`verbatim_release_needs_allow`.** The exact (untransformed) bytes of a chunk
    reach the sink only under `Allow`. Redact/Downgrade payload safety rests on the
    (unproven) transforms; the *original* bytes never escape except via `allow`. -/
theorem verbatim_release_needs_allow {e : Effect}
    (h : emitPayload e = some .verbatim) : e = .allow := by
  cases e <;> simp_all [emitPayload]

/-! ## §W3 (depth) Placing the enforcer in the edit-automaton hierarchy

The enforcer is a **sound, transparent suppression/edit automaton** in the
enforcement-monitor sense (Schneider; Ligatti, Bauer, Walker). The evidence,
assembled from the theorems above plus the three below:
* **sound**: `stream_soundness` (text is released only at authorized positions);
* **transparent**: `stream_transparency` (a valid all-`allow` stream passes unchanged);
* **non-inserting**: `steps_length` (exactly one action per input effect, so the
  monitor never fabricates output). This is what separates a suppression/edit
  automaton from an insertion automaton;
* **truncating**: `sealed_stream` (after a halt the whole suffix is suppressed);
* **edit power beyond truncation**: `buffer_then_approve_releases` (a `defer`red
  chunk is buffered, not decided, and a later approval releases it, which a pure
  truncation automaton cannot do).
The exact per-step release condition is the iff `step_releases_iff`. -/

/-- **`step_releases_iff`.** A step releases text iff the stream is live and the
    effect is releasing. The exact both-directions form of `release_effect`. -/
theorem step_releases_iff {st : EState} {e : Effect} :
    (step st e).1.releasesAny = true ↔
      st.halted = false ∧ (e = .allow ∨ e = .downgrade ∨ e = .redact) := by
  constructor
  · exact release_effect
  · rintro ⟨hns, rfl | rfl | rfl⟩ <;> simp [step, hns, Action.releasesAny]

/-- **`steps_length` (non-insertion).** The enforcer emits exactly one action per
    input effect; it never fabricates output. This places it below the insertion
    automata: it can only suppress and transform, never insert. -/
theorem steps_length (st : EState) (es : List Effect) :
    (steps st es).1.length = es.length := by
  induction es generalizing st with
  | nil => rfl
  | cons e es ih => simp only [steps, List.length_cons]; rw [ih (step st e).2]

/-- **`buffer_then_approve_releases` (edit power beyond truncation).** A `defer`red
    chunk is buffered rather than released or killed, and a later authorizing approval
    releases it. A truncation (halt-only) automaton cannot delay-then-release, so the
    enforcer is a genuine edit automaton, not merely a security/truncation automaton. -/
theorem buffer_then_approve_releases (st : EState) (hns : st.halted = false) :
    (step st .defer).1 = Action.buffer ∧
    (approve (step st .defer).2 .allow false).1 = Action.emit := by
  refine ⟨by simp [step, hns], ?_⟩
  simp [step, hns, approve, stepSeal]

/-! ## §W3 (separation) The enforcer is strictly beyond a truncation automaton

A security/truncation automaton (Schneider) enforces safety only by halting at a
bad prefix: once it suppresses an item it suppresses everything after, so
suppression is a *suffix*. `truncationShapedB` captures exactly those output
streams. Our enforcer instead DROPS an unauthorized chunk and CONTINUES, releasing
later authorized chunks. On `allow · deny · allow` it emits `emit · drop · emit`,
a release after a non-halting suppression, which is not truncation-shaped. So the
enforcer is strictly an *edit* automaton (suppress-and-resume), not merely a
truncation automaton: a genuine separation, not just a richer vocabulary. -/

/-- The output streams a truncation/security automaton can produce: once an action
    suppresses (releases nothing), every later action suppresses too. -/
def truncationShapedB : List Action → Bool
  | [] => true
  | a :: rest =>
      (if a.releasesAny then true else rest.all (fun b => !b.releasesAny)) && truncationShapedB rest

/-- The enforcer's output on `allow · deny · allow`, from the initial live state:
    it releases, suppresses the middle, then releases again. -/
theorem drop_then_resume :
    (steps { buffered := false, halted := false }
        [Effect.allow, Effect.deny, Effect.allow]).1
      = [Action.emit, Action.drop, Action.emit] := by rfl

/-- **`enforcer_beyond_truncation`.** There is an input whose enforced output no
    truncation automaton can produce (a release after a non-halting suppression).
    The enforcer is therefore strictly more expressive than a security/truncation
    automaton, which is the edit-automaton separation. -/
theorem enforcer_beyond_truncation :
    ∃ (es : List Effect) (s : EState), truncationShapedB (steps s es).1 = false :=
  ⟨[Effect.allow, Effect.deny, Effect.allow],
   { buffered := false, halted := false }, by rfl⟩

end ChaiProofs
