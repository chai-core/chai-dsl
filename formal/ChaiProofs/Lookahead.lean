import ChaiProofs.Decision

/-!
# k-lookahead atomic release (updated_plan §1.4)

The per-chunk emission calculus catches unsafe content at the first chunk whose
prefix trips a detector, but a secret split across a chunk boundary can leak its
already-released prefix. The **k-lookahead** variant holds a sliding window of up to
`k` chunks and releases the window's lead chunk only when every decision over the
window authorizes release. Then a substring contained within any `k` consecutive
chunks is never *partially* released: if any chunk in its window trips a detector,
the whole window is withheld.

This file mechanizes the atomicity core over the window's decisions. It reuses the
Buffer machinery: the window is exactly the deferred buffer of the emission
calculus, now bounded at `k`.
-/

namespace ChaiProofs

/-- Every decision over a window authorizes verbatim release. -/
def allAllow (w : List Effect) : Bool := w.all (fun e => decide (e = .allow))

/-- `allAllow` holds iff every chunk in the window decided `Allow`. -/
theorem allAllow_true_iff {w : List Effect} :
    allAllow w = true ↔ ∀ e ∈ w, e = .allow := by
  simp [allAllow]

/-- **`window_blocks`.** If any chunk in the window decides something other than
    `Allow`, the window does not all-authorize, so its lead chunk is withheld. A
    single tripped detector anywhere in the `k`-window blocks the whole window. -/
theorem window_blocks {w : List Effect} {e : Effect}
    (hmem : e ∈ w) (hne : e ≠ .allow) : allAllow w = false := by
  cases h : allAllow w with
  | false => rfl
  | true => exact absurd ((allAllow_true_iff.1 h) e hmem) hne

/-- The lead chunk of a window is released only when the window all-authorizes. -/
def released (w : List Effect) : Bool := allAllow w

/-- **`substring_atomic`.** A substring whose chunks lie within a single `k`-window:
    if any chunk in that window is unsafe (a non-`Allow` decision), the window is not
    released, so no part of the substring reaches the sink. Never partial. -/
theorem substring_atomic {w : List Effect} {e : Effect}
    (hmem : e ∈ w) (hne : e ≠ .allow) : released w = false := by
  unfold released; exact window_blocks hmem hne

/-- Conversely, a fully-clean window releases (transparency for the window). -/
theorem clean_window_releases {w : List Effect} (h : ∀ e ∈ w, e = .allow) :
    released w = true := by
  unfold released; exact allAllow_true_iff.2 h

end ChaiProofs
