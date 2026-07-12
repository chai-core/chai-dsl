//! Emission: the streaming enforcement runtime.
//!
//! Implements the Streaming Enforcement Protocol from the three-layer spec.
//! For each output prefix chunk, given its alignment facts `F_t`, ESP produces a
//! decision `d_t`, and this runtime executes it.
//!   ALLOW -> emit, DEFER -> buffer, REDACT -> transform+emit, DENY -> drop,
//!   REQUIRE_HUMAN -> halt, DOWNGRADE -> emit reduced.
//!
//! Facts are injected here. The AFC layer computes them elsewhere. This module
//! is only the deterministic control half.
//!
//! Invariants enforced:
//!   * Fail-closed. Nothing is emitted unless a decision authorized it. An
//!     evaluation error or a deny yields no output.
//!   * Deterministic. Same (policy, facts) gives the same action.
//!   * Auditable. Every step's Decision is retained in `history`.

use crate::ast::{ChaiProgram, Decision, Effect, Value};
use crate::entity::EntityStore;
use crate::evaluator::eval_with_store;
use std::collections::HashMap;

/// What the runtime does with a prefix chunk.
#[derive(Debug, Clone, PartialEq)]
pub enum EmitAction {
    /// Release this text to the sink (may include previously-buffered text).
    Emit(String),
    /// Hold the chunk; nothing released yet.
    Buffer,
    /// Release the rewritten text.
    Redact(String),
    /// Drop the chunk (and any buffered prefix); nothing released.
    Drop,
    /// Halt the stream pending human approval; nothing released.
    RequireHuman,
}

pub struct EmissionEnforcer<'a> {
    program: &'a ChaiProgram,
    store: &'a EntityStore,
    /// Static request bindings (subject `s`, object `o`) merged with per-step facts.
    base_context: HashMap<String, Value>,
    /// Deferred prefix awaiting a decision.
    buffer: String,
    /// Audit trail. One Decision per step.
    history: Vec<Decision>,
    /// Once a halting decision (REQUIRE_HUMAN) fires, the stream is sealed.
    halted: bool,
}

impl<'a> EmissionEnforcer<'a> {
    pub fn new(
        program: &'a ChaiProgram,
        store: &'a EntityStore,
        base_context: HashMap<String, Value>,
    ) -> Self {
        EmissionEnforcer {
            program,
            store,
            base_context,
            buffer: String::new(),
            history: Vec::new(),
            halted: false,
        }
    }

    /// Process one prefix chunk together with its alignment facts.
    pub fn step(&mut self, chunk: &str, facts: HashMap<String, Value>) -> EmitAction {
        // Once halted, emit nothing further. Fail-closed.
        if self.halted {
            return EmitAction::Drop;
        }

        let mut ctx = self.base_context.clone();
        for (k, v) in facts {
            ctx.insert(k, v);
        }

        // An evaluation error becomes a deny. Fail-closed.
        let decision = eval_with_store(self.program, ctx, self.store)
            .unwrap_or_else(|e| fail_closed_deny(format!("eval error: {e}")));
        let effect = decision.effect.clone();
        // Seal-on-presence: seal whenever a require_human rule was among the
        // outcomes, regardless of which effect won the join. A chunk that trips
        // both `deny` (winning verdict) and `require_human` is dropped *and* seals
        // the stream for review, so more-alarming evidence never yields a weaker
        // stream-level response than `require_human` alone would.
        let seal = matches!(effect, Effect::RequireHuman) || decision.require_human_present;
        let transforms = decision.transforms.clone();
        self.history.push(decision);

        let action = match effect {
            // Releasing effects apply the *accumulated* transform set (all matched
            // releasing rules at-or-below the verdict), so redact(SSN)+downgrade
            // (labels) apply both. The action label follows the verdict (Redact
            // rewrites; Allow/Downgrade emit).
            Effect::Allow | Effect::Downgrade | Effect::Redact => {
                let combined = format!("{}{}", self.buffer, chunk);
                self.buffer.clear();
                release_action(effect, &combined, &transforms)
            }
            Effect::Defer => {
                self.buffer.push_str(chunk);
                EmitAction::Buffer
            }
            // A deny drops the current chunk AND the unapproved buffer. The
            // prefix so far is deemed unsafe. Fail-closed.
            Effect::Deny | Effect::Forbid => {
                self.buffer.clear();
                EmitAction::Drop
            }
            Effect::RequireHuman => EmitAction::RequireHuman,
        };

        if seal {
            self.halted = true;
        }
        action
    }

    /// Human-in-the-loop release of deferred content: the **Approve transition**.
    /// Re-decide the buffered prefix under new facts `F'` (typically carrying an
    /// attested approval fact) and release it only if that re-decision authorizes
    /// release. A buffered release still requires an authorizing decision, now on
    /// the approval facts, so `defer` is no longer a delayed drop: an approved
    /// buffer is emitted, an unapproved one is held or dropped, fail-closed. A
    /// sealed stream, or an empty buffer, approves nothing.
    ///
    /// The effect→action mapping mirrors `step` (with the buffer as the payload
    /// source), so the same fail-closed release invariant holds: text reaches the
    /// sink only under a releasing effect (`allow`/`downgrade`/`redact`).
    pub fn approve(&mut self, facts: HashMap<String, Value>) -> EmitAction {
        if self.halted || self.buffer.is_empty() {
            return EmitAction::Drop;
        }

        let mut ctx = self.base_context.clone();
        for (k, v) in facts {
            ctx.insert(k, v);
        }

        let decision = eval_with_store(self.program, ctx, self.store)
            .unwrap_or_else(|e| fail_closed_deny(format!("approve eval error: {e}")));
        let effect = decision.effect.clone();
        let seal = matches!(effect, Effect::RequireHuman) || decision.require_human_present;
        let transforms = decision.transforms.clone();
        self.history.push(decision);

        let action = match effect {
            // Authorizing re-decision: release the buffered content with the full
            // accumulated transform set applied.
            Effect::Allow | Effect::Downgrade | Effect::Redact => {
                let combined = std::mem::take(&mut self.buffer);
                release_action(effect, &combined, &transforms)
            }
            // Still deferred: keep the buffer for a later approval or end-of-stream drop.
            Effect::Defer => EmitAction::Buffer,
            // Denied or halted on re-decision: the buffered content is not released.
            Effect::Deny | Effect::Forbid => {
                self.buffer.clear();
                EmitAction::Drop
            }
            Effect::RequireHuman => EmitAction::RequireHuman,
        };

        if seal {
            self.halted = true;
        }
        action
    }

    /// Flush at end-of-stream. Any text still buffered was never approved, so
    /// drop it. Fail-closed. By invariant nothing is released.
    pub fn finish(&mut self) -> EmitAction {
        if self.buffer.is_empty() {
            EmitAction::Drop
        } else {
            // Deferred content that was never approved gets dropped.
            self.buffer.clear();
            EmitAction::Drop
        }
    }

    /// Full audit trail. One decision per step.
    pub fn history(&self) -> &[Decision] {
        &self.history
    }

    pub fn is_halted(&self) -> bool {
        self.halted
    }
}

/// The canonical fail-closed decision: a Deny tagged `fail_closed`. Shared by the
/// emission runtime and the MCP wire layer so the two cannot drift.
pub fn fail_closed_deny(reason: String) -> Decision {
    Decision {
        effect: Effect::Deny,
        reason,
        reason_codes: vec!["fail_closed".to_string()],
        obligations: Vec::new(),
        rule_trace: Vec::new(),
        errors: Vec::new(),
        require_human_present: false,
        transforms: Vec::new(),
        metadata: HashMap::new(),
    }
}

/// Turn a releasing verdict plus the accumulated transform set into an action.
/// The transforms are applied in order (Downgrade before Redact); a Redact
/// transform that localizes no span fails closed to `Drop`. The action label
/// follows the verdict: a `Redact` verdict yields `Redact(..)`, `Allow`/`Downgrade`
/// yield `Emit(..)`.
fn release_action(verdict: Effect, text: &str, transforms: &[Effect]) -> EmitAction {
    match apply_transforms(text, transforms) {
        Some(out) => {
            if verdict == Effect::Redact {
                EmitAction::Redact(out)
            } else {
                EmitAction::Emit(out)
            }
        }
        // A redaction that removes nothing is not a redaction: fail-closed drop.
        None => EmitAction::Drop,
    }
}

/// Apply the accumulated release transforms in order. Returns `None` if a Redact
/// transform localizes no span (fail-closed). `Allow` (identity) is never present.
fn apply_transforms(text: &str, transforms: &[Effect]) -> Option<String> {
    let mut out = text.to_string();
    for t in transforms {
        match t {
            Effect::Downgrade => out = downgrade(&out),
            Effect::Redact => {
                let masked = redact(&out);
                if masked == out {
                    return None;
                }
                out = masked;
            }
            _ => {}
        }
    }
    Some(out)
}

/// Span-masking redaction obligation. Mask the PII spans, keep everything else.
/// The non-sensitive content survives. Patterns are applied in order. Emails go
/// before phone so an email's digits aren't mis-masked. Detector-supplied spans
/// (e.g. Presidio start/end) can extend this. These structured patterns are the
/// always-on baseline.
fn redact(text: &str) -> String {
    use std::sync::OnceLock;
    static PATTERNS: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        let p: &[(&str, &str)] = &[
            (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "EMAIL"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
            (r"\b(?:\d[ -]?){13,16}\b", "CARD"),
            (r"\b\d{3}[-.]\d{3}[-.]\d{4}\b", "PHONE"),
            (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "IP"),
        ];
        p.iter().map(|(re, label)| (regex::Regex::new(re).unwrap(), *label)).collect()
    });
    let mut out = text.to_string();
    for (re, label) in patterns {
        out = re.replace_all(&out, format!("[{label}]")).into_owned();
    }
    out
}

fn downgrade(text: &str) -> String {
    format!("{text} [downgraded]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_chai;

    fn facts(pii: f64) -> HashMap<String, Value> {
        let mut dlp = HashMap::new();
        dlp.insert("pii".to_string(), Value::Float(pii));
        let mut f = HashMap::new();
        f.insert("dlp_facts".to_string(), Value::Dict(dlp));
        f
    }

    #[test]
    fn allow_then_defer_then_deny_is_fail_closed() {
        // Allow while pii is low, defer in the middle band, deny when high.
        let policy = "\
deny when dlp_facts.pii > 0.8
defer when dlp_facts.pii > 0.4
permit when dlp_facts.pii < 0.4
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

        assert_eq!(enf.step("hello ", facts(0.1)), EmitAction::Emit("hello ".into()));
        assert_eq!(enf.step("my ", facts(0.5)), EmitAction::Buffer); // deferred
        assert_eq!(enf.step("ssn", facts(0.9)), EmitAction::Drop); // deny drops buffer+chunk

        // Nothing unsafe was ever emitted. 3 decisions recorded.
        assert_eq!(enf.history().len(), 3);
    }

    #[test]
    fn redact_masks_pii_spans_keeps_rest() {
        // The non-sensitive text survives. Only the PII spans are masked.
        let out = redact("contact alice@example.com or 123-45-6789 about order 42");
        assert!(out.contains("contact"));
        assert!(out.contains("about order 42"));
        assert!(!out.contains("alice@example.com"));
        assert!(!out.contains("123-45-6789"));
        assert!(out.contains("[EMAIL]") && out.contains("[SSN]"));
    }

    #[test]
    fn redact_with_no_maskable_span_is_fail_closed() {
        // ESP says redact, but the chunk has PII *words* and no PII *value* the
        // span-masker can localize. Emitting it verbatim would be fail-open, so
        // the chunk is dropped. (A real SSN/email would mask and Redact instead.)
        let program = parse_chai("redact when dlp_facts.pii > 0.4\n").unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());
        // "the ssn is 123": no \d{3}-\d{2}-\d{4}, nothing to mask -> Drop.
        assert_eq!(enf.step("the ssn is 123", facts(0.9)), EmitAction::Drop);
        // A real SSN localizes a span, so it masks and releases the rewrite.
        assert_eq!(
            enf.step("ssn 123-45-6789", facts(0.9)),
            EmitAction::Redact("ssn [SSN]".into())
        );
    }

    #[test]
    fn redact_masks_injected_pii_across_random_surroundings() {
        // Property test (deterministic generator, no dependency): for random benign
        // surroundings with one injected PII value, the masker removes the value
        // verbatim, emits its label, and preserves the surrounding words. This is the
        // masker-correctness property behind the `Redact` release payload.
        struct Lcg(u64);
        impl Lcg {
            fn below(&mut self, n: u64) -> u64 {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (self.0 >> 33) % n
            }
        }
        const FILLER: &[&str] = &[
            "contact", "about", "the", "order", "please", "review", "note", "hello",
            "regards", "team", "for", "your", "records",
        ];
        let mut rng = Lcg(0xDEAD_BEEF_1234_5678);
        for _ in 0..2000 {
            let (value, label): (String, &str) = match rng.below(5) {
                0 => (format!("user{}@example.com", rng.below(1000)), "EMAIL"),
                1 => (
                    format!("{:03}-{:02}-{:04}", rng.below(1000), rng.below(100), rng.below(10000)),
                    "SSN",
                ),
                2 => ("4111111111111111".to_string(), "CARD"),
                3 => (
                    format!("{:03}-{:03}-{:04}", rng.below(1000), rng.below(1000), rng.below(10000)),
                    "PHONE",
                ),
                _ => (
                    format!(
                        "{}.{}.{}.{}",
                        rng.below(256),
                        rng.below(256),
                        rng.below(256),
                        rng.below(256)
                    ),
                    "IP",
                ),
            };
            let n_words = rng.below(5) as usize;
            let mut words: Vec<String> = (0..n_words)
                .map(|_| FILLER[rng.below(FILLER.len() as u64) as usize].to_string())
                .collect();
            let pos = rng.below((words.len() + 1) as u64) as usize;
            words.insert(pos, value.clone());
            let text = words.join(" ");

            let out = redact(&text);
            assert!(!out.contains(&value), "PII value leaked: {value:?} in {out:?}");
            assert!(out.contains(&format!("[{label}]")), "label [{label}] missing in {out:?}");
            for w in &words {
                if *w != value {
                    assert!(out.contains(w), "benign word {w:?} lost in {out:?}");
                }
            }
        }
    }

    /// Build a `{"<ns>": {"<key>": <val>}}` fact bundle.
    fn ns_facts(ns: &str, key: &str, val: Value) -> HashMap<String, Value> {
        let mut inner = HashMap::new();
        inner.insert(key.to_string(), val);
        let mut f = HashMap::new();
        f.insert(ns.to_string(), Value::Dict(inner));
        f
    }

    #[test]
    fn deny_plus_require_human_drops_and_seals() {
        // §1.2 seal-on-presence. A chunk that trips BOTH deny (winning verdict)
        // and require_human must drop the chunk AND seal the stream, so more
        // evidence never yields a weaker stream-level response.
        let policy = "\
deny when dlp_facts.pii > 0.8
require_human when safety_facts.harm > 0.5
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

        let mut f = ns_facts("dlp_facts", "pii", Value::Float(0.9));
        f.insert("safety_facts".into(), {
            let mut h = HashMap::new();
            h.insert("harm".into(), Value::Float(0.9));
            Value::Dict(h)
        });

        // Deny wins the verdict, so the chunk drops; require_human presence seals.
        assert_eq!(enf.step("secret harm", f), EmitAction::Drop);
        assert!(enf.is_halted(), "require_human presence must seal even when deny wins");
        // A sealed stream emits nothing further.
        assert_eq!(enf.step("more", HashMap::new()), EmitAction::Drop);
    }

    #[test]
    fn approve_releases_buffered_content() {
        // §1.3 Approve transition. A deferred chunk is released only under a
        // re-decision (new facts) whose verdict authorizes release.
        let policy = "\
permit when review.stage == \"approved\"
defer when review.stage == \"hold\"
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

        // Streaming: stage=hold -> defer -> buffer, nothing released.
        assert_eq!(
            enf.step("draft answer", ns_facts("review", "stage", Value::String("hold".into()))),
            EmitAction::Buffer
        );
        // Approve with an authorizing re-decision -> the buffered text is emitted.
        assert_eq!(
            enf.approve(ns_facts("review", "stage", Value::String("approved".into()))),
            EmitAction::Emit("draft answer".into())
        );
        // Buffer is now consumed; end-of-stream releases nothing.
        assert_eq!(enf.finish(), EmitAction::Drop);
    }

    #[test]
    fn approve_without_authorization_does_not_release() {
        // An unapproved re-decision keeps the buffer (still deferred); a later
        // finish drops it. Fail-closed: nothing leaks without authorization.
        let policy = "\
permit when review.stage == \"approved\"
defer when review.stage == \"hold\"
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

        assert_eq!(
            enf.step("draft", ns_facts("review", "stage", Value::String("hold".into()))),
            EmitAction::Buffer
        );
        // Re-decision still `hold` -> not authorized -> nothing released.
        assert_eq!(
            enf.approve(ns_facts("review", "stage", Value::String("hold".into()))),
            EmitAction::Buffer
        );
        // Never approved -> dropped at end of stream.
        assert_eq!(enf.finish(), EmitAction::Drop);
    }

    #[test]
    fn approve_after_seal_releases_nothing() {
        // Once the stream is sealed (require_human), the Approve transition must
        // release nothing, even under an authorizing re-decision. Fail-closed.
        let policy = "\
require_human when review.stage == \"escalate\"
defer when review.stage == \"hold\"
permit when review.stage == \"approved\"
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

        assert_eq!(
            enf.step("draft", ns_facts("review", "stage", Value::String("hold".into()))),
            EmitAction::Buffer
        );
        assert_eq!(
            enf.step("x", ns_facts("review", "stage", Value::String("escalate".into()))),
            EmitAction::RequireHuman
        );
        assert!(enf.is_halted());
        // Authorizing facts cannot un-seal the stream.
        assert_eq!(
            enf.approve(ns_facts("review", "stage", Value::String("approved".into()))),
            EmitAction::Drop
        );
        assert_eq!(enf.finish(), EmitAction::Drop);
    }

    #[test]
    fn approve_redact_with_no_maskable_span_drops_and_consumes_buffer() {
        // A redact re-decision that localizes nothing is fail-closed (drop), and it
        // still consumes the buffer so a later approve cannot release the stale text.
        let policy = "\
redact when review.stage == \"mask\"
defer when review.stage == \"hold\"
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

        assert_eq!(
            enf.step("the ssn is 123", ns_facts("review", "stage", Value::String("hold".into()))),
            EmitAction::Buffer
        );
        // No \d{3}-\d{2}-\d{4} to mask -> redact drops rather than release verbatim.
        assert_eq!(
            enf.approve(ns_facts("review", "stage", Value::String("mask".into()))),
            EmitAction::Drop
        );
        // Buffer was consumed by the drop; nothing lingers for a later approve/finish.
        assert_eq!(
            enf.approve(ns_facts("review", "stage", Value::String("mask".into()))),
            EmitAction::Drop
        );
        assert_eq!(enf.finish(), EmitAction::Drop);
    }

    #[test]
    fn approve_deny_re_decision_clears_buffer() {
        // A deny re-decision drops the buffered content and clears it. Fail-closed.
        let policy = "\
deny when review.stage == \"block\"
defer when review.stage == \"hold\"
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

        assert_eq!(
            enf.step("secret", ns_facts("review", "stage", Value::String("hold".into()))),
            EmitAction::Buffer
        );
        assert_eq!(
            enf.approve(ns_facts("review", "stage", Value::String("block".into()))),
            EmitAction::Drop
        );
        assert_eq!(enf.finish(), EmitAction::Drop);
    }

    #[test]
    fn redact_and_downgrade_both_apply_to_release() {
        // §3.1 obligation accumulation. A chunk matching BOTH redact (SSN) and
        // downgrade (labels) must have both transforms applied to the release, not
        // just the winning redact. Under the old code the downgrade was silently
        // dropped and labelled text escaped.
        let policy = "\
redact    when dlp_facts.pii > 0.4
downgrade when label.secret == true
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

        let mut f = ns_facts("dlp_facts", "pii", Value::Float(0.9));
        f.insert("label".into(), {
            let mut h = HashMap::new();
            h.insert("secret".into(), Value::Bool(true));
            Value::Dict(h)
        });

        // Redact wins the verdict; the transform set is [Downgrade, Redact].
        match enf.step("ssn 123-45-6789", f) {
            EmitAction::Redact(out) => {
                assert!(out.contains("[SSN]"), "SSN must be masked: {out}");
                assert!(out.contains("[downgraded]"), "downgrade must also apply: {out}");
                assert!(!out.contains("123-45-6789"), "raw SSN must not escape: {out}");
            }
            other => panic!("expected Redact with both transforms, got {other:?}"),
        }
        // The winning decision records both transforms in order.
        assert_eq!(enf.history()[0].transforms, vec![Effect::Downgrade, Effect::Redact]);
    }

    #[test]
    fn error_is_fail_closed_not_emit() {
        // A type-error condition must never produce an Emit.
        let program = parse_chai("permit when dlp_facts.pii > \"oops\"\n").unwrap();
        let store = EntityStore::new();
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());
        let action = enf.step("text", facts(0.1));
        assert_eq!(action, EmitAction::Drop);
        assert!(!enf.history()[0].errors.is_empty());
    }
}
