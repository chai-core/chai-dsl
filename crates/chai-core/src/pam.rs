//! PAM-style guard combinator, safe order-independent variant.
//!
//! A guard is a stack of tagged sub-conditions that gates one rule's effect.
//! Two levels here. This decides pass/fail. The effect then resolves via the
//! deny-override lattice in `evaluator.rs`. The semantics are proven in
//! `formal/ChaiProofs/PamGuard.lean`. This module is the executable counterpart.
//! `tests/pam_guard.rs` checks the two agree via an exhaustive truth-table plus
//! the proof's invariants over random guards.
//!
//! A `sufficient` success never bypasses a mandatory check, so the verdict is the
//! order-independent formula
//! `(∃ gate) ∧ (∀ mandatory pass) ∧ (no sufficient ∨ some sufficient passes)`.

use crate::ast::{Expr, Value};
use crate::evaluator::Evaluator;

/// PAM control tag on a guard sub-condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    Required,
    Requisite,
    Sufficient,
    Optional,
}

impl Flag {
    /// Contributes to the verdict (everything but `optional`).
    pub fn is_gate(&self) -> bool {
        !matches!(self, Flag::Optional)
    }
    /// Must pass. `required` and `requisite` are verdict-identical here. They
    /// differ only operationally in real PAM, proven `required_requisite_same_class`.
    pub fn is_mandatory(&self) -> bool {
        matches!(self, Flag::Required | Flag::Requisite)
    }
    pub fn is_sufficient(&self) -> bool {
        matches!(self, Flag::Sufficient)
    }
}

/// Parse a PAM control tag; `None` for an unknown tag (caller fails closed).
pub fn parse_flag(s: &str) -> Option<Flag> {
    match s {
        "required" => Some(Flag::Required),
        "requisite" => Some(Flag::Requisite),
        "sufficient" => Some(Flag::Sufficient),
        "optional" => Some(Flag::Optional),
        _ => None,
    }
}

/// The guard verdict over already-evaluated `(tag, did-it-pass)` pairs.
/// Faithful to `ChaiProofs.passes`.
pub fn passes(stack: &[(Flag, bool)]) -> bool {
    let has_gate = stack.iter().any(|(f, _)| f.is_gate());
    let mandatory_all = stack.iter().all(|(f, ok)| !f.is_mandatory() || *ok);
    let sufficient_ok = !stack.iter().any(|(f, _)| f.is_sufficient())
        || stack.iter().any(|(f, ok)| f.is_sufficient() && *ok);
    has_gate && mandatory_all && sufficient_ok
}

/// Evaluate a guard of `(tag, condition)` against a context. Each condition is
/// evaluated to a bool, fail-closed (an error or a non-bool result counts as
/// `false`), then combined by [`passes`].
pub fn eval_guard(stack: &[(Flag, Expr)], evaluator: &Evaluator<'_>) -> bool {
    let resolved: Vec<(Flag, bool)> = stack
        .iter()
        .map(|(flag, cond)| (*flag, matches!(evaluator.eval_expr(cond), Ok(Value::Bool(true)))))
        .collect();
    passes(&resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::ChaiProgram;
    use crate::entity::EntityStore;
    use crate::parser::parse_chai;
    use std::collections::HashMap;

    // Unit, tag parsing.

    #[test]
    fn parse_flag_known_and_unknown() {
        assert_eq!(parse_flag("required"), Some(Flag::Required));
        assert_eq!(parse_flag("requisite"), Some(Flag::Requisite));
        assert_eq!(parse_flag("sufficient"), Some(Flag::Sufficient));
        assert_eq!(parse_flag("optional"), Some(Flag::Optional));
        assert_eq!(parse_flag("REQUIRED"), None); // case-sensitive on purpose
        assert_eq!(parse_flag("permit"), None);
        assert_eq!(parse_flag(""), None);
    }

    // Unit, the verdict truth table by hand.

    #[test]
    fn passes_truth_table() {
        use Flag::*;
        assert!(!passes(&[])); // empty -> deny (fail-closed)
        assert!(!passes(&[(Optional, true)])); // all-optional -> deny, no gate
        assert!(passes(&[(Required, true)]));
        assert!(!passes(&[(Required, false)]));
        assert!(passes(&[(Requisite, true)]));
        assert!(!passes(&[(Requisite, false)]));
        assert!(passes(&[(Sufficient, true)]));
        assert!(!passes(&[(Sufficient, false)])); // sufficient present, none pass
        // A present sufficient OR-group must be satisfied. A passing required does
        // not carry it past a failing, otherwise-empty sufficient group.
        assert!(!passes(&[(Required, true), (Sufficient, false)]));
        assert!(!passes(&[(Required, false), (Sufficient, true)])); // mandatory fail dominates
        assert!(passes(&[(Required, true), (Sufficient, true)]));
        // required + an OR group where one alternative passes
        assert!(passes(&[(Required, true), (Sufficient, false), (Sufficient, true)]));
        assert!(!passes(&[(Required, true), (Sufficient, false), (Sufficient, false)]));
    }

    // Unit and integration, real condition evaluation, fail-closed.

    fn cond(src: &str) -> Expr {
        match parse_chai(&format!("permit when {src}\n")).unwrap() {
            ChaiProgram::SingleLineRules(r) => r[0].condition.clone().unwrap(),
            _ => panic!("expected single-line rule"),
        }
    }

    fn ctx_pii(pii: f64) -> HashMap<String, Value> {
        let mut dlp = HashMap::new();
        dlp.insert("pii".to_string(), Value::Float(pii));
        let mut c = HashMap::new();
        c.insert("dlp_facts".to_string(), Value::Dict(dlp));
        c
    }

    #[test]
    fn eval_guard_required_and_sufficient() {
        let store = EntityStore::new();
        let ev = Evaluator::new(&store).with_context(ctx_pii(0.6));
        // required pii < 0.9 (true), sufficient pii > 0.5 (true), so pass
        let stack = vec![
            (Flag::Required, cond("dlp_facts.pii < 0.9")),
            (Flag::Sufficient, cond("dlp_facts.pii > 0.5")),
        ];
        assert!(eval_guard(&stack, &ev));
    }

    #[test]
    fn eval_guard_failed_required_denies() {
        let store = EntityStore::new();
        let ev = Evaluator::new(&store).with_context(ctx_pii(0.95));
        // required pii < 0.9 is false at 0.95, deny regardless of sufficient
        let stack = vec![
            (Flag::Required, cond("dlp_facts.pii < 0.9")),
            (Flag::Sufficient, cond("dlp_facts.pii > 0.5")),
        ];
        assert!(!eval_guard(&stack, &ev));
    }

    #[test]
    fn eval_guard_errored_condition_is_fail_closed() {
        let store = EntityStore::new();
        let ev = Evaluator::new(&store).with_context(ctx_pii(0.1));
        // a type-error condition must count as false (fail-closed), denying the
        // mandatory check. Never panic, never silently pass.
        let stack = vec![(Flag::Required, cond("dlp_facts.pii > \"oops\""))];
        assert!(!eval_guard(&stack, &ev));
    }
}
