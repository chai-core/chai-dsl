//! Monotone session budgets (updated_plan §3.3).
//!
//! Session state is a join-semilattice a guard may read, e.g.
//! `forbid when session.spend + args.amount > session.cap`. The security-relevant
//! quantity is cumulative *spend*, which only grows. The runtime maintains it and
//! charges a release only when it stays within the cap, so the released spend never
//! exceeds the cap. This mirrors `formal/ChaiProofs/Budget.lean` (`charge`,
//! `spend_bounded`): `try_charge` is the Lean `charge`, and repeated calls keep
//! `spend <= cap` by construction.

use chai_core::ast::Value;
use std::collections::HashMap;

/// A monotone per-session spend budget.
#[derive(Debug, Clone)]
pub struct SessionBudget {
    spend: i64,
    cap: i64,
}

impl SessionBudget {
    pub fn new(cap: i64) -> Self {
        SessionBudget { spend: 0, cap }
    }

    pub fn spend(&self) -> i64 {
        self.spend
    }

    pub fn cap(&self) -> i64 {
        self.cap
    }

    /// Inject `session.spend` and `session.cap` into an eval context so a guard
    /// like `forbid when session.spend + args.amount > session.cap` can read them.
    pub fn inject(&self, ctx: &mut HashMap<String, Value>) {
        let mut s = HashMap::new();
        s.insert("spend".to_string(), Value::Int(self.spend));
        s.insert("cap".to_string(), Value::Int(self.cap));
        ctx.insert("session".to_string(), Value::Dict(s));
    }

    /// Release-and-charge: add `amount` to the spend iff it stays within the cap.
    /// Returns `true` if charged (the release is within budget), `false` if it would
    /// breach the cap (denied; spend unchanged). Negative amounts are refused, since
    /// spend only grows. This is the Lean `charge`; iterating it keeps
    /// `spend() <= cap()` (`Budget.lean::spend_bounded`).
    pub fn try_charge(&mut self, amount: i64) -> bool {
        if amount < 0 {
            return false;
        }
        match self.spend.checked_add(amount) {
            Some(next) if next <= self.cap => {
                self.spend = next;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spend_never_exceeds_cap() {
        let mut b = SessionBudget::new(100);
        assert!(b.try_charge(60)); // 60
        assert!(!b.try_charge(60)); // would be 120 > 100 -> denied, spend unchanged
        assert_eq!(b.spend(), 60);
        assert!(b.try_charge(40)); // 100 exactly
        assert_eq!(b.spend(), 100);
        assert!(!b.try_charge(1)); // 101 > 100 -> denied
        assert!(!b.try_charge(-5)); // spend only grows
        assert!(b.spend() <= b.cap()); // the spend_bounded invariant
    }
}
