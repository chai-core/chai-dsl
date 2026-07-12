//! Static policy analysis. Detect rules that can never fire (provably
//! unsatisfiable conditions), e.g. `pii > 0.5 and pii < 0.3`.
//!
//! Sound under-approximation. A rule is flagged only when we can prove the
//! condition unsatisfiable, via interval reasoning over conjunctions of numeric
//! comparisons and boolean literals. Anything we can't decide is assumed
//! satisfiable, so this never reports a false dead rule.
//!
//! Full SMT-grade analysis (equivalence, permissiveness comparison) needs a
//! solver and lives behind the `smt` feature. This covers the common
//! contradiction/dead-rule case in pure Rust, with tests.

use crate::ast::{BinaryOp, ChaiProgram, Expr, Value};
use std::collections::HashMap;

/// IDs (or `<anonymous>`) of rules whose condition is provably unsatisfiable.
pub fn unreachable_rules(program: &ChaiProgram) -> Vec<String> {
    let rules = match program {
        ChaiProgram::SingleLineRules(r) => r.as_slice(),
        ChaiProgram::StructuredRules(p) => p.rules.as_slice(),
        ChaiProgram::HierarchicalConfig(c) => c.rules.as_slice(),
    };
    rules
        .iter()
        .filter(|r| r.condition.as_ref().map_or(false, |c| !satisfiable(c)))
        .map(|r| r.id.clone().unwrap_or_else(|| "<anonymous>".into()))
        .collect()
}

/// Conservative satisfiability. Returns `false` only when provably unsatisfiable.
pub fn satisfiable(e: &Expr) -> bool {
    match e {
        Expr::Literal(Value::Bool(b)) => *b,
        // `true`/`false` parse as bare identifiers. The evaluator treats them as
        // boolean constants, so handle them here too.
        Expr::Variable(v) if v == "false" => false,
        Expr::Variable(v) if v == "true" => true,
        Expr::BinaryOp { left, op: BinaryOp::Or, right } => satisfiable(left) || satisfiable(right),
        Expr::BinaryOp { op: BinaryOp::And, .. } => {
            let mut conj = Vec::new();
            flatten_and(e, &mut conj);
            conjunction_feasible(&conj)
        }
        // A lone comparison, or anything else, is assumed satisfiable.
        _ => true,
    }
}

fn flatten_and<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
    if let Expr::BinaryOp { left, op: BinaryOp::And, right } = e {
        flatten_and(left, out);
        flatten_and(right, out);
    } else {
        out.push(e);
    }
}

/// Interval over a numeric path. [lo, hi] with inclusivity flags.
#[derive(Clone)]
struct Interval {
    lo: f64,
    lo_incl: bool,
    hi: f64,
    hi_incl: bool,
}

impl Interval {
    fn full() -> Self {
        Interval { lo: f64::NEG_INFINITY, lo_incl: false, hi: f64::INFINITY, hi_incl: false }
    }
    fn empty(&self) -> bool {
        self.lo > self.hi || (self.lo == self.hi && !(self.lo_incl && self.hi_incl))
    }
    fn raise_lo(&mut self, lo: f64, incl: bool) {
        if lo > self.lo || (lo == self.lo && !incl) {
            self.lo = lo;
            self.lo_incl = incl;
        }
    }
    fn lower_hi(&mut self, hi: f64, incl: bool) {
        if hi < self.hi || (hi == self.hi && !incl) {
            self.hi = hi;
            self.hi_incl = incl;
        }
    }
}

/// True unless the conjuncts are provably contradictory.
fn conjunction_feasible(conj: &[&Expr]) -> bool {
    let mut intervals: HashMap<String, Interval> = HashMap::new();

    for &c in conj {
        match c {
            Expr::Literal(Value::Bool(false)) => return false,
            Expr::Variable(v) if v == "false" => return false,
            Expr::Literal(Value::Bool(true)) => {}
            Expr::Variable(v) if v == "true" => {}
            // A nested OR (or anything non-trivial) is satisfiable on its own. It
            // adds no hard numeric constraint, so skip it. Conservative.
            Expr::BinaryOp { left, op, right } => {
                if let (Some((path, _)), Some(n)) = (path_of(left), number_of(right)) {
                    let iv = intervals.entry(path).or_insert_with(Interval::full);
                    match op {
                        BinaryOp::Gt => iv.raise_lo(n, false),
                        BinaryOp::Ge => iv.raise_lo(n, true),
                        BinaryOp::Lt => iv.lower_hi(n, false),
                        BinaryOp::Le => iv.lower_hi(n, true),
                        BinaryOp::Eq => {
                            iv.raise_lo(n, true);
                            iv.lower_hi(n, true);
                        }
                        _ => {}
                    }
                } else if let (Some(n), Some((path, _))) = (number_of(left), path_of(right)) {
                    // mirrored form, const OP path
                    let iv = intervals.entry(path).or_insert_with(Interval::full);
                    match op {
                        BinaryOp::Lt => iv.raise_lo(n, false),
                        BinaryOp::Le => iv.raise_lo(n, true),
                        BinaryOp::Gt => iv.lower_hi(n, false),
                        BinaryOp::Ge => iv.lower_hi(n, true),
                        BinaryOp::Eq => {
                            iv.raise_lo(n, true);
                            iv.lower_hi(n, true);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    !intervals.values().any(|iv| iv.empty())
}

/// Canonical dotted path of a field-access or variable chain, e.g. "dlp_facts.pii".
fn path_of(e: &Expr) -> Option<(String, ())> {
    match e {
        Expr::Variable(v) => Some((v.clone(), ())),
        Expr::FieldAccess { object, field } => {
            let (base, _) = path_of(object)?;
            Some((format!("{base}.{field}"), ()))
        }
        _ => None,
    }
}

fn number_of(e: &Expr) -> Option<f64> {
    match e {
        Expr::Literal(Value::Int(i)) => Some(*i as f64),
        Expr::Literal(Value::Float(f)) => Some(*f),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_chai;

    fn dead(src: &str) -> Vec<String> {
        unreachable_rules(&parse_chai(src).unwrap())
    }

    #[test]
    fn detects_contradictory_numeric_conjunction() {
        assert_eq!(dead("@id(\"x\") permit when dlp_facts.pii > 0.5 and dlp_facts.pii < 0.3\n"), vec!["x".to_string()]);
        // touching bounds with a strict inequality is also empty
        assert_eq!(dead("@id(\"y\") permit when a.b >= 5 and a.b < 5\n"), vec!["y".to_string()]);
    }

    #[test]
    fn detects_literal_false() {
        assert_eq!(dead("@id(\"f\") forbid when false\n"), vec!["f".to_string()]);
    }

    #[test]
    fn keeps_satisfiable_rules() {
        assert!(dead("permit when dlp_facts.pii > 0.5 and dlp_facts.pii < 0.8\n").is_empty());
        assert!(dead("permit when true\n").is_empty());
        // an OR makes the rule satisfiable even when one side is contradictory
        assert!(dead("permit when (a.b > 5 and a.b < 3) or a.b == 1\n").is_empty());
        // different paths never contradict each other
        assert!(dead("permit when a.b > 5 and a.c < 3\n").is_empty());
    }
}
