//! SMT-backed policy analysis (feature = `smt`, needs libz3).
//!
//! Encodes a policy condition into linear real arithmetic plus booleans and
//! asks z3. The pure-Rust `analysis` module is a sound under-approximation over
//! conjunctions of intervals. This is sound and complete over the encoded
//! fragment. That fragment is boolean combinations (`and`/`or`/`not`) of:
//!   - numeric comparisons `< <= > >= == !=` over linear/polynomial real
//!     arithmetic (`+ - *`), so `a.score >= 0.8`, `a.pii + a.harm > 1.0`, and
//!     `a.x > a.y` are all in-fragment;
//!   - boolean atoms (`flag`, `flag == true`);
//!   - entity/string equality (`principal == User::"x"`, `tag == "secret"`),
//!     modelled as equality over an interned, open-world integer domain.
//! Completeness over that fragment lets it decide things interval reasoning
//! cannot: OR-simplification, negation equivalence, cross-bound implication,
//! entity-scope disjointness.
//!
//! Anything outside it (methods, list/`in` terms, ordering of entities) makes
//! the encoder bail and the analysis return `None` (unknown). It never returns
//! a wrong answer.

use crate::ast::{BinaryOp, Expr, UnaryOp, Value};
use std::collections::HashMap;
use z3::ast::{Ast, Bool, Int, Real};
use z3::{Config, Context, SatResult, Solver};

/// Is the condition satisfiable (can any request make it true)?
/// `Some(true/false)` when decided. `None` if it uses unencodable constructs.
pub fn condition_reachable(expr: &Expr) -> Option<bool> {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let mut enc = Encoder::new(&ctx);
    let f = enc.encode_bool(expr);
    if enc.conflict {
        return None;
    }
    let f = f?;
    let s = Solver::new(&ctx);
    s.assert(&f);
    match s.check() {
        SatResult::Sat => Some(true),
        SatResult::Unsat => Some(false),
        SatResult::Unknown => None,
    }
}

/// Are two conditions equivalent for ALL inputs? `Some(true)` means equivalent.
/// Answers "did this refactor change any decision?".
pub fn conditions_equivalent(a: &Expr, b: &Expr) -> Option<bool> {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let mut enc = Encoder::new(&ctx);
    let fa = enc.encode_bool(a);
    let fb = enc.encode_bool(b);
    if enc.conflict {
        return None;
    }
    let (fa, fb) = (fa?, fb?);
    let s = Solver::new(&ctx);
    s.assert(&fa.xor(&fb)); // SAT iff they differ somewhere
    match s.check() {
        SatResult::Unsat => Some(true),  // never differ, so equivalent
        SatResult::Sat => Some(false),
        SatResult::Unknown => None,
    }
}

struct Encoder<'c> {
    ctx: &'c Context,
    reals: HashMap<String, Real<'c>>,
    bools: HashMap<String, Bool<'c>>,
    /// Entity/string-typed paths, modelled as z3 integers. Each distinct UID or
    /// string literal interns to a distinct integer constant. Sound for
    /// equality/disequality reasoning over an open-world domain.
    ents: HashMap<String, Int<'c>>,
    /// UID/string literal to distinct integer id (the interner).
    interned: HashMap<String, i64>,
    conflict: bool,
}

impl<'c> Encoder<'c> {
    fn new(ctx: &'c Context) -> Self {
        Encoder {
            ctx,
            reals: HashMap::new(),
            bools: HashMap::new(),
            ents: HashMap::new(),
            interned: HashMap::new(),
            conflict: false,
        }
    }

    /// A path used inconsistently (e.g. as both a number and a boolean) makes
    /// the whole encoding unsound to reason about. Flag a conflict and bail.
    fn real_var(&mut self, path: &str) -> Option<Real<'c>> {
        if self.bools.contains_key(path) || self.ents.contains_key(path) {
            self.conflict = true;
            return None;
        }
        Some(self.reals.entry(path.to_string()).or_insert_with(|| Real::new_const(self.ctx, path)).clone())
    }

    fn bool_var(&mut self, path: &str) -> Option<Bool<'c>> {
        if self.reals.contains_key(path) || self.ents.contains_key(path) {
            self.conflict = true;
            return None;
        }
        Some(self.bools.entry(path.to_string()).or_insert_with(|| Bool::new_const(self.ctx, path)).clone())
    }

    /// An entity/string-typed variable (a path), modelled as an unconstrained
    /// z3 integer. It may take any value, capturing the open-world fact that
    /// `principal` could be an entity not named in the policy.
    fn ent_var(&mut self, path: &str) -> Option<Int<'c>> {
        if self.reals.contains_key(path) || self.bools.contains_key(path) {
            self.conflict = true;
            return None;
        }
        Some(self.ents.entry(path.to_string()).or_insert_with(|| Int::new_const(self.ctx, path)).clone())
    }

    /// Intern a UID/string literal to a distinct integer constant. Distinct
    /// literals get distinct ids, so `X == lit_a` and `X == lit_b` are
    /// satisfiably different. That is the equality semantics we need.
    fn ent_const(&mut self, key: &str) -> Int<'c> {
        let next = self.interned.len() as i64;
        let id = *self.interned.entry(key.to_string()).or_insert(next);
        Int::from_i64(self.ctx, id)
    }

    /// Encode `n` as an exact decimal rational k / 10^d. If it cannot be
    /// represented exactly (more precision than 10^-9, or out of i32 range),
    /// return `None` so the whole analysis bails to unknown. We never feed z3 a
    /// value it would reason about differently than the evaluator does. Replaces
    /// the old lossy `*10_000` rounding, which was unsound.
    fn real_const(&mut self, n: f64) -> Option<Real<'c>> {
        for d in 0..=9u32 {
            let scale = 10f64.powi(d as i32);
            let scaled = n * scale;
            if scaled.fract() == 0.0 && scaled.abs() <= i32::MAX as f64 {
                return Some(Real::from_real(self.ctx, scaled as i32, scale as i32));
            }
        }
        None
    }

    /// Encode a numeric (real) expression: a path, a constant, or a
    /// linear/polynomial combination via `+ - *`. Returns `None` if any leaf is
    /// non-numeric or a constant isn't exactly representable.
    fn encode_real(&mut self, e: &Expr) -> Option<Real<'c>> {
        match e {
            Expr::Literal(Value::Int(_)) | Expr::Literal(Value::Float(_)) => {
                let n = number_of(e)?;
                self.real_const(n)
            }
            Expr::Variable(_) | Expr::FieldAccess { .. } => {
                let p = path_of(e)?;
                self.real_var(&p)
            }
            Expr::UnaryOp { op: UnaryOp::Neg, operand } => {
                let o = self.encode_real(operand)?;
                Some(o.unary_minus())
            }
            Expr::BinaryOp { left, op, right } => {
                let l = self.encode_real(left)?;
                let r = self.encode_real(right)?;
                match op {
                    BinaryOp::Add => Some(Real::add(self.ctx, &[&l, &r])),
                    BinaryOp::Sub => Some(Real::sub(self.ctx, &[&l, &r])),
                    BinaryOp::Mul => Some(Real::mul(self.ctx, &[&l, &r])),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Encode an entity/string-typed operand to a z3 integer. A literal interns
    /// to a constant. A path becomes an unconstrained integer variable.
    fn encode_ent(&mut self, e: &Expr) -> Option<Int<'c>> {
        match e {
            Expr::Literal(Value::EntityUid(u)) => Some(self.ent_const(&format!("E:{u}"))),
            Expr::Literal(Value::String(s)) => Some(self.ent_const(&format!("S:{s}"))),
            Expr::Variable(_) | Expr::FieldAccess { .. } => {
                let p = path_of(e)?;
                self.ent_var(&p)
            }
            _ => None,
        }
    }

    fn encode_bool(&mut self, e: &Expr) -> Option<Bool<'c>> {
        match e {
            Expr::Literal(Value::Bool(b)) => Some(Bool::from_bool(self.ctx, *b)),
            Expr::Variable(v) if v == "true" => Some(Bool::from_bool(self.ctx, true)),
            Expr::Variable(v) if v == "false" => Some(Bool::from_bool(self.ctx, false)),
            Expr::Variable(_) | Expr::FieldAccess { .. } => {
                let p = path_of(e)?;
                self.bool_var(&p)
            }
            Expr::UnaryOp { op: crate::ast::UnaryOp::Not, operand } => {
                Some(self.encode_bool(operand)?.not())
            }
            Expr::BinaryOp { left, op, right } => match op {
                BinaryOp::And => {
                    let l = self.encode_bool(left)?;
                    let r = self.encode_bool(right)?;
                    Some(Bool::and(self.ctx, &[&l, &r]))
                }
                BinaryOp::Or => {
                    let l = self.encode_bool(left)?;
                    let r = self.encode_bool(right)?;
                    Some(Bool::or(self.ctx, &[&l, &r]))
                }
                BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                    self.encode_cmp(left, *op, right)
                }
                BinaryOp::Eq | BinaryOp::Ne => self.encode_eq(left, *op, right),
                _ => None,
            },
            _ => None,
        }
    }

    /// Order comparison (`< <= > >=`). Both sides are numeric, since entities
    /// aren't ordered, so encode each as a real. Covers path-vs-path and
    /// arithmetic along with `path OP constant`.
    fn encode_cmp(&mut self, left: &Expr, op: BinaryOp, right: &Expr) -> Option<Bool<'c>> {
        let l = self.encode_real(left)?;
        let r = self.encode_real(right)?;
        Some(cmp(&l, op, &r))
    }

    /// Equality/disequality. The operand kind is decided syntactically so we
    /// never pollute the var maps by trial-encoding. An entity/string literal on
    /// either side means entity equality. A number/arithmetic operand means
    /// numeric. Anything else is boolean (e.g. `flag == true`).
    fn encode_eq(&mut self, left: &Expr, op: BinaryOp, right: &Expr) -> Option<Bool<'c>> {
        let neg = op == BinaryOp::Ne;
        let finish = |eq: Bool<'c>| Some(if neg { eq.not() } else { eq });

        if is_entity_or_string_lit(left) || is_entity_or_string_lit(right) {
            let l = self.encode_ent(left)?;
            let r = self.encode_ent(right)?;
            return finish(l._eq(&r));
        }
        if is_numeric(left) || is_numeric(right) {
            let l = self.encode_real(left)?;
            let r = self.encode_real(right)?;
            return finish(l._eq(&r));
        }
        let l = self.encode_bool(left)?;
        let r = self.encode_bool(right)?;
        finish(l._eq(&r))
    }
}

/// Syntactically a numeric operand: a number literal, an arithmetic combination,
/// or a unary negation. Drives equality kind-detection with no encoding side
/// effects.
fn is_numeric(e: &Expr) -> bool {
    match e {
        Expr::Literal(Value::Int(_)) | Expr::Literal(Value::Float(_)) => true,
        Expr::UnaryOp { op: UnaryOp::Neg, .. } => true,
        Expr::BinaryOp { op, .. } => matches!(op, BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul),
        _ => false,
    }
}

fn is_entity_or_string_lit(e: &Expr) -> bool {
    matches!(e, Expr::Literal(Value::EntityUid(_)) | Expr::Literal(Value::String(_)))
}

fn cmp<'c>(a: &Real<'c>, op: BinaryOp, b: &Real<'c>) -> Bool<'c> {
    match op {
        BinaryOp::Lt => a.lt(b),
        BinaryOp::Le => a.le(b),
        BinaryOp::Gt => a.gt(b),
        _ => a.ge(b),
    }
}

fn path_of(e: &Expr) -> Option<String> {
    match e {
        Expr::Variable(v) if v != "true" && v != "false" => Some(v.clone()),
        Expr::FieldAccess { object, field } => Some(format!("{}.{}", path_of(object)?, field)),
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
    use crate::ast::ChaiProgram;
    use crate::parser::parse_chai;

    fn cond(src: &str) -> Expr {
        match parse_chai(&format!("permit when {src}\n")).unwrap() {
            ChaiProgram::SingleLineRules(r) => r[0].condition.clone().unwrap(),
            _ => panic!(),
        }
    }

    #[test]
    fn reachability() {
        assert_eq!(condition_reachable(&cond("a.x > 0.5 and a.x < 0.3")), Some(false));
        assert_eq!(condition_reachable(&cond("a.x > 0.5 and a.x < 0.8")), Some(true));
        // entity equality is in-fragment via the interned integer domain
        assert_eq!(condition_reachable(&cond("principal == User::\"a\"")), Some(true));
        // a principal cannot equal two distinct entities at once
        assert_eq!(
            condition_reachable(&cond("principal == User::\"a\" and principal == User::\"b\"")),
            Some(false)
        );
        // arithmetic and path-vs-path are in-fragment too
        assert_eq!(condition_reachable(&cond("a.x + a.y > 3.0 and a.x < 1.0 and a.y < 1.0")), Some(false));
        assert_eq!(condition_reachable(&cond("a.x > a.y and a.y > a.x")), Some(false));
        // a method term is out-of-fragment, so unknown
        assert_eq!(condition_reachable(&cond("principal.addr.isInRange(ip(\"10.0.0.0/24\"))")), None);
    }

    // At-scale differential vs an independent, complete oracle.
    //
    // Ground truth is a separate reference interpreter (`ref_eval`, not our
    // evaluator), brute-forced over a domain fine enough to be a complete
    // decision procedure for the generated fragment. z3 must match the grid
    // verdict exactly in both directions.
    //
    // Why the grid is complete for the wider fragment:
    //   - thresholds are 0.1-multiples, the numeric grid steps by 0.05, so every
    //     decision boundary `x OP t` lands on a sampled point;
    //   - sums/differences of two grid values are themselves 0.05-multiples and
    //     the boundary `x±y = t` is hit by grid points, so `(x+y) OP t` and
    //     `(x-y) OP t` are decided exactly;
    //   - the path-vs-path boundary `x = y` is on the grid (diagonal points);
    //   - entities use an open domain {E0,E1,E2, Eother}. The generator only ever
    //     names E0..E2, and every unnamed entity is interchangeable, so a single
    //     `Eother` representative makes the finite grid match z3's open-world
    //     (unconstrained-integer) entity encoding exactly.
    // The fragment mixes numeric threshold comparisons, path-vs-path comparisons,
    // +/- arithmetic, entity equality, and boolean atoms under and/or/not.

    use crate::ast::{BinaryOp as B, UnaryOp};

    // The numeric grid is multiples of 0.05 in [0,1]. The oracle works in exact
    // integer "twentieths" (1 unit = 0.05) so it never suffers f64 rounding.
    // That matters because z3 reasons over exact rationals (0.65+0.05 is exactly
    // 0.7 for z3 but 0.7000000000000001 in f64). Thresholds are 0.1-multiples,
    // so even twentieths. Any sum/difference of grid points stays an integer
    // twentieth, and every solution to these constraints lands on the grid, so
    // it stays a complete decision procedure.
    const TWENTIETHS: i32 = 20; // 1.0
    const THRESH: &[f64] = &[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9];
    // Entity literals the generator may name (ids 0..=2). The grid also ranges
    // `e.r` over id 3, "some other entity", which is never named.
    const ENT_LITS: &[u8] = &[0, 1, 2];

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn pick<'a, T>(&mut self, s: &'a [T]) -> &'a T {
            &s[self.next() as usize % s.len()]
        }
    }

    fn field(base: &str, f: &str) -> Expr {
        Expr::FieldAccess { object: Box::new(Expr::Variable(base.into())), field: f.into() }
    }
    fn ent_lit(id: u8) -> Expr {
        Expr::Literal(Value::EntityUid(format!("E::e{id}")))
    }

    fn cmp_op(rng: &mut Rng) -> BinaryOp {
        *rng.pick(&[B::Lt, B::Le, B::Gt, B::Ge, B::Eq, B::Ne])
    }
    // Order-only. Used where both sides are bare numeric paths. `x == y` between
    // two bare paths is syntactically ambiguous (could be bool or entity eq) and
    // the encoder deliberately can't disambiguate it. Order ops are
    // unambiguously numeric.
    fn order_op(rng: &mut Rng) -> BinaryOp {
        *rng.pick(&[B::Lt, B::Le, B::Gt, B::Ge])
    }

    fn gen(rng: &mut Rng, depth: u32) -> Expr {
        if depth == 0 || rng.next() % 3 == 0 {
            match rng.next() % 5 {
                // numeric atom: n.{x,y} OP threshold
                0 => {
                    let v = *rng.pick(&["x", "y"]);
                    Expr::BinaryOp { left: Box::new(field("n", v)), op: cmp_op(rng), right: Box::new(Expr::Literal(Value::Float(*rng.pick(THRESH)))) }
                }
                // path-vs-path: n.x OP n.y (order ops only, see order_op)
                1 => Expr::BinaryOp { left: Box::new(field("n", "x")), op: order_op(rng), right: Box::new(field("n", "y")) },
                // arithmetic: (n.x +/- n.y) OP threshold
                2 => {
                    let arith = if rng.next() % 2 == 0 { B::Add } else { B::Sub };
                    let sum = Expr::BinaryOp { left: Box::new(field("n", "x")), op: arith, right: Box::new(field("n", "y")) };
                    Expr::BinaryOp { left: Box::new(sum), op: cmp_op(rng), right: Box::new(Expr::Literal(Value::Float(*rng.pick(THRESH)))) }
                }
                // entity equality: e.r == or != E::eK
                3 => {
                    let op = if rng.next() % 2 == 0 { B::Eq } else { B::Ne };
                    Expr::BinaryOp { left: Box::new(field("e", "r")), op, right: Box::new(ent_lit(*rng.pick(ENT_LITS))) }
                }
                // boolean atom: b.{p,q}, maybe negated
                _ => {
                    let atom = field("b", *rng.pick(&["p", "q"]));
                    if rng.next() % 2 == 0 { atom } else { Expr::UnaryOp { op: UnaryOp::Not, operand: Box::new(atom) } }
                }
            }
        } else {
            match rng.next() % 3 {
                0 => Expr::BinaryOp { left: Box::new(gen(rng, depth - 1)), op: B::And, right: Box::new(gen(rng, depth - 1)) },
                1 => Expr::BinaryOp { left: Box::new(gen(rng, depth - 1)), op: B::Or, right: Box::new(gen(rng, depth - 1)) },
                _ => Expr::UnaryOp { op: UnaryOp::Not, operand: Box::new(gen(rng, depth - 1)) },
            }
        }
    }

    #[derive(Clone, Copy)]
    struct Asg {
        x: i32, // twentieths, 0..=20
        y: i32, // twentieths, 0..=20
        p: bool,
        q: bool,
        r: u8, // entity id 0..=3 (3 is "some other entity")
    }

    fn path(e: &Expr) -> String {
        match e {
            Expr::FieldAccess { object, field } => format!("{}.{}", path(object), field),
            Expr::Variable(v) => v.clone(),
            _ => unreachable!(),
        }
    }

    /// Exact value of a numeric expression in twentieths via integer arithmetic.
    fn ref_real(e: &Expr, a: &Asg) -> i32 {
        match e {
            Expr::Literal(Value::Float(f)) => (f * TWENTIETHS as f64).round() as i32,
            Expr::FieldAccess { .. } => match path(e).as_str() {
                "n.x" => a.x,
                "n.y" => a.y,
                p => unreachable!("real path {p}"),
            },
            Expr::BinaryOp { left, op: B::Add, right } => ref_real(left, a) + ref_real(right, a),
            Expr::BinaryOp { left, op: B::Sub, right } => ref_real(left, a) - ref_real(right, a),
            _ => unreachable!(),
        }
    }

    /// Independent reference interpreter. Exact f64/bool/entity, not our evaluator.
    fn ref_eval(e: &Expr, a: &Asg) -> bool {
        match e {
            Expr::UnaryOp { op: UnaryOp::Not, operand } => !ref_eval(operand, a),
            Expr::BinaryOp { left, op: B::And, right } => ref_eval(left, a) && ref_eval(right, a),
            Expr::BinaryOp { left, op: B::Or, right } => ref_eval(left, a) || ref_eval(right, a),
            // entity (dis)equality
            Expr::BinaryOp { left, op: op @ (B::Eq | B::Ne), right }
                if matches!(right.as_ref(), Expr::Literal(Value::EntityUid(_))) =>
            {
                let lit = match right.as_ref() {
                    Expr::Literal(Value::EntityUid(u)) => u.trim_start_matches("E::e").parse::<u8>().unwrap(),
                    _ => unreachable!(),
                };
                debug_assert_eq!(path(left), "e.r");
                if *op == B::Eq { a.r == lit } else { a.r != lit }
            }
            // numeric comparison (threshold, path-vs-path, or arithmetic)
            Expr::BinaryOp { left, op, right } => {
                let (l, r) = (ref_real(left, a), ref_real(right, a));
                match op {
                    B::Lt => l < r,
                    B::Le => l <= r,
                    B::Gt => l > r,
                    B::Ge => l >= r,
                    B::Eq => l == r,
                    _ => l != r,
                }
            }
            Expr::FieldAccess { .. } => match path(e).as_str() {
                "b.p" => a.p,
                "b.q" => a.q,
                p => unreachable!("bool path {p}"),
            },
            _ => unreachable!(),
        }
    }

    fn for_grid(mut f: impl FnMut(Asg) -> bool) -> bool {
        for x in 0..=TWENTIETHS {
            for y in 0..=TWENTIETHS {
                for &p in &[false, true] {
                    for &q in &[false, true] {
                        for r in 0u8..=3 {
                            if f(Asg { x, y, p, q, r }) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn grid_sat(e: &Expr) -> bool {
        for_grid(|a| ref_eval(e, &a))
    }

    fn grid_equal(a: &Expr, b: &Expr) -> bool {
        !for_grid(|asg| ref_eval(a, &asg) != ref_eval(b, &asg))
    }

    // z3's real vars are unbounded, but the grid enumerates the [0,1] box.
    // Without this they diverge as soon as arithmetic escapes the box (e.g.
    // `x - y >= 0.4 and y >= 0.8` is SAT over ℝ at x=1.3 but empty in [0,1]).
    // Conjoining the box constraints makes z3 reason over exactly the domain the
    // grid samples, restoring a complete oracle. Conjoining the same bounds to
    // both sides of an equivalence query preserves equivalence-over-the-box.
    // Outside the box both sides are false, so they agree there trivially.
    fn cmp_lit(field_name: &str, op: BinaryOp, lit: f64) -> Expr {
        Expr::BinaryOp { left: Box::new(field("n", field_name)), op, right: Box::new(Expr::Literal(Value::Float(lit))) }
    }
    fn with_bounds(e: &Expr) -> Expr {
        let conj = |a: Expr, b: Expr| Expr::BinaryOp { left: Box::new(a), op: B::And, right: Box::new(b) };
        let bounds = conj(
            conj(cmp_lit("x", B::Ge, 0.0), cmp_lit("x", B::Le, 1.0)),
            conj(cmp_lit("y", B::Ge, 0.0), cmp_lit("y", B::Le, 1.0)),
        );
        conj(bounds, e.clone())
    }

    /// z3 reachability over the [0,1] box must equal the complete-grid verdict.
    #[test]
    fn z3_matches_independent_oracle_reachability() {
        let mut rng = Rng(0x1111_2222_3333_4444);
        for _ in 0..3000 {
            let e = gen(&mut rng, 3);
            assert_eq!(condition_reachable(&with_bounds(&e)), Some(grid_sat(&e)), "z3 vs grid disagree: {e:?}");
        }
    }

    /// z3 equivalence over the [0,1] box must equal the complete-grid verdict.
    #[test]
    fn z3_matches_independent_oracle_equivalence() {
        let mut rng = Rng(0x5555_6666_7777_8888);
        for _ in 0..3000 {
            let a = gen(&mut rng, 3);
            let b = gen(&mut rng, 3);
            assert_eq!(
                conditions_equivalent(&with_bounds(&a), &with_bounds(&b)),
                Some(grid_equal(&a, &b)),
                "z3 vs grid disagree on equivalence:\n a={a:?}\n b={b:?}"
            );
        }
    }

    #[test]
    fn equivalence_beyond_intervals() {
        let strict = conditions_equivalent(&cond("a.x > 5"), &cond("a.x >= 5"));
        let or_abs = conditions_equivalent(&cond("a.x > 5 or a.x > 3"), &cond("a.x > 3"));
        let neg = conditions_equivalent(&cond("not (a.x > 5)"), &cond("a.x <= 5"));
        let dem = conditions_equivalent(
            &cond("not (a.x > 5 or a.y < 1)"),
            &cond("a.x <= 5 and a.y >= 1"),
        );
        eprintln!("strict={strict:?} or_abs={or_abs:?} neg={neg:?} dem={dem:?}");
        assert_eq!(strict, Some(false));
        assert_eq!(or_abs, Some(true));
        assert_eq!(neg, Some(true));
        assert_eq!(dem, Some(true));
    }

    // Performance / scale study.
    //
    // Empirical scaling of the z3-backed analysis as a policy condition grows.
    // The correctness tests above fix the answer. This one fixes nothing and
    // measures wall-clock. For each N it builds three workloads of size ~N and
    // times encode+solve, asserting the analysis stays decidable and under a
    // generous ceiling. Run `cargo test --features smt perf_scale -- --nocapture`
    // to see the table.
    #[test]
    fn perf_scale_study() {
        use std::time::Instant;

        fn var(i: usize) -> Expr {
            Expr::FieldAccess { object: Box::new(Expr::Variable("a".into())), field: format!("x{i}") }
        }
        fn leaf(i: usize, t: f64, op: BinaryOp) -> Expr {
            Expr::BinaryOp { left: Box::new(var(i)), op, right: Box::new(Expr::Literal(Value::Float(t))) }
        }
        fn not(e: Expr) -> Expr {
            Expr::UnaryOp { op: UnaryOp::Not, operand: Box::new(e) }
        }
        fn fold(leaves: &[Expr], op: BinaryOp) -> Expr {
            let mut it = leaves.iter().cloned();
            let mut acc = it.next().unwrap();
            for e in it {
                acc = Expr::BinaryOp { left: Box::new(acc), op, right: Box::new(e) };
            }
            acc
        }
        fn ms(start: Instant) -> f64 {
            start.elapsed().as_secs_f64() * 1000.0
        }

        eprintln!("\n  z3 analysis scaling (encode + solve, single thread)");
        eprintln!("  ----------------------------------------------------------------");
        eprintln!("   N(terms)   sat-conj   unsat-1var   equiv-DeMorgan(2N)");
        for &n in &[10usize, 50, 100, 200, 400, 800] {
            // Exact-representable thresholds, literal 0.1-multiples. Arithmetic
            // like `0.1 + i*0.1` would accumulate f64 error and bail to None.
            let leaves: Vec<Expr> =
                (0..n).map(|i| leaf(i, THRESH[i % THRESH.len()], BinaryOp::Gt)).collect();

            // (1) SAT: conjunction of N independent satisfiable bounds.
            let big_and = fold(&leaves, BinaryOp::And);
            let t = Instant::now();
            let reach = condition_reachable(&big_and);
            let sat_ms = ms(t);

            // (2) UNSAT: N contradictory bounds on one variable. The solver must
            //     derive the conflict, it cannot just find a witness.
            let mut conflict: Vec<Expr> = (0..n).map(|i| leaf(0, 0.5, if i % 2 == 0 { BinaryOp::Gt } else { BinaryOp::Lt })).collect();
            conflict.push(leaf(0, 0.5, BinaryOp::Gt));
            conflict.push(leaf(0, 0.5, BinaryOp::Lt)); // x>0.5 and x<0.5 is UNSAT
            let big_conflict = fold(&conflict, BinaryOp::And);
            let t = Instant::now();
            let unsat = condition_reachable(&big_conflict);
            let unsat_ms = ms(t);

            // (3) Equivalence: De Morgan tautology over 2N terms.
            let lhs = not(fold(&leaves, BinaryOp::Or));
            let neg_leaves: Vec<Expr> = leaves.iter().cloned().map(not).collect();
            let rhs = fold(&neg_leaves, BinaryOp::And);
            let t = Instant::now();
            let equiv = conditions_equivalent(&lhs, &rhs);
            let equiv_ms = ms(t);

            eprintln!("   {n:<10} {sat_ms:>7.2}ms   {unsat_ms:>7.2}ms     {equiv_ms:>7.2}ms");

            assert_eq!(reach, Some(true), "N={n} sat-conj");
            assert_eq!(unsat, Some(false), "N={n} unsat-1var");
            assert_eq!(equiv, Some(true), "N={n} equiv-DeMorgan");
            assert!(sat_ms < 5000.0 && unsat_ms < 5000.0 && equiv_ms < 5000.0, "z3 exceeded 5s ceiling at N={n}");
        }
        eprintln!("  ----------------------------------------------------------------");
    }
}
