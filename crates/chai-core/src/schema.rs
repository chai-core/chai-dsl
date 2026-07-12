//! Static policy validation against a schema (Cedar-style).
//! Deferred by design. See CLAUDE.md.
//!
//! A `Schema` declares entity attribute types and each action's `appliesTo`,
//! the principal/resource types it accepts. The validator type-checks every
//! policy in each request environment the schema permits. It catches three
//! classes of bug before runtime. Unknown attributes, type-mismatched
//! comparisons, and methods applied to the wrong type.
//!
//! Sound by omission. An expression rooted at something other than a schema
//! entity (e.g. `dlp_facts.pii`) is treated as `Unknown` and not flagged, so
//! fact-based emission policies never trip a false error.

use crate::ast::{BinaryOp, ChaiProgram, Expr, Rule, UnaryOp, Value};
use std::collections::{HashMap, HashSet};

/// A static type in the schema's type system.
#[derive(Debug, Clone, PartialEq)]
pub enum Ty {
    Bool,
    Long,
    String,
    Decimal,
    Ip,
    Set(Box<Ty>),
    /// An untyped record (fields not declared).
    Record,
    /// A named record type with declared field types (e.g. `context`,
    /// `subject`). Fields may themselves be `RecordOf(..)` for nesting.
    RecordOf(String),
    Entity(String),
    /// Not known to the schema. Never produces a type error.
    Unknown,
}

struct EntityDecl {
    attrs: HashMap<String, Ty>,
}

struct RecordDecl {
    attrs: HashMap<String, Ty>,
}

struct ActionDecl {
    principals: Vec<String>,
    resources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidationError {
    pub rule: String,
    pub message: String,
}

#[derive(Default)]
pub struct Schema {
    entities: HashMap<String, EntityDecl>,
    actions: HashMap<String, ActionDecl>,
    records: HashMap<String, RecordDecl>,
}

impl Schema {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare an entity type and its attribute types.
    pub fn add_entity(&mut self, name: &str, attrs: &[(&str, Ty)]) -> &mut Self {
        self.entities.insert(
            name.to_string(),
            EntityDecl { attrs: attrs.iter().map(|(k, t)| (k.to_string(), t.clone())).collect() },
        );
        self
    }

    /// Declare a named record type (e.g. `subject`, `object`, or a nested record)
    /// and its field types. Fields may be `Ty::RecordOf(inner)` to nest.
    pub fn add_record(&mut self, name: &str, fields: &[(&str, Ty)]) -> &mut Self {
        self.records.insert(
            name.to_string(),
            RecordDecl { attrs: fields.iter().map(|(k, t)| (k.to_string(), t.clone())).collect() },
        );
        self
    }

    /// Declare the typed fields of the request `context` record.
    pub fn add_context(&mut self, fields: &[(&str, Ty)]) -> &mut Self {
        self.add_record("context", fields)
    }

    /// Declare an action and the principal/resource types it applies to.
    pub fn add_action(&mut self, name: &str, principals: &[&str], resources: &[&str]) -> &mut Self {
        self.actions.insert(
            name.to_string(),
            ActionDecl {
                principals: principals.iter().map(|s| s.to_string()).collect(),
                resources: resources.iter().map(|s| s.to_string()).collect(),
            },
        );
        self
    }

    /// Validate a program; returns the (deduplicated) type errors.
    pub fn validate(&self, program: &ChaiProgram) -> Vec<ValidationError> {
        let rules = match program {
            ChaiProgram::SingleLineRules(r) => r.as_slice(),
            ChaiProgram::StructuredRules(p) => p.rules.as_slice(),
            ChaiProgram::HierarchicalConfig(c) => c.rules.as_slice(),
        };
        let mut out: HashSet<ValidationError> = HashSet::new();
        for rule in rules {
            for action in self.applicable_actions(rule) {
                let adecl = &self.actions[&action];
                for p in &adecl.principals {
                    for r in &adecl.resources {
                        let env = Env { principal: p.clone(), resource: r.clone() };
                        let mut chk = Checker { schema: self, env, errors: Vec::new() };
                        chk.exprs_of(rule).for_each(|e| {
                            chk.check_bool(e);
                        });
                        let rid = rule.id.clone().unwrap_or_else(|| "<anonymous>".into());
                        for m in std::mem::take(&mut chk.errors) {
                            out.insert(ValidationError { rule: rid.clone(), message: m });
                        }
                    }
                }
            }
        }
        let mut v: Vec<_> = out.into_iter().collect();
        v.sort_by(|a, b| (a.rule.clone(), a.message.clone()).cmp(&(b.rule.clone(), b.message.clone())));
        v
    }

    /// Which actions a rule can apply to. An explicit `action == Action::"x"`
    /// in the action pattern or as a condition conjunct narrows it. With no
    /// such constraint, every action is in scope.
    fn applicable_actions(&self, rule: &Rule) -> Vec<String> {
        use crate::ast::ActionPattern;
        if let Some(ActionPattern::Eq(a)) = &rule.action {
            return vec![action_id(a)];
        }
        let mut found = Vec::new();
        if let Some(cond) = &rule.condition {
            collect_action_eq(cond, &mut found);
        }
        if !found.is_empty() {
            found.retain(|a| self.actions.contains_key(a));
            if !found.is_empty() {
                return found;
            }
        }
        self.actions.keys().cloned().collect()
    }
}

struct Env {
    principal: String,
    resource: String,
}

struct Checker<'a> {
    schema: &'a Schema,
    env: Env,
    errors: Vec<String>,
}

impl<'a> Checker<'a> {
    fn exprs_of<'r>(&self, rule: &'r Rule) -> impl Iterator<Item = &'r Expr> {
        use crate::ast::{PrincipalPattern, ResourcePattern};
        let mut v: Vec<&Expr> = Vec::new();
        if let Some(c) = &rule.condition {
            v.push(c);
        }
        if let Some(PrincipalPattern::Condition(e)) = &rule.principal {
            v.push(e);
        }
        if let Some(ResourcePattern::Condition(e)) = &rule.resource {
            v.push(e);
        }
        v.into_iter()
    }

    fn err(&mut self, m: String) {
        self.errors.push(m);
    }

    fn check_bool(&mut self, e: &Expr) {
        let t = self.infer(e);
        if !matches!(t, Ty::Bool | Ty::Unknown) {
            self.err(format!("condition is not boolean (is {t:?})"));
        }
    }

    fn infer(&mut self, e: &Expr) -> Ty {
        match e {
            Expr::Literal(v) => ty_of_value(v),
            Expr::Variable(name) => match name.as_str() {
                "principal" => Ty::Entity(self.env.principal.clone()),
                "resource" => Ty::Entity(self.env.resource.clone()),
                "action" => Ty::Entity("Action".into()),
                "true" | "false" => Ty::Bool,
                // A declared named record (e.g. `context`) is typed. Anything
                // else, like undeclared facts `dlp_facts`, stays Unknown.
                other if self.schema.records.contains_key(other) => Ty::RecordOf(other.to_string()),
                _ => Ty::Unknown,
            },
            Expr::FieldAccess { object, field } => {
                let ot = self.infer(object);
                match ot {
                    Ty::Entity(t) => match self.schema.entities.get(&t) {
                        Some(decl) => match decl.attrs.get(field) {
                            Some(ty) => ty.clone(),
                            None => {
                                self.err(format!("entity `{t}` has no attribute `{field}`"));
                                Ty::Unknown
                            }
                        },
                        None => {
                            self.err(format!("unknown entity type `{t}`"));
                            Ty::Unknown
                        }
                    },
                    Ty::RecordOf(name) => match self.schema.records.get(&name) {
                        Some(decl) => match decl.attrs.get(field) {
                            Some(ty) => ty.clone(),
                            None => {
                                self.err(format!("record `{name}` has no field `{field}`"));
                                Ty::Unknown
                            }
                        },
                        None => Ty::Unknown,
                    },
                    Ty::Record | Ty::Unknown => Ty::Unknown,
                    other => {
                        self.err(format!("cannot access `.{field}` on {other:?}"));
                        Ty::Unknown
                    }
                }
            }
            Expr::BinaryOp { left, op, right } => {
                let lt = self.infer(left);
                let rt = self.infer(right);
                use BinaryOp::*;
                match op {
                    Eq | Ne => {
                        if !compatible(&lt, &rt) {
                            self.err(format!("comparing incompatible types {lt:?} and {rt:?}"));
                        }
                        Ty::Bool
                    }
                    Lt | Le | Gt | Ge => {
                        self.expect_numeric(&lt);
                        self.expect_numeric(&rt);
                        Ty::Bool
                    }
                    And | Or => {
                        self.expect_bool(&lt);
                        self.expect_bool(&rt);
                        Ty::Bool
                    }
                    Add | Sub | Mul | Div | Mod => {
                        self.expect(&lt, &Ty::Long);
                        self.expect(&rt, &Ty::Long);
                        Ty::Long
                    }
                    In | Has | Contains | Like | Is => Ty::Bool,
                }
            }
            Expr::UnaryOp { op, operand } => {
                let t = self.infer(operand);
                match op {
                    UnaryOp::Not => {
                        self.expect_bool(&t);
                        Ty::Bool
                    }
                    UnaryOp::Neg => {
                        self.expect_numeric(&t);
                        Ty::Long
                    }
                }
            }
            Expr::MethodCall { object, method, args } => {
                let ot = self.infer(object);
                for a in args {
                    let _ = self.infer(a);
                }
                match (&ot, method.as_str()) {
                    (Ty::Ip, "isLoopback" | "isMulticast" | "isIpv4" | "isIpv6" | "isInRange") => Ty::Bool,
                    (Ty::Decimal, "lessThan" | "lessThanOrEqual" | "greaterThan" | "greaterThanOrEqual") => {
                        Ty::Bool
                    }
                    (Ty::Unknown, _) => Ty::Unknown,
                    _ => {
                        self.err(format!("no method `{method}` on {ot:?}"));
                        Ty::Unknown
                    }
                }
            }
            Expr::FunctionCall { name, args } => {
                for a in args {
                    let _ = self.infer(a);
                }
                match name.as_str() {
                    "ip" => Ty::Ip,
                    "decimal" => Ty::Decimal,
                    "size" | "len" => Ty::Long,
                    "containsAll" | "containsAny" => Ty::Bool,
                    _ => Ty::Unknown,
                }
            }
            Expr::List(_) => Ty::Set(Box::new(Ty::Unknown)),
            Expr::Dict(_) => Ty::Record,
            Expr::Slot(_) => Ty::Unknown,
        }
    }

    fn expect(&mut self, t: &Ty, want: &Ty) {
        if t != want && *t != Ty::Unknown {
            self.err(format!("expected {want:?}, found {t:?}"));
        }
    }
    fn expect_bool(&mut self, t: &Ty) {
        if !matches!(t, Ty::Bool | Ty::Unknown) {
            self.err(format!("expected Bool, found {t:?}"));
        }
    }
    fn expect_numeric(&mut self, t: &Ty) {
        if !matches!(t, Ty::Long | Ty::Decimal | Ty::Unknown) {
            self.err(format!("expected a number, found {t:?}"));
        }
    }
}

fn ty_of_value(v: &Value) -> Ty {
    match v {
        Value::Bool(_) => Ty::Bool,
        Value::Int(_) => Ty::Long,
        Value::Float(_) => Ty::Decimal,
        Value::String(_) => Ty::String,
        Value::List(_) => Ty::Set(Box::new(Ty::Unknown)),
        Value::Dict(_) => Ty::Record,
        Value::EntityUid(uid) => Ty::Entity(entity_type_of(uid)),
        Value::Ip(_) => Ty::Ip,
        Value::Decimal(_) => Ty::Decimal,
    }
}

/// Whether two types may be compared with `==`/`!=`. Unknown is compatible
/// with anything since we can't check it. Any two entity types are comparable,
/// which Cedar allows.
fn compatible(a: &Ty, b: &Ty) -> bool {
    use Ty::*;
    match (a, b) {
        (Unknown, _) | (_, Unknown) => true,
        (Entity(_), Entity(_)) => true,
        (Set(_), Set(_)) => true,
        // Records are mutually comparable. Named records match by name.
        (RecordOf(x), RecordOf(y)) => x == y,
        (RecordOf(_) | Record, RecordOf(_) | Record) => true,
        _ => a == b,
    }
}

fn entity_type_of(uid: &str) -> String {
    uid.rsplit_once("::").map(|(t, _)| t).unwrap_or(uid).to_string()
}

fn action_id(uid: &str) -> String {
    uid.rsplit_once("::").map(|(_, id)| id).unwrap_or(uid).to_string()
}

/// Collect `action == Action::"x"` constraints anywhere in an expression.
fn collect_action_eq(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::BinaryOp { left, op: BinaryOp::Eq, right } => {
            if let (Expr::Variable(v), Expr::Literal(Value::EntityUid(uid))) = (left.as_ref(), right.as_ref()) {
                if v == "action" {
                    out.push(action_id(uid));
                }
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            collect_action_eq(left, out);
            collect_action_eq(right, out);
        }
        Expr::UnaryOp { operand, .. } => collect_action_eq(operand, out),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_chai;

    fn schema() -> Schema {
        let mut s = Schema::new();
        s.add_entity("User", &[("trust_tier", Ty::Long), ("name", Ty::String)]);
        s.add_entity("Photo", &[("isPublic", Ty::Bool)]);
        s.add_action("view", &["User"], &["Photo"]);
        s
    }

    #[test]
    fn accepts_well_typed_policy() {
        let p = parse_chai(
            "permit when action == Action::\"view\" and principal.trust_tier > 3 and resource.isPublic\n",
        )
        .unwrap();
        assert!(schema().validate(&p).is_empty());
    }

    #[test]
    fn catches_unknown_attribute() {
        let p = parse_chai("permit when action == Action::\"view\" and principal.nonexistent > 3\n").unwrap();
        let errs = schema().validate(&p);
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(errs[0].message.contains("no attribute `nonexistent`"));
    }

    #[test]
    fn catches_type_mismatch() {
        // trust_tier is Long. Comparing it to a String is a type error.
        let p = parse_chai("permit when action == Action::\"view\" and principal.trust_tier == \"admin\"\n").unwrap();
        let errs = schema().validate(&p);
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(errs[0].message.contains("incompatible"));
    }

    #[test]
    fn catches_bad_method() {
        // isPublic is Bool. Calling an ip method on it is a type error.
        let p = parse_chai("permit when action == Action::\"view\" and resource.isPublic.isLoopback()\n").unwrap();
        let errs = schema().validate(&p);
        assert!(errs.iter().any(|e| e.message.contains("no method `isLoopback`")));
    }

    #[test]
    fn ignores_non_schema_roots() {
        // dlp_facts is not a schema entity, so it infers Unknown and is not flagged.
        let p = parse_chai("permit when dlp_facts.pii < 0.5 and safety_facts.harm > 0.2\n").unwrap();
        assert!(schema().validate(&p).is_empty());
    }

    // typed context records

    fn schema_with_context() -> Schema {
        let mut s = schema();
        s.add_record("session", &[("level", Ty::Long)]);
        s.add_context(&[
            ("hour", Ty::Long),
            ("tenant", Ty::String),
            ("session", Ty::RecordOf("session".into())),
        ]);
        s
    }

    #[test]
    fn accepts_well_typed_context() {
        let p = parse_chai(
            "permit when action == Action::\"view\" and context.hour >= 9 and context.tenant == \"acme\"\n",
        )
        .unwrap();
        assert!(schema_with_context().validate(&p).is_empty());
    }

    #[test]
    fn catches_context_type_mismatch() {
        // context.hour is Long. Comparing it to a String is a type error.
        let p = parse_chai("permit when action == Action::\"view\" and context.hour == \"nine\"\n").unwrap();
        let errs = schema_with_context().validate(&p);
        assert!(errs.iter().any(|e| e.message.contains("incompatible")), "{errs:?}");
    }

    #[test]
    fn catches_unknown_context_field() {
        let p = parse_chai("permit when action == Action::\"view\" and context.nonexistent > 3\n").unwrap();
        let errs = schema_with_context().validate(&p);
        assert!(errs.iter().any(|e| e.message.contains("record `context` has no field `nonexistent`")), "{errs:?}");
    }

    #[test]
    fn types_nested_context_records() {
        // context.session.level is Long, so it passes. A bad nested field is caught.
        let ok = parse_chai("permit when action == Action::\"view\" and context.session.level > 2\n").unwrap();
        assert!(schema_with_context().validate(&ok).is_empty());

        let bad = parse_chai("permit when action == Action::\"view\" and context.session.bogus > 2\n").unwrap();
        let errs = schema_with_context().validate(&bad);
        assert!(errs.iter().any(|e| e.message.contains("record `session` has no field `bogus`")), "{errs:?}");
    }

    #[test]
    fn undeclared_context_stays_unknown() {
        // No add_context, so context is Unknown and nothing is flagged. Back-compat.
        let p = parse_chai("permit when action == Action::\"view\" and context.anything == 5\n").unwrap();
        assert!(schema().validate(&p).is_empty());
    }
}
