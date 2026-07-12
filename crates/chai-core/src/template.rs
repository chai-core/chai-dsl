//! Policy templates. Parameterized policies with `?principal` / `?resource`
//! slots that are filled in (`link`ed) per grant to produce concrete policies.
//!
//! Example template:
//! ```text
//! permit when principal == ?principal and resource in ?resource
//! ```
//! Linking it with `{principal: User::"alice", resource: Album::"trip"}` yields
//! a concrete policy specific to that user/resource.

use crate::ast::*;
use std::collections::HashMap;

/// Link a template program by substituting every `?slot` with its bound value.
/// An unbound slot is left in place. Evaluating it later errors (fail-closed).
pub fn link(program: &ChaiProgram, bindings: &HashMap<String, Value>) -> ChaiProgram {
    let link_rules = |rules: &[Rule]| -> Vec<Rule> {
        rules.iter().map(|r| link_rule(r, bindings)).collect()
    };
    match program {
        ChaiProgram::SingleLineRules(rs) => ChaiProgram::SingleLineRules(link_rules(rs)),
        ChaiProgram::StructuredRules(p) => {
            ChaiProgram::StructuredRules(Policy { rules: link_rules(&p.rules) })
        }
        ChaiProgram::HierarchicalConfig(c) => {
            let mut c = c.clone();
            c.rules = link_rules(&c.rules);
            ChaiProgram::HierarchicalConfig(c)
        }
    }
}

fn link_rule(rule: &Rule, b: &HashMap<String, Value>) -> Rule {
    let mut r = rule.clone();
    r.principal = r.principal.map(|p| link_principal(p, b));
    r.resource = r.resource.map(|p| link_resource(p, b));
    r.condition = r.condition.map(|e| subst(&e, b));
    r
}

fn link_principal(p: PrincipalPattern, b: &HashMap<String, Value>) -> PrincipalPattern {
    match p {
        PrincipalPattern::Condition(e) => PrincipalPattern::Condition(subst(&e, b)),
        other => other,
    }
}

fn link_resource(p: ResourcePattern, b: &HashMap<String, Value>) -> ResourcePattern {
    match p {
        ResourcePattern::Condition(e) => ResourcePattern::Condition(subst(&e, b)),
        other => other,
    }
}

/// Recursively replace `Expr::Slot(name)` with the bound literal.
fn subst(e: &Expr, b: &HashMap<String, Value>) -> Expr {
    match e {
        Expr::Slot(name) => match b.get(name) {
            Some(v) => Expr::Literal(v.clone()),
            None => e.clone(),
        },
        Expr::BinaryOp { left, op, right } => Expr::BinaryOp {
            left: Box::new(subst(left, b)),
            op: *op,
            right: Box::new(subst(right, b)),
        },
        Expr::UnaryOp { op, operand } => Expr::UnaryOp {
            op: *op,
            operand: Box::new(subst(operand, b)),
        },
        Expr::FieldAccess { object, field } => Expr::FieldAccess {
            object: Box::new(subst(object, b)),
            field: field.clone(),
        },
        Expr::MethodCall { object, method, args } => Expr::MethodCall {
            object: Box::new(subst(object, b)),
            method: method.clone(),
            args: args.iter().map(|a| subst(a, b)).collect(),
        },
        Expr::FunctionCall { name, args } => Expr::FunctionCall {
            name: name.clone(),
            args: args.iter().map(|a| subst(a, b)).collect(),
        },
        Expr::List(items) => Expr::List(items.iter().map(|i| subst(i, b)).collect()),
        Expr::Dict(entries) => {
            Expr::Dict(entries.iter().map(|(k, v)| (k.clone(), subst(v, b))).collect())
        }
        Expr::Literal(_) | Expr::Variable(_) => e.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityStore;
    use crate::evaluator::eval_with_store;
    use crate::parser::parse_chai;

    #[test]
    fn link_fills_slots() {
        let template = parse_chai("permit when principal == ?principal and resource == ?resource\n").unwrap();

        let mut binding = HashMap::new();
        binding.insert("principal".to_string(), Value::EntityUid("User::alice".to_string()));
        binding.insert("resource".to_string(), Value::EntityUid("Doc::readme".to_string()));
        let linked = link(&template, &binding);

        let store = EntityStore::new();
        let mut ctx = HashMap::new();
        ctx.insert("principal".to_string(), Value::EntityUid("User::alice".to_string()));
        ctx.insert("resource".to_string(), Value::EntityUid("Doc::readme".to_string()));
        assert!(matches!(eval_with_store(&linked, ctx, &store).unwrap().effect, Effect::Allow));

        // A different principal does not match the linked instance.
        let mut ctx2 = HashMap::new();
        ctx2.insert("principal".to_string(), Value::EntityUid("User::bob".to_string()));
        ctx2.insert("resource".to_string(), Value::EntityUid("Doc::readme".to_string()));
        assert!(matches!(eval_with_store(&linked, ctx2, &store).unwrap().effect, Effect::Deny));
    }

    #[test]
    fn unlinked_slot_is_fail_closed() {
        // Evaluating a template without linking must not allow.
        let template = parse_chai("permit when principal == ?principal\n").unwrap();
        let store = EntityStore::new();
        let mut ctx = HashMap::new();
        ctx.insert("principal".to_string(), Value::EntityUid("User::alice".to_string()));
        let d = eval_with_store(&template, ctx, &store).unwrap();
        assert!(matches!(d.effect, Effect::Deny));
        assert!(!d.errors.is_empty(), "unlinked slot should surface an error");
    }
}
