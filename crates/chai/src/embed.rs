//! In-process evaluation helpers shared by the native C ABI (`ffi`, feature
//! `capi`) and the WASM export (feature `wasm`). One code path, so the proofs and
//! differential tests cover every embedding.
//!
//! Two entry points cover all three policy paradigms:
//!   * [`evaluate_json`] runs a policy. It honors the `mode` directive, so it
//!     covers both the default Cedar deny-override and the ACL `first_match` mode.
//!   * [`pam_decide_json`] runs a PAM guard stack (required/requisite/sufficient/
//!     optional).

use chai_core::ast::{ChaiProgram, Expr, Value};
use chai_core::entity::json_to_value;
use chai_core::evaluator::Evaluator;
use chai_core::pam::{eval_guard, parse_flag, Flag};
use crate::{eval_with_strategy, parse_chai, parse_chai_with_mode, EntityStore};
use std::collections::HashMap;

/// Parse a JSON object of request bindings and facts into an eval context.
pub fn context_from_json(context_json: &str) -> Result<HashMap<String, Value>, String> {
    match serde_json::from_str::<serde_json::Value>(context_json).map_err(|e| e.to_string())? {
        serde_json::Value::Object(m) => Ok(m.iter().map(|(k, v)| (k.clone(), json_to_value(v))).collect()),
        _ => Err("context must be a JSON object".into()),
    }
}

/// Parse one boolean condition (as written after `when`) into an AST node.
fn condition_from_str(src: &str) -> Result<Expr, String> {
    match parse_chai(&format!("permit when {src}\n")).map_err(|e| e.to_string())? {
        ChaiProgram::SingleLineRules(rules) => rules
            .into_iter()
            .next()
            .and_then(|r| r.condition)
            .ok_or_else(|| "empty condition".to_string()),
        _ => Err("expected a single-line rule".into()),
    }
}

/// Evaluate `policy` against `context_json`, honoring the `mode` directive
/// (deny-override by default, or `first_match` for ACL policies). Returns a JSON
/// decision string:
///
/// ```json
/// {"effect": "Allow", "reason": "...", "rule_trace": ["ok"], "errors": []}
/// ```
///
/// Fail-closed: a parse error, a non-object context, or an evaluation error
/// becomes `{"parse_error": "..."}`, never a silent allow.
pub fn evaluate_json(policy: &str, context_json: &str) -> String {
    let result: Result<serde_json::Value, String> = (|| {
        let (strategy, program) = parse_chai_with_mode(policy).map_err(|e| format!("{e}"))?;
        let ctx = context_from_json(context_json)?;
        let d = eval_with_strategy(&program, ctx, &EntityStore::new(), strategy).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "effect": format!("{:?}", d.effect),
            "reason": d.reason,
            "rule_trace": d.rule_trace,
            "errors": d.errors,
        }))
    })();
    match result {
        Ok(v) => v.to_string(),
        Err(e) => serde_json::json!({ "parse_error": e }).to_string(),
    }
}

/// Evaluate a PAM guard against `context_json`. `guard_json` is an array of
/// tagged checks:
///
/// ```json
/// [{"flag": "required",   "when": "subject.trust_tier >= 2"},
///  {"flag": "sufficient", "when": "subject.role == \"senior\""},
///  {"flag": "sufficient", "when": "args.amount <= 100"}]
/// ```
///
/// Returns `{"pass": true}` or `{"pass": false}`. Fail-closed: any error yields
/// `{"pass": false, "parse_error": "..."}`.
pub fn pam_decide_json(guard_json: &str, context_json: &str) -> String {
    let result: Result<bool, String> = (|| {
        let spec: Vec<serde_json::Value> = serde_json::from_str(guard_json).map_err(|e| e.to_string())?;
        let ctx = context_from_json(context_json)?;
        let store = EntityStore::new();
        let ev = Evaluator::new(&store).with_context(ctx);
        let mut stack: Vec<(Flag, Expr)> = Vec::with_capacity(spec.len());
        for entry in &spec {
            let flag_s = entry.get("flag").and_then(|f| f.as_str()).ok_or("guard entry missing \"flag\"")?;
            let flag = parse_flag(flag_s).ok_or_else(|| format!("unknown flag {flag_s:?}"))?;
            let cond_s = entry.get("when").and_then(|w| w.as_str()).ok_or("guard entry missing \"when\"")?;
            stack.push((flag, condition_from_str(cond_s)?));
        }
        Ok(eval_guard(&stack, &ev))
    })();
    match result {
        Ok(pass) => serde_json::json!({ "pass": pass }).to_string(),
        Err(e) => serde_json::json!({ "pass": false, "parse_error": e }).to_string(),
    }
}
