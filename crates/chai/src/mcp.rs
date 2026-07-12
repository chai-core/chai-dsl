//! MCP boundary interceptors. The connective tissue between the safety layer and
//! an MCP/agent system.
//!
//! The functional code (MCP servers, agent reasoning) stays safety-agnostic and
//! calls these at two boundaries:
//!   * `authorize_tool_call` (agent to tool): may this agent invoke this tool?
//!   * `filter_tool_result`  (tool to agent/user): may this result be released,
//!     and if so, redacted or deferred?
//!
//! Both are thin bindings over the ESP evaluator, AFC, and Emission. They shape
//! an MCP request/result into the policy evaluation context.

use crate::afc::Afc;
use chai_core::ast::{ChaiProgram, Decision, Value};
use chai_core::emission::{EmissionEnforcer, EmitAction};
use chai_core::entity::EntityStore;
use chai_core::error::ChaiError;
use std::collections::HashMap;

/// The acting agent. A UID for ReBAC (`principal in ...`) plus attributes for
/// ABAC conditions (`subject.trust_tier`, `subject.capabilities contains ...`).
#[derive(Debug, Clone)]
pub struct AgentSubject {
    pub uid: String,
    pub attrs: HashMap<String, Value>,
}

impl AgentSubject {
    pub fn new(uid: impl Into<String>) -> Self {
        AgentSubject { uid: uid.into(), attrs: HashMap::new() }
    }
    pub fn attr(mut self, key: impl Into<String>, value: Value) -> Self {
        self.attrs.insert(key.into(), value);
        self
    }
}

/// Bind the agent into the eval context as both `principal` (UID, for ReBAC) and
/// `subject` (attributes, for ABAC), plus `action`.
pub(crate) fn base_context(subject: &AgentSubject, tool: &str) -> HashMap<String, Value> {
    let mut ctx = HashMap::new();
    ctx.insert("principal".to_string(), Value::EntityUid(subject.uid.clone()));
    ctx.insert("subject".to_string(), Value::Dict(subject.attrs.clone()));
    ctx.insert("action".to_string(), Value::String(tool.to_string()));
    ctx
}

/// Agent to tool. Authorize an MCP tool invocation. The policy sees `principal`,
/// `subject`, `action` (the tool name), `args`, and optionally `resource`.
pub fn authorize_tool_call(
    program: &ChaiProgram,
    store: &EntityStore,
    subject: &AgentSubject,
    tool: &str,
    args: &HashMap<String, Value>,
    resource: Option<&str>,
) -> Result<Decision, ChaiError> {
    let mut ctx = base_context(subject, tool);
    ctx.insert("args".to_string(), Value::Dict(args.clone()));
    if let Some(r) = resource {
        ctx.insert("resource".to_string(), Value::EntityUid(r.to_string()));
    }
    chai_core::evaluator::eval_with_store(program, ctx, store)
}

/// What to do with a tool result, plus the decision that produced it.
pub struct ResultDecision {
    pub action: EmitAction,
    pub decision: Decision,
}

/// Tool to agent/user. Run a tool's result through AFC, ESP, and Emission. Compute
/// facts over the result, decide, and return the emission action (emit / redact /
/// drop / buffer / require-human). Fail-closed.
pub fn filter_tool_result(
    program: &ChaiProgram,
    store: &EntityStore,
    afc: &Afc,
    subject: &AgentSubject,
    tool: &str,
    result: &str,
) -> ResultDecision {
    let facts = afc.compute(result, 0);
    let mut enforcer = EmissionEnforcer::new(program, store, base_context(subject, tool));
    let action = enforcer.step(result, facts.to_context());
    let decision = enforcer
        .history()
        .first()
        .cloned()
        .expect("one decision was just recorded");
    ResultDecision { action, decision }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chai_core::ast::Effect;
    use chai_core::parser::parse_chai;

    fn agent(tier: i64) -> AgentSubject {
        AgentSubject::new("Agent::a1").attr("trust_tier", Value::Int(tier))
    }

    #[test]
    fn tool_call_authorization() {
        // Only trust tier >= 3 may call write tools.
        let policy = "\
@id(\"untrusted\") forbid when subject.trust_tier < 3
@id(\"ok\")        permit when subject.trust_tier >= 3
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();
        let args = HashMap::new();

        let d = authorize_tool_call(&program, &store, &agent(4), "db.write", &args, None).unwrap();
        assert!(matches!(d.effect, Effect::Allow));

        let d = authorize_tool_call(&program, &store, &agent(1), "db.write", &args, None).unwrap();
        assert!(matches!(d.effect, Effect::Deny));
        assert_eq!(d.rule_trace, vec!["untrusted".to_string()]);
    }

    #[test]
    fn tool_result_emission_filter() {
        // Redact PII-laden tool results. Drop secrets.
        let policy = "\
@id(\"secret\") deny   when dlp_facts.secrets_found == true
@id(\"pii\")    redact when dlp_facts.pii_confidence > 0.4
@id(\"clean\")  permit when dlp_facts.pii_confidence <= 0.4
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();
        let afc = Afc::with_default_detectors();

        let clean = filter_tool_result(&program, &store, &afc, &agent(5), "db.read", "row count: 42");
        assert!(matches!(clean.action, EmitAction::Emit(_)));

        // Real PII values: the span-masker localizes them, so the result is
        // released redacted (masked), not verbatim.
        let leaky = filter_tool_result(
            &program, &store, &afc, &agent(5), "db.read",
            "ssn 123-45-6789 email a@b.co on file",
        );
        match &leaky.action {
            EmitAction::Redact(s) => {
                assert!(!s.contains("123-45-6789") && !s.contains("a@b.co"));
            }
            other => panic!("expected redacted release, got {other:?}"),
        }

        // PII *words* but no maskable *value*: redaction removes nothing, so the
        // decision fails closed and the chunk is dropped rather than leaked.
        let word_only = filter_tool_result(&program, &store, &afc, &agent(5), "db.read", "ssn and email on file");
        assert!(matches!(word_only.action, EmitAction::Drop));

        let secret = filter_tool_result(&program, &store, &afc, &agent(5), "vault.read", "password: hunter2");
        assert!(matches!(secret.action, EmitAction::Drop));
    }
}
