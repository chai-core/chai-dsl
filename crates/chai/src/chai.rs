//! Chai, the agent orchestration layer at the top of the three-layer stack.
//!
//! Chai is the agent that produces draft output and tool actions. It drives the
//! full pipeline. For each step the agent emits, Chai accumulates the output
//! prefix, asks AFC for facts `F_t`, and runs the chunk through the ESP and
//! Emission enforcer. The agent is pluggable; a real LLM implements `Agent` and
//! `ScriptedAgent` stands in for tests/demos.
//!
//!   Agent (Chai) -> AFC -> ESP -> Emission -> sink
//!
//! Subject/object bindings live in the evaluation context, so subject checks
//! (capabilities, trust tier) are ordinary ESP rules with no separate code path.

use crate::afc::{Afc, ToolCall};
use chai_core::ast::{ChaiProgram, Decision, Value};
use chai_core::emission::{EmissionEnforcer, EmitAction};
use chai_core::entity::EntityStore;
use std::collections::HashMap;

/// One unit of agent output. Text plus any external actions taken alongside it.
pub struct AgentStep {
    pub text: String,
    pub tools: Vec<ToolCall>,
}

impl AgentStep {
    pub fn text(s: impl Into<String>) -> Self {
        AgentStep { text: s.into(), tools: Vec::new() }
    }
    pub fn with_tool(mut self, name: impl Into<String>, ok: bool) -> Self {
        self.tools.push(ToolCall { name: name.into(), ok });
        self
    }
}

/// Produces a stream of steps. A real LLM/agent implements this.
pub trait Agent {
    fn next_step(&mut self) -> Option<AgentStep>;
}

/// A fixed, replayable script of steps. Stands in for a real model.
pub struct ScriptedAgent {
    steps: std::vec::IntoIter<AgentStep>,
}

impl ScriptedAgent {
    pub fn new(steps: Vec<AgentStep>) -> Self {
        ScriptedAgent { steps: steps.into_iter() }
    }
}

impl Agent for ScriptedAgent {
    fn next_step(&mut self) -> Option<AgentStep> {
        self.steps.next()
    }
}

/// Result of running the full stack.
pub struct ChaiOutcome {
    /// What actually reached the sink (emitted/redacted, fail-closed).
    pub released: String,
    /// Per-step ESP decisions, the audit trail.
    pub decisions: Vec<Decision>,
    /// Names of tools the agent attempted.
    pub tools_seen: Vec<String>,
}

/// Drive an agent through AFC → ESP → Emission and collect the outcome.
pub fn run_chai(
    program: &ChaiProgram,
    store: &EntityStore,
    subject_object_ctx: HashMap<String, Value>,
    afc: &Afc,
    agent: &mut dyn Agent,
) -> ChaiOutcome {
    let mut enforcer = EmissionEnforcer::new(program, store, subject_object_ctx);
    let mut prefix = String::new();
    let mut tools: Vec<ToolCall> = Vec::new();
    let mut released = String::new();
    let mut t = 0u64;

    while let Some(step) = agent.next_step() {
        prefix.push_str(&step.text);
        tools.extend(step.tools);

        // AFC computes facts over the full prefix plus execution context so far.
        let bundle = afc.compute_with_tools(&prefix, t, &tools);
        // ESP decides, Emission enforces.
        match enforcer.step(&step.text, bundle.to_context()) {
            EmitAction::Emit(s) | EmitAction::Redact(s) => released.push_str(&s),
            EmitAction::Buffer | EmitAction::Drop | EmitAction::RequireHuman => {}
        }
        t += 1;
    }
    let _ = enforcer.finish();

    ChaiOutcome {
        released,
        decisions: enforcer.history().to_vec(),
        tools_seen: tools.into_iter().map(|tc| tc.name).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chai_core::parser::parse_chai;

    #[test]
    fn full_stack_is_fail_closed() {
        // Subject gate + PII gate, all as ordinary ESP rules.
        let policy = "\
@id(\"trusted\") forbid when subject.trust_tier < 2
@id(\"pii\") deny when dlp_facts.pii_confidence > 0.8
@id(\"ok\") permit when dlp_facts.pii_confidence < 0.8
";
        let program = parse_chai(policy).unwrap();
        let store = EntityStore::new();

        // subject s with trust tier 3.
        let mut subject = HashMap::new();
        subject.insert("trust_tier".to_string(), Value::Int(3));
        let mut ctx = HashMap::new();
        ctx.insert("subject".to_string(), Value::Dict(subject));

        let afc = Afc::with_default_detectors();
        let mut agent = ScriptedAgent::new(vec![
            AgentStep::text("All clear so far. ").with_tool("db.read", true),
            AgentStep::text("the ssn and email are leaked"), // trips PII, drop
        ]);

        let outcome = run_chai(&program, &store, ctx, &afc, &mut agent);

        assert!(outcome.released.contains("All clear"));
        assert!(!outcome.released.contains("ssn"));
        assert_eq!(outcome.decisions.len(), 2);
        assert_eq!(outcome.tools_seen, vec!["db.read".to_string()]);
    }
}
