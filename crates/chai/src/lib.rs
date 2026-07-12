//! chai_dsl: the policy language and runtime, layered on the verified `chai-core`
//! engine. Re-exports keep the public API stable after the workspace split.

// The verified engine. Re-exported so `chai_dsl::ast`, `chai_dsl::evaluator`, etc.
// keep resolving exactly as before the split.
pub use chai_core::{
    analysis, ast, emission, entity, error, evaluator, parser, pam, schema, taint, template,
};
#[cfg(feature = "smt")]
pub use chai_core::smt;

// The runtime / exposure layer on top of the engine.
pub mod agent_verifier;
pub mod streaming;
pub mod afc;
pub mod chai;
pub mod mcp;
pub mod runtime;
pub mod mcp_contract;
pub mod cli;
pub mod embed;
#[cfg(feature = "capi")]
pub mod ffi;
#[cfg(feature = "grpc")]
pub mod grpc_authz;
#[cfg(feature = "icap")]
pub mod icap;
#[cfg(feature = "wasm")]
pub mod wasm;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "postgres")]
pub mod pg_store;
#[cfg(feature = "redis")]
pub mod redis_store;
pub mod fact_calculator;
pub mod session;

// Public API re-exports (unchanged from before the split).
pub use chai_core::parser::{parse_chai, parse_chai_with_mode};
pub use chai_core::evaluator::{eval, eval_with_store, eval_with_strategy, EvalStrategy};
pub use chai_core::entity::{Entity, EntityResolver, EntityStore};
pub use chai_core::error::ChaiError;
pub use chai_core::emission::{EmissionEnforcer, EmitAction};
pub use chai_core::template::link;
pub use chai_core::schema::{Schema, Ty, ValidationError};
pub use agent_verifier::{AgentContext, AgentVerifier, AgentConstraints, RateLimiter, verify_agent_action};
pub use streaming::{StreamingEvaluator, StreamingDecision};
pub use session::SessionBudget;
pub use afc::{
    Afc, Detector, Evidence, FactBundle, InjectionDetector, LakeraDetector, LlamaGuardDetector,
    PresidioDetector, RemoteCall, Source, StreamingAfc,
};
pub use chai::{run_chai, Agent, AgentStep, ChaiOutcome, ScriptedAgent};
pub use mcp::{authorize_tool_call, filter_tool_result, AgentSubject, ResultDecision};
pub use runtime::{
    settle, AuditSink, JsonlAuditSink, MemoryAuditSink, ObligationExecutor, ObligationReport,
};
pub use fact_calculator::{
    AlignmentFacts, SubjectRecord, ObjectRecord, ExecutionContext, ToolCall,
    DLPFacts, SafetyFacts, SchemaFacts, GroundingFacts, ToolTraceFacts, RiskFacts,
};
