//! chai-core: the verified decision-and-emission engine.
//!
//! This is the engine the `formal/` proofs and the DRT harness cover, and the
//! foil to AWS Bedrock AgentCore: a verified runtime, not just an analyzable
//! language. The runtime/exposure layer (detectors, CLI, sidecar, wire surfaces)
//! lives in the `chai_dsl` crate on top of this one.

pub mod ast;
pub mod error;
pub mod parser;
pub mod evaluator;
pub mod emission;
pub mod entity;
pub mod taint;
pub mod template;
pub mod schema;
pub mod analysis;
pub mod pam;
#[cfg(feature = "smt")]
pub mod smt;
