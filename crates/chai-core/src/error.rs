use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum ChaiError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Type error: {0}")]
    TypeError(String),

    #[error("Evaluation error: {0}")]
    EvalError(String),

    #[error("Unknown entity: {0}")]
    UnknownEntity(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    /// An entity-resolver backend (Postgres/Redis/…) could not answer a lookup:
    /// a timeout, connection failure, or malformed response during evaluation of
    /// an `in`/entity expression. This is fail-closed: it becomes the `Err`
    /// outcome for the rule (same path as a detector failure), never a silent
    /// `false`/`None`.
    #[error("Resolver unavailable: {0}")]
    ResolverUnavailable(String),
}
