use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    List(Vec<Value>),
    Dict(HashMap<String, Value>),
    /// Reference to an entity in the EntityStore by its UID. Kept separate from
    /// String so the evaluator resolves attributes and hierarchy (`in`) against
    /// the store.
    EntityUid(String),
    /// IP extension type. Holds the address or CIDR string, e.g. "10.0.0.0/24".
    Ip(String),
    /// Decimal extension type. Fixed-point with 4 fractional digits, stored as
    /// value * 10_000 (0.75 becomes 7500). Same precision as Cedar.
    Decimal(i64),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Type {
    Bool,
    Int,
    Float,
    String,
    List(Box<Type>),
    Dict(Box<Type>),
    Agent,
    Resource,
    Decision,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
    Forbid,  // Cedar deny-overrides
    Redact,
    Defer,
    RequireHuman,
    Downgrade,
}

impl Effect {
    /// A restrictive effect narrows or blocks emission (anything other than an
    /// unqualified permit). Under effect-tagged error semantics, a condition
    /// error on a restrictive rule contributes that effect ("could not check the
    /// restriction, so restrict"); a permit is the only non-restrictive effect.
    pub fn is_restrictive(self) -> bool {
        self != Effect::Allow
    }

    /// A releasing effect puts (possibly transformed) content on the sink:
    /// `Allow` (verbatim), `Downgrade` (reduced), `Redact` (masked). `Defer`,
    /// `RequireHuman`, `Deny`/`Forbid` release nothing.
    pub fn is_releasing(self) -> bool {
        matches!(self, Effect::Allow | Effect::Downgrade | Effect::Redact)
    }

    /// Restrictiveness rank; higher = more restrictive. Mirrors the lattice
    /// `DENY > REQUIRE_HUMAN > DEFER > REDACT > DOWNGRADE > ALLOW`. Used to
    /// accumulate release transforms "at-or-below the verdict".
    pub fn rank(self) -> u8 {
        match self {
            Effect::Allow => 0,
            Effect::Downgrade => 1,
            Effect::Redact => 2,
            Effect::Defer => 3,
            Effect::RequireHuman => 4,
            Effect::Deny | Effect::Forbid => 5,
        }
    }
}

/// How a condition-evaluation error on a rule feeds the decision. Effect-tagged
/// errors: a `Strict` error contributes the rule's effect (XACML `Indeterminate`
/// specialized to the erroring rule's decision); a `Lenient` error is inert
/// (recorded for audit, contributes nothing). Restrictive effects default to
/// `Strict`; permit defaults to `Lenient` (a permit error can never grant, so it
/// is inert either way).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorMode {
    Strict,
    Lenient,
}

impl ErrorMode {
    /// The default error mode for an effect when the rule carries no explicit
    /// `strict`/`lenient` annotation.
    pub fn default_for(effect: Effect) -> ErrorMode {
        if effect.is_restrictive() {
            ErrorMode::Strict
        } else {
            ErrorMode::Lenient
        }
    }
}

/// Evidence tier: the provenance-and-trust level of a fact. Ordered by trust:
/// `Measured` < `Derived` < `Attested`. *Measured* facts are detector outputs (a
/// classifier estimate, with confidence); *derived* facts are runtime-computed
/// (taint joins, counters, a clock read); *attested* facts are signature-verified
/// (approvals, tokens, mandates). A per-rule minimum-tier annotation gates a guard,
/// so a `permit requires attested` can never fire from measured or derived
/// evidence. Signature verification thereby joins the trusted base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    Measured,
    Derived,
    Attested,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub effect: Effect,
    pub reason: String,
    pub reason_codes: Vec<String>,  // policy justification identifiers
    pub obligations: Vec<String>,
    pub rule_trace: Vec<String>,
    /// Errors hit while deciding, e.g. a rule whose condition raised a type
    /// error. We record them so a broken policy is never mistaken for a clean
    /// deny. Same shape as Cedar's per-response error diagnostics.
    pub errors: Vec<String>,
    /// Seal-on-presence: whether a `require_human` rule was among the matched (or
    /// strictly-errored) outcomes, regardless of which effect won the join. The
    /// emission runtime seals the stream whenever this holds, so a chunk that
    /// trips both `deny` and `require_human` is dropped *and* the stream seals
    /// for review (the more alarming evidence never produces a weaker response).
    #[serde(default)]
    pub require_human_present: bool,
    /// Accumulated release *transforms* (the obligation set). When the verdict is a
    /// releasing effect, every matched releasing rule at-or-below the verdict
    /// contributes its transform, in ascending-rank order (`Downgrade` before
    /// `Redact`). So a chunk matching both `redact`(SSN) and `downgrade`(labels)
    /// has both applied to the release, not just the winning one. Empty for a
    /// non-releasing verdict or a pure `Allow`. `Allow` is identity and never
    /// listed. See [`Effect::is_releasing`].
    #[serde(default)]
    pub transforms: Vec<Effect>,
    pub metadata: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    Literal(Value),
    Variable(String),
    BinaryOp {
        left: Box<Expr>,
        op: BinaryOp,
        right: Box<Expr>,
    },
    UnaryOp {
        op: UnaryOp,
        operand: Box<Expr>,
    },
    FieldAccess {
        object: Box<Expr>,
        field: String,
    },
    MethodCall {
        object: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },
    FunctionCall {
        name: String,
        args: Vec<Expr>,
    },
    List(Vec<Expr>),
    Dict(Vec<(String, Expr)>),
    /// Template slot, e.g. `?principal`. Must be filled by `link` before
    /// evaluation. Evaluating an unlinked slot is an error (fail-closed).
    Slot(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum BinaryOp {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    // Comparison
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    // Logical
    And,
    Or,
    // Cedar Collection operators
    In,        // x in [...]
    Has,       // obj.attrs has x
    Contains,  // str contains substr
    Like,      // str like pattern
    Is,        // entity is Type. Type test, RHS is a type-name string literal
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: Option<String>,
    pub effect: Effect,
    pub principal: Option<PrincipalPattern>,
    pub action: Option<ActionPattern>,
    pub resource: Option<ResourcePattern>,
    pub condition: Option<Expr>,
    pub obligations: Vec<String>,
    /// Explicit `strict`/`lenient` error annotation, or `None` for the
    /// effect-derived default (see [`ErrorMode::default_for`]).
    #[serde(default)]
    pub error_mode: Option<ErrorMode>,
    /// Minimum evidence tier the guard's facts must meet for this rule to fire
    /// (`requires attested`). `None` means ungated. A gated rule that reads any
    /// fact below the required tier does not fire (fail-closed for a permit).
    #[serde(default)]
    pub min_tier: Option<Tier>,
}

impl Rule {
    /// The resolved error mode: the explicit annotation if present, else the
    /// effect default.
    pub fn resolved_error_mode(&self) -> ErrorMode {
        self.error_mode.unwrap_or_else(|| ErrorMode::default_for(self.effect))
    }

    /// Whether a condition-evaluation error on this rule contributes its effect
    /// to the decision. True only for a strict, restrictive rule. A permit error
    /// or a lenient rule is inert.
    pub fn error_contributes(&self) -> bool {
        self.effect.is_restrictive() && self.resolved_error_mode() == ErrorMode::Strict
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrincipalPattern {
    Any,
    Eq(String),           // principal == "user-123"
    In(String),           // principal in Group::"admin"
    Like(String),         // principal like "user-*"
    Condition(Expr),      // principal.trust_tier > 3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionPattern {
    Any,
    Eq(String),           // action == "emit"
    In(Vec<String>),      // action in ["emit", "plan"]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourcePattern {
    Any,
    Eq(String),           // resource == "channel-public"
    In(String),           // resource in Channel::"public"
    Like(String),         // resource like "channel-*"
    Condition(Expr),      // resource.sensitivity == "low"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub id: String,
    pub entity_type: String,
    pub attributes: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub entities: HashMap<String, HashMap<String, Entity>>,
    pub thresholds: HashMap<String, Value>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaiProgram {
    SingleLineRules(Vec<Rule>),
    StructuredRules(Policy),
    HierarchicalConfig(Config),
}
