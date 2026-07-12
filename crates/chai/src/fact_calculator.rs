use chai_core::ast::Value;
use std::collections::HashMap;

/// Alignment Fact Calculator (AFC), the semantic sensor layer.
/// Produces structured alignment evidence from emissions.
/// Superseded by afc.rs. Prefer that module.
#[derive(Debug, Clone)]
pub struct AlignmentFacts {
    pub dlp_facts: DLPFacts,
    pub safety_facts: SafetyFacts,
    pub schema_facts: SchemaFacts,
    pub grounding_facts: GroundingFacts,
    pub tooltrace_facts: ToolTraceFacts,
    pub risk_facts: RiskFacts,
}

impl AlignmentFacts {
    /// Calculate all facts from output and context.
    pub fn calculate(
        output: &str,
        _subject: &SubjectRecord,
        object: &ObjectRecord,
        context: &ExecutionContext,
    ) -> Self {
        AlignmentFacts {
            dlp_facts: DLPFacts::calculate(output),
            safety_facts: SafetyFacts::calculate(output),
            schema_facts: SchemaFacts::calculate(output, object),
            grounding_facts: GroundingFacts::calculate(output, context),
            tooltrace_facts: ToolTraceFacts::from_context(context),
            risk_facts: RiskFacts::aggregate_all(output),
        }
    }

    /// Flatten to the HashMap ESP consumes.
    pub fn to_context(&self) -> HashMap<String, Value> {
        let mut context = HashMap::new();

        context.insert("dlp_facts".to_string(), self.dlp_facts.to_value());
        context.insert("safety_facts".to_string(), self.safety_facts.to_value());
        context.insert("schema_facts".to_string(), self.schema_facts.to_value());
        context.insert("grounding_facts".to_string(), self.grounding_facts.to_value());
        context.insert("tooltrace_facts".to_string(), self.tooltrace_facts.to_value());
        context.insert("risk_facts".to_string(), self.risk_facts.to_value());

        context
    }
}

/// Subject (agent) record.
#[derive(Debug, Clone)]
pub struct SubjectRecord {
    pub agent_id: String,
    pub model: String,
    pub capability: Vec<String>,
    pub role: Vec<String>,
    pub trust_tier: i64,
}

impl SubjectRecord {
    pub fn to_value(&self) -> Value {
        let mut dict = HashMap::new();
        dict.insert("agent_id".to_string(), Value::String(self.agent_id.clone()));
        dict.insert("model".to_string(), Value::String(self.model.clone()));
        dict.insert(
            "capability".to_string(),
            Value::List(
                self.capability
                    .iter()
                    .map(|c| Value::String(c.clone()))
                    .collect(),
            ),
        );
        dict.insert(
            "role".to_string(),
            Value::List(self.role.iter().map(|r| Value::String(r.clone())).collect()),
        );
        dict.insert("trust_tier".to_string(), Value::Int(self.trust_tier));
        Value::Dict(dict)
    }
}

/// Object (emission target) record.
#[derive(Debug, Clone)]
pub struct ObjectRecord {
    pub action: String,
    pub channel: String,
    pub destination: String,
    pub audience: String,
    pub persistence: bool,
}

impl ObjectRecord {
    pub fn to_value(&self) -> Value {
        let mut dict = HashMap::new();
        dict.insert("action".to_string(), Value::String(self.action.clone()));
        dict.insert("channel".to_string(), Value::String(self.channel.clone()));
        dict.insert("destination".to_string(), Value::String(self.destination.clone()));
        dict.insert("audience".to_string(), Value::String(self.audience.clone()));
        dict.insert("persistence".to_string(), Value::Bool(self.persistence));
        Value::Dict(dict)
    }
}

/// Execution context (session metadata).
#[derive(Debug, Clone, Default)]
pub struct ExecutionContext {
    pub session_id: String,
    pub timestamp: i64,
    pub trace: Vec<String>,
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub name: String,
    pub args: HashMap<String, String>,
    pub result: String,
}

// ============================================================================
// DLP facts. PII, secrets, credential matches.
// ============================================================================

#[derive(Debug, Clone)]
pub struct DLPFacts {
    pub pii_confidence: f64,
    pub secrets_found: bool,
    pub credential_matches: Vec<String>,
    pub entropy: f64,
}

impl DLPFacts {
    pub fn calculate(output: &str) -> Self {
        let pii_confidence = detect_pii(output);
        let secrets_found = detect_secrets(output);
        let credential_matches = detect_credentials(output);
        let entropy = calculate_entropy(output);

        DLPFacts {
            pii_confidence,
            secrets_found,
            credential_matches,
            entropy,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut dict = HashMap::new();
        dict.insert("pii_confidence".to_string(), Value::Float(self.pii_confidence));
        dict.insert("secrets_found".to_string(), Value::Bool(self.secrets_found));
        dict.insert(
            "credential_matches".to_string(),
            Value::List(
                self.credential_matches
                    .iter()
                    .map(|c| Value::String(c.clone()))
                    .collect(),
            ),
        );
        dict.insert("entropy".to_string(), Value::Float(self.entropy));
        Value::Dict(dict)
    }
}

// ============================================================================
// Safety facts. Harm category scores.
// ============================================================================

#[derive(Debug, Clone)]
pub struct SafetyFacts {
    pub harm: f64,
    pub bias: f64,
    pub toxicity: f64,
    pub jailbreak_attempt: bool,
}

impl SafetyFacts {
    pub fn calculate(output: &str) -> Self {
        SafetyFacts {
            harm: detect_harm(output),
            bias: detect_bias(output),
            toxicity: detect_toxicity(output),
            jailbreak_attempt: detect_jailbreak(output),
        }
    }

    pub fn to_value(&self) -> Value {
        let mut dict = HashMap::new();
        dict.insert("harm".to_string(), Value::Float(self.harm));
        dict.insert("bias".to_string(), Value::Float(self.bias));
        dict.insert("toxicity".to_string(), Value::Float(self.toxicity));
        dict.insert("jailbreak_attempt".to_string(), Value::Bool(self.jailbreak_attempt));
        Value::Dict(dict)
    }
}

// ============================================================================
// Schema facts. Structural validation results.
// ============================================================================

#[derive(Debug, Clone)]
pub struct SchemaFacts {
    pub valid_format: bool,
    pub schema_errors: Vec<String>,
    pub completeness: f64,
}

impl SchemaFacts {
    pub fn calculate(output: &str, _object: &ObjectRecord) -> Self {
        // Heuristic. Output must be non-empty and, if it looks like JSON, well-formed.
        let valid_format = !output.is_empty();
        let schema_errors = if output.starts_with('{') && !output.ends_with('}') {
            vec!["Incomplete JSON structure".to_string()]
        } else {
            vec![]
        };

        SchemaFacts {
            valid_format,
            schema_errors,
            completeness: if valid_format { 1.0 } else { 0.0 },
        }
    }

    pub fn to_value(&self) -> Value {
        let mut dict = HashMap::new();
        dict.insert("valid_format".to_string(), Value::Bool(self.valid_format));
        dict.insert(
            "schema_errors".to_string(),
            Value::List(
                self.schema_errors
                    .iter()
                    .map(|e| Value::String(e.clone()))
                    .collect(),
            ),
        );
        dict.insert("completeness".to_string(), Value::Float(self.completeness));
        Value::Dict(dict)
    }
}

// ============================================================================
// Grounding facts. Citation support metrics.
// ============================================================================

#[derive(Debug, Clone)]
pub struct GroundingFacts {
    pub has_citations: bool,
    pub citation_coverage: f64,
    pub cited_sources: Vec<String>,
    pub external_knowledge_ratio: f64,
}

impl GroundingFacts {
    pub fn calculate(output: &str, _context: &ExecutionContext) -> Self {
        let has_citations = output.contains("[") && output.contains("]");
        let cited_sources = extract_citations(output);
        let citation_coverage = if !output.is_empty() && has_citations {
            0.8
        } else {
            0.0
        };

        GroundingFacts {
            has_citations,
            citation_coverage,
            cited_sources,
            external_knowledge_ratio: 0.5,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut dict = HashMap::new();
        dict.insert("has_citations".to_string(), Value::Bool(self.has_citations));
        dict.insert("citation_coverage".to_string(), Value::Float(self.citation_coverage));
        dict.insert(
            "cited_sources".to_string(),
            Value::List(
                self.cited_sources
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        dict.insert(
            "external_knowledge_ratio".to_string(),
            Value::Float(self.external_knowledge_ratio),
        );
        Value::Dict(dict)
    }
}

// ============================================================================
// Tooltrace facts. Attempted external actions.
// ============================================================================

#[derive(Debug, Clone)]
pub struct ToolTraceFacts {
    pub tools_called: Vec<String>,
    pub tool_count: i64,
    pub last_tool: Option<String>,
}

impl ToolTraceFacts {
    pub fn from_context(context: &ExecutionContext) -> Self {
        let tools_called = context.tool_calls.iter().map(|t| t.name.clone()).collect();
        let tool_count = context.tool_calls.len() as i64;
        let last_tool = context.tool_calls.last().map(|t| t.name.clone());

        ToolTraceFacts {
            tools_called,
            tool_count,
            last_tool,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut dict = HashMap::new();
        dict.insert(
            "tools_called".to_string(),
            Value::List(
                self.tools_called
                    .iter()
                    .map(|t| Value::String(t.clone()))
                    .collect(),
            ),
        );
        dict.insert("tool_count".to_string(), Value::Int(self.tool_count));
        dict.insert(
            "last_tool".to_string(),
            match &self.last_tool {
                Some(t) => Value::String(t.clone()),
                None => Value::String("none".to_string()),
            },
        );
        Value::Dict(dict)
    }
}

// ============================================================================
// Risk facts. Aggregated alignment risk indicators.
// ============================================================================

#[derive(Debug, Clone)]
pub struct RiskFacts {
    pub overall_risk: f64,
    pub risk_factors: Vec<String>,
    pub risk_level: String, // "low" | "medium" | "high" | "critical"
}

impl RiskFacts {
    pub fn aggregate_all(output: &str) -> Self {
        let pii = detect_pii(output);
        let harm = detect_harm(output);
        let secrets = detect_secrets(output);

        let overall_risk = (pii * 0.4 + harm * 0.4 + if secrets { 1.0 } else { 0.0 } * 0.2)
            .min(1.0);

        let mut risk_factors = Vec::new();
        if pii > 0.5 {
            risk_factors.push("high_pii_confidence".to_string());
        }
        if harm > 0.5 {
            risk_factors.push("high_harm_score".to_string());
        }
        if secrets {
            risk_factors.push("secrets_detected".to_string());
        }

        let risk_level = match overall_risk {
            r if r > 0.75 => "critical",
            r if r > 0.5 => "high",
            r if r > 0.25 => "medium",
            _ => "low",
        }
        .to_string();

        RiskFacts {
            overall_risk,
            risk_factors,
            risk_level,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut dict = HashMap::new();
        dict.insert("overall_risk".to_string(), Value::Float(self.overall_risk));
        dict.insert(
            "risk_factors".to_string(),
            Value::List(
                self.risk_factors
                    .iter()
                    .map(|f| Value::String(f.clone()))
                    .collect(),
            ),
        );
        dict.insert("risk_level".to_string(), Value::String(self.risk_level.clone()));
        Value::Dict(dict)
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn detect_pii(text: &str) -> f64 {
    let pii_patterns = [
        "ssn", "social security", "credit card", "password", "api key",
        "phone number", "email", "address", "zip code"
    ];
    let matches = pii_patterns
        .iter()
        .filter(|p| text.to_lowercase().contains(**p))
        .count();
    (matches as f64 / pii_patterns.len() as f64).min(1.0)
}

fn detect_secrets(text: &str) -> bool {
    let secret_patterns = ["secret:", "password:", "api_key:", "token:", "private_key"];
    secret_patterns
        .iter()
        .any(|p| text.to_lowercase().contains(p))
}

fn detect_credentials(text: &str) -> Vec<String> {
    let mut credentials = Vec::new();
    if text.to_lowercase().contains("password:") {
        credentials.push("password".to_string());
    }
    if text.to_lowercase().contains("api_key:") {
        credentials.push("api_key".to_string());
    }
    if text.to_lowercase().contains("token:") {
        credentials.push("token".to_string());
    }
    credentials
}

fn calculate_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut frequencies = HashMap::new();
    for c in text.chars() {
        *frequencies.entry(c).or_insert(0) += 1;
    }

    let len = text.len() as f64;
    let entropy = frequencies
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum::<f64>();

    entropy
}

fn detect_harm(text: &str) -> f64 {
    let harmful_keywords = ["violence", "illegal", "harm", "danger", "attack"];
    let matches = harmful_keywords
        .iter()
        .filter(|kw| text.to_lowercase().contains(**kw))
        .count();
    (matches as f64 / harmful_keywords.len() as f64).min(1.0)
}

fn detect_bias(text: &str) -> f64 {
    let bias_keywords = ["always", "never", "all", "none"];
    let matches = bias_keywords
        .iter()
        .filter(|kw| text.to_lowercase().contains(**kw))
        .count();
    (matches as f64 / bias_keywords.len() as f64).min(1.0)
}

fn detect_toxicity(text: &str) -> f64 {
    let toxic_keywords = ["hate", "offensive", "discriminat"];
    let matches = toxic_keywords
        .iter()
        .filter(|kw| text.to_lowercase().contains(**kw))
        .count();
    (matches as f64 / toxic_keywords.len() as f64).min(1.0)
}

fn detect_jailbreak(_text: &str) -> bool {
    // Stub. Always false for now.
    false
}

fn extract_citations(text: &str) -> Vec<String> {
    let mut citations = Vec::new();
    for part in text.split(']') {
        if let Some(start) = part.rfind('[') {
            let citation = part[start + 1..].to_string();
            if !citation.is_empty() {
                citations.push(citation);
            }
        }
    }
    citations
}
