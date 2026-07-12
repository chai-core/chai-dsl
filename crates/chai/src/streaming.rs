//! Superseded. Prefer `afc.rs` for fact computation and `emission.rs` for the
//! streaming state machine. Kept for reference.

use chai_core::ast::{Decision, Effect, Value, ChaiProgram};
use chai_core::entity::EntityStore;
use chai_core::evaluator::eval_rules;
use chai_core::error::ChaiError;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct StreamingDecision {
    pub effect: Effect,
    pub reason: String,
    pub prefix: String,
    pub tokens_processed: usize,
}

pub struct StreamingEvaluator {
    program: ChaiProgram,
    context: HashMap<String, Value>,
    buffer: String,
    decision_cache: Option<Decision>,
}

impl StreamingEvaluator {
    pub fn new(program: ChaiProgram, context: HashMap<String, Value>) -> Self {
        StreamingEvaluator {
            program,
            context,
            buffer: String::new(),
            decision_cache: None,
        }
    }

    /// Push a token and evaluate the policy on the new prefix.
    pub fn process_token(&mut self, token: &str) -> Result<StreamingDecision, ChaiError> {
        self.buffer.push_str(token);

        let prefix_facts = self.calculate_prefix_facts(&self.buffer);

        let mut eval_context = self.context.clone();
        for (key, value) in prefix_facts {
            eval_context.insert(key, value);
        }

        match eval_rules_for_streaming(&self.program, eval_context)? {
            (effect, reason) => {
                // Cache the decision once it's final (forbid/allow/deny).
                if matches!(effect, Effect::Allow | Effect::Forbid | Effect::Deny) {
                    self.decision_cache = Some(Decision {
                        effect: effect.clone(),
                        reason: reason.clone(),
                        reason_codes: vec![format!("{:?}", effect).to_lowercase()],
                        obligations: Vec::new(),
                        rule_trace: vec![],
                        errors: Vec::new(),
                        require_human_present: false,
                        transforms: Vec::new(),
                        metadata: HashMap::new(),
                    });
                }

                Ok(StreamingDecision {
                    effect,
                    reason,
                    prefix: self.buffer.clone(),
                    tokens_processed: self.buffer.len(),
                })
            }
        }
    }

    /// The cached final decision, if one has been reached.
    pub fn get_decision(&self) -> Option<Decision> {
        self.decision_cache.clone()
    }

    /// Compute facts about the output prefix.
    fn calculate_prefix_facts(&self, prefix: &str) -> HashMap<String, Value> {
        let mut facts = HashMap::new();

        // Basic prefix statistics.
        facts.insert(
            "prefix_length".to_string(),
            Value::Int(prefix.len() as i64),
        );
        facts.insert(
            "token_count".to_string(),
            Value::Int(prefix.split_whitespace().count() as i64),
        );

        let dlp_facts = calculate_dlp_facts(prefix);
        facts.insert("dlp_facts".to_string(), Value::Dict(dlp_facts));

        let safety_facts = calculate_safety_facts(prefix);
        facts.insert("safety_facts".to_string(), Value::Dict(safety_facts));

        facts
    }
}

fn eval_rules_for_streaming(
    program: &ChaiProgram,
    context: HashMap<String, Value>,
) -> Result<(Effect, String), ChaiError> {
    let rules = match program {
        ChaiProgram::SingleLineRules(rules) => rules.clone(),
        ChaiProgram::StructuredRules(policy) => policy.rules.clone(),
        ChaiProgram::HierarchicalConfig(config) => config.rules.clone(),
    };

    // Streaming policies operate on facts in the context. There is no entity store.
    let store = EntityStore::new();
    match eval_rules(&rules, context, &store) {
        Ok(decision) => Ok((decision.effect, decision.reason)),
        Err(e) => Err(e),
    }
}

/// Compute DLP (Data Loss Prevention) facts about the output.
fn calculate_dlp_facts(prefix: &str) -> HashMap<String, Value> {
    let mut facts = HashMap::new();

    // Crude PII check.
    let pii_indicators = ["ssn", "social security", "credit card", "password", "api key"];
    let has_pii = pii_indicators
        .iter()
        .any(|indicator| prefix.to_lowercase().contains(indicator));

    let pii_confidence = if has_pii { 0.95 } else { 0.05 };
    facts.insert(
        "pii_confidence".to_string(),
        Value::Float(pii_confidence),
    );

    // Crude secret scan.
    let secret_patterns = ["secret:", "password:", "api_key:", "token:"];
    let has_secrets = secret_patterns
        .iter()
        .any(|pattern| prefix.to_lowercase().contains(pattern));
    facts.insert("secrets_found".to_string(), Value::Bool(has_secrets));

    let entropy = calculate_entropy(prefix);
    facts.insert("entropy".to_string(), Value::Float(entropy));

    facts
}

/// Compute safety facts about the output.
fn calculate_safety_facts(prefix: &str) -> HashMap<String, Value> {
    let mut facts = HashMap::new();

    // Crude harmful-content keyword count.
    let harmful_keywords = ["violence", "illegal", "harm", "danger", "attack"];
    let harm_score = harmful_keywords
        .iter()
        .filter(|kw| prefix.to_lowercase().contains(**kw))
        .count() as f64
        / 100.0;

    let harm = (harm_score * 10.0).min(1.0); // Normalize to 0..1.
    facts.insert("harm".to_string(), Value::Float(harm));

    // Crude bias keyword count.
    let bias_keywords = ["always", "never", "all", "none"];
    let bias_score = bias_keywords
        .iter()
        .filter(|kw| prefix.to_lowercase().contains(**kw))
        .count() as f64;
    facts.insert("bias_indicators".to_string(), Value::Float(bias_score));

    facts
}

/// Shannon entropy of the text.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_facts_calculation() {
        let prefix = "Hello world";
        let facts = calculate_dlp_facts(prefix);
        assert!(facts.contains_key("pii_confidence"));
        assert!(facts.contains_key("secrets_found"));
    }

    #[test]
    fn test_safety_facts() {
        let prefix = "This should never happen";
        let facts = calculate_safety_facts(prefix);
        assert!(facts.contains_key("harm"));
        assert!(facts.contains_key("bias_indicators"));
    }
}
