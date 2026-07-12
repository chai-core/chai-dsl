use chai_core::ast::{Value, Decision, Effect};
use chai_core::error::ChaiError;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AgentContext {
    pub agent_id: String,
    pub trust_tier: i64,
    pub capabilities: Vec<String>,
    pub roles: Vec<String>,
    pub last_auth_seconds_ago: i64,
}

impl AgentContext {
    pub fn from_values(values: &HashMap<String, Value>) -> Result<Self, ChaiError> {
        let agent = values
            .get("agent")
            .and_then(|v| if let Value::Dict(d) = v { Some(d) } else { None })
            .ok_or_else(|| ChaiError::UnknownEntity("agent context not found".to_string()))?;

        let agent_id = if let Some(Value::String(id)) = agent.get("agent_id") {
            id.clone()
        } else if let Some(Value::String(id)) = agent.get("id") {
            id.clone()
        } else {
            "unknown".to_string()
        };

        let trust_tier = if let Some(Value::Int(tier)) = agent.get("trust_tier") {
            *tier
        } else {
            0
        };

        let capabilities = if let Some(Value::List(caps)) = agent.get("capabilities") {
            caps.iter()
                .filter_map(|v| if let Value::String(s) = v { Some(s.clone()) } else { None })
                .collect()
        } else {
            Vec::new()
        };

        let roles = if let Some(Value::List(r)) = agent.get("roles") {
            r.iter()
                .filter_map(|v| if let Value::String(s) = v { Some(s.clone()) } else { None })
                .collect()
        } else {
            Vec::new()
        };

        let last_auth_seconds_ago = if let Some(Value::Int(sec)) = agent.get("last_auth_seconds_ago") {
            *sec
        } else {
            i64::MAX
        };

        Ok(AgentContext {
            agent_id,
            trust_tier,
            capabilities,
            roles,
            last_auth_seconds_ago,
        })
    }
}

pub struct AgentVerifier;

impl AgentVerifier {
    /// Check the agent meets a minimum trust tier.
    pub fn verify_trust_tier(ctx: &AgentContext, min_tier: i64) -> Result<(), ChaiError> {
        if ctx.trust_tier >= min_tier {
            Ok(())
        } else {
            Err(ChaiError::EvalError(format!(
                "Agent {} trust tier {} < required {}",
                ctx.agent_id, ctx.trust_tier, min_tier
            )))
        }
    }

    /// Check the agent has a required capability.
    pub fn verify_capability(ctx: &AgentContext, capability: &str) -> Result<(), ChaiError> {
        if ctx.capabilities.contains(&capability.to_string()) {
            Ok(())
        } else {
            Err(ChaiError::EvalError(format!(
                "Agent {} missing capability: {}",
                ctx.agent_id, capability
            )))
        }
    }

    /// Check the agent holds at least one of the required roles.
    pub fn verify_role(ctx: &AgentContext, required_roles: &[&str]) -> Result<(), ChaiError> {
        if required_roles.iter().any(|r| ctx.roles.contains(&r.to_string())) {
            Ok(())
        } else {
            Err(ChaiError::EvalError(format!(
                "Agent {} does not have required role",
                ctx.agent_id
            )))
        }
    }

    /// Check the agent authenticated within the last `max_seconds`.
    pub fn verify_recent_auth(ctx: &AgentContext, max_seconds: i64) -> Result<(), ChaiError> {
        if ctx.last_auth_seconds_ago <= max_seconds {
            Ok(())
        } else {
            Err(ChaiError::EvalError(format!(
                "Agent {} auth expired {} seconds ago (max: {})",
                ctx.agent_id, ctx.last_auth_seconds_ago, max_seconds
            )))
        }
    }

}

/// Sliding-window rate limiter, keyed by (agent, action). Deterministic. The
/// caller supplies `now` (in seconds), so there are no hidden clock reads and it
/// stays fully testable.
pub struct RateLimiter {
    windows: std::sync::Mutex<std::collections::HashMap<(String, String), std::collections::VecDeque<u64>>>,
    window_secs: u64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_window(60)
    }

    pub fn with_window(window_secs: u64) -> Self {
        RateLimiter {
            windows: std::sync::Mutex::new(std::collections::HashMap::new()),
            window_secs,
        }
    }

    /// Allow the request at time `now` if fewer than `quota` requests fall within
    /// the trailing window; records it on success, errors when the quota is hit.
    pub fn check(&self, agent: &str, action: &str, quota: usize, now: u64) -> Result<(), ChaiError> {
        let mut w = self.windows.lock().unwrap();
        let dq = w.entry((agent.to_string(), action.to_string())).or_default();
        while let Some(&front) = dq.front() {
            if now.saturating_sub(front) >= self.window_secs {
                dq.pop_front();
            } else {
                break;
            }
        }
        if dq.len() >= quota {
            return Err(ChaiError::EvalError(format!(
                "rate limit exceeded for {agent}/{action}: {} requests in last {}s >= {quota}",
                dq.len(),
                self.window_secs
            )));
        }
        dq.push_back(now);
        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub fn verify_agent_action(
    agent_ctx: &AgentContext,
    action: &str,
    constraints: &AgentConstraints,
) -> Result<Decision, ChaiError> {
    if let Some(min_tier) = constraints.min_trust_tier {
        AgentVerifier::verify_trust_tier(agent_ctx, min_tier)?;
    }

    if let Some(ref required_cap) = constraints.required_capability {
        AgentVerifier::verify_capability(agent_ctx, required_cap)?;
    }

    if !constraints.required_roles.is_empty() {
        let roles: Vec<&str> = constraints.required_roles.iter().map(|s| s.as_str()).collect();
        AgentVerifier::verify_role(agent_ctx, &roles)?;
    }

    if let Some(max_age) = constraints.max_auth_age_seconds {
        AgentVerifier::verify_recent_auth(agent_ctx, max_age)?;
    }

    // Rate limiting needs state across requests. A stateless function can't carry
    // it, so callers enforce it through a `RateLimiter`.

    Ok(Decision {
        effect: Effect::Allow,
        reason: format!("Agent {} verified for action {}", agent_ctx.agent_id, action),
        reason_codes: vec!["agent_verification_passed".to_string()],
        obligations: Vec::new(),
        rule_trace: vec!["agent_verify".to_string()],
        errors: Vec::new(),
        require_human_present: false,
        transforms: Vec::new(),
        metadata: HashMap::new(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct AgentConstraints {
    pub min_trust_tier: Option<i64>,
    pub required_capability: Option<String>,
    pub required_roles: Vec<String>,
    pub max_auth_age_seconds: Option<i64>,
    pub rate_limit_per_minute: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ctx(last_auth: i64) -> AgentContext {
        AgentContext {
            agent_id: "a1".into(),
            trust_tier: 3,
            capabilities: vec![],
            roles: vec![],
            last_auth_seconds_ago: last_auth,
        }
    }

    #[test]
    fn recent_auth_boundary() {
        assert!(AgentVerifier::verify_recent_auth(&ctx(60), 60).is_ok()); // inclusive
        assert!(AgentVerifier::verify_recent_auth(&ctx(61), 60).is_err());
        let _ = HashMap::<String, ()>::new();
    }

    #[test]
    fn rate_limit_sliding_window() {
        let rl = RateLimiter::with_window(60);
        // quota 2 per window. First two at t=0 ok, third blocked.
        assert!(rl.check("a1", "emit", 2, 0).is_ok());
        assert!(rl.check("a1", "emit", 2, 1).is_ok());
        assert!(rl.check("a1", "emit", 2, 2).is_err());
        // a different action is tracked separately.
        assert!(rl.check("a1", "read", 2, 2).is_ok());
        // once the window slides past the early requests, it frees up.
        assert!(rl.check("a1", "emit", 2, 61).is_ok()); // t=0 and t=1 now expired
        // a different agent has its own bucket.
        assert!(rl.check("a2", "emit", 1, 2).is_ok());
        assert!(rl.check("a2", "emit", 1, 3).is_err());
    }
}
