use chai_dsl::{AgentContext, AgentVerifier, AgentConstraints};
use chai_dsl::ast::Value;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Phase 4: Agent Verification ===\n");

    // Test 1: Agent with sufficient trust tier
    let mut agent_attrs = HashMap::new();
    agent_attrs.insert("agent_id".to_string(), Value::String("claude-1".to_string()));
    agent_attrs.insert("trust_tier".to_string(), Value::Int(4));
    agent_attrs.insert("capabilities".to_string(), Value::List(vec![
        Value::String("emit".to_string()),
        Value::String("plan".to_string()),
    ]));
    agent_attrs.insert("roles".to_string(), Value::List(vec![
        Value::String("admin".to_string()),
    ]));
    agent_attrs.insert("last_auth_seconds_ago".to_string(), Value::Int(30));

    let mut values = HashMap::new();
    values.insert("agent".to_string(), Value::Dict(agent_attrs));

    let ctx1 = AgentContext::from_values(&values)?;
    println!("Agent 1: {:?}", ctx1.agent_id);
    println!("  Trust tier: {}", ctx1.trust_tier);
    println!("  Capabilities: {:?}", ctx1.capabilities);
    println!("  Roles: {:?}", ctx1.roles);

    // Verify trust tier
    match AgentVerifier::verify_trust_tier(&ctx1, 3) {
        Ok(_) => println!("✓ Trust tier check passed"),
        Err(e) => println!("✗ Trust tier check failed: {}", e),
    }

    // Verify capability
    match AgentVerifier::verify_capability(&ctx1, "emit") {
        Ok(_) => println!("✓ Capability check passed"),
        Err(e) => println!("✗ Capability check failed: {}", e),
    }

    // Verify missing capability
    match AgentVerifier::verify_capability(&ctx1, "delete") {
        Ok(_) => println!("✓ Delete capability check passed"),
        Err(e) => println!("✗ Delete capability check failed (expected): {}", e),
    }

    // Verify role
    match AgentVerifier::verify_role(&ctx1, &["admin", "moderator"]) {
        Ok(_) => println!("✓ Role check passed"),
        Err(e) => println!("✗ Role check failed: {}", e),
    }

    // Verify recent auth
    match AgentVerifier::verify_recent_auth(&ctx1, 60) {
        Ok(_) => println!("✓ Recent auth check passed"),
        Err(e) => println!("✗ Recent auth check failed: {}", e),
    }

    println!("\n--- Test 2: Agent with insufficient trust tier ---");

    // Test 2: Agent with insufficient trust tier
    let mut agent_attrs2 = HashMap::new();
    agent_attrs2.insert("agent_id".to_string(), Value::String("user-1".to_string()));
    agent_attrs2.insert("trust_tier".to_string(), Value::Int(1));

    let mut values2 = HashMap::new();
    values2.insert("agent".to_string(), Value::Dict(agent_attrs2));

    let ctx2 = AgentContext::from_values(&values2)?;
    println!("Agent 2: {:?}", ctx2.agent_id);
    println!("  Trust tier: {}", ctx2.trust_tier);

    match AgentVerifier::verify_trust_tier(&ctx2, 3) {
        Ok(_) => println!("✓ Trust tier check passed"),
        Err(e) => println!("✗ Trust tier check failed (expected): {}", e),
    }

    println!("\n--- Test 3: Agent constraints ---");

    // Test 3: Verify using constraints
    let constraints = AgentConstraints {
        min_trust_tier: Some(3),
        required_capability: Some("emit".to_string()),
        required_roles: vec!["admin".to_string()],
        max_auth_age_seconds: Some(60),
        rate_limit_per_minute: Some(100),
    };

    match chai_dsl::verify_agent_action(&ctx1, "emit", &constraints) {
        Ok(decision) => {
            println!("✓ Agent verification passed");
            println!("  Reason: {}", decision.reason);
        }
        Err(e) => {
            println!("✗ Agent verification failed: {}", e);
        }
    }

    Ok(())
}
