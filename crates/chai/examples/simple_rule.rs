use chai_dsl::{parse_chai, eval};
use chai_dsl::ast::Value;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: Simple permit rule
    let input1 = "permit when true\n";

    match parse_chai(input1) {
        Ok(program) => {
            println!("Parsed program: {:?}", program);

            let context = HashMap::new();
            match eval(&program, context) {
                Ok(decision) => {
                    println!("Decision: {:?}", decision);
                }
                Err(e) => {
                    println!("Evaluation error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Parse error: {}", e);
        }
    }

    println!("\n---\n");

    // Example 2: Permit rule with principal check
    let input2 = "permit from agent.trust_tier > 3 when true\n";

    match parse_chai(input2) {
        Ok(program) => {
            println!("Parsed program: {:?}", program);

            let mut context = HashMap::new();
            let mut agent_attrs = HashMap::new();
            agent_attrs.insert("trust_tier".to_string(), Value::Int(4));
            context.insert("agent".to_string(), Value::Dict(agent_attrs));

            match eval(&program, context) {
                Ok(decision) => {
                    println!("Decision: {:?}", decision);
                }
                Err(e) => {
                    println!("Evaluation error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Parse error: {}", e);
        }
    }

    Ok(())
}
