use chai_dsl::{parse_chai, eval};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Form 2: Structured Cedar-style rules. The structured form puts the
    // condition on the line after `when:` (the grammar expects a newline there).
    let input = "permit(principal: Agent, action: string, resource: Channel) when:\n  agent.trust_tier > 3 and action == \"emit\"\n";

    match parse_chai(input) {
        Ok(program) => {
            println!("=== Form 2: Structured Rule ===");
            println!("Parsed successfully!");
            println!("Program: {:?}\n", program);

            let mut context = HashMap::new();
            let mut agent = HashMap::new();
            agent.insert("trust_tier".to_string(), chai_dsl::ast::Value::Int(5));
            context.insert("agent".to_string(), chai_dsl::ast::Value::Dict(agent));
            context.insert("action".to_string(), chai_dsl::ast::Value::String("emit".to_string()));

            match eval(&program, context) {
                Ok(decision) => {
                    println!("Decision: {:?}", decision.effect);
                    println!("Obligations: {:?}", decision.obligations);
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
