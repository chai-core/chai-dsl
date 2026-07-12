use chai_dsl::{parse_chai, eval};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Phase 2 example with Cedar semantics
    // Testing deny-overrides: forbid takes precedence over permit

    let input = "forbid when false\npermit when true\n";

    match parse_chai(input) {
        Ok(program) => {
            println!("=== Cedar Deny-Overrides Example ===");
            println!("Program (2 rules):");
            println!("  1. forbid when false");
            println!("  2. permit when true\n");

            let context = HashMap::new();
            match eval(&program, context) {
                Ok(decision) => {
                    println!("Decision: effect={:?}", decision.effect);
                    println!("Reason: {}", decision.reason);
                    println!("Expected: Allow (forbid didn't match)\n");
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

    // Test 2: forbid does match
    let input2 = "forbid when true\npermit when true\n";

    match parse_chai(input2) {
        Ok(program) => {
            println!("=== Cedar Deny-Overrides: Forbid Matches ===");
            println!("Program:");
            println!("  1. forbid when true");
            println!("  2. permit when true\n");

            let context = HashMap::new();
            match eval(&program, context) {
                Ok(decision) => {
                    println!("Decision: effect={:?}", decision.effect);
                    println!("Reason: {}", decision.reason);
                    println!("Expected: Deny (forbid overrides permit)\n");
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
