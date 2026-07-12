use chai_dsl::{parse_chai, StreamingEvaluator};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Phase 5: Streaming Evaluation ===\n");

    // Simple policy: allow if dlp_facts.pii_confidence < 0.3
    let policy_str = "permit when dlp_facts.pii_confidence < 0.3\n";

    let program = parse_chai(policy_str)?;
    let context = HashMap::new();

    // Create streaming evaluator
    let mut evaluator = StreamingEvaluator::new(program, context);

    println!("Policy: permit when dlp_facts.pii_confidence < 0.3");
    println!("(Allows output if PII confidence is low)\n");

    // Simulate token-by-token generation
    let tokens = vec![
        "Hello",
        " world",
        ", ",
        "my",
        " ",
        "name",
        " ",
        "is",
        " ",
        "John",
    ];

    println!("Token-by-token evaluation:");
    println!("{:<20} | {:<10} | {:<15}", "Prefix", "Effect", "PII Score");
    println!("{}", "-".repeat(50));

    for token in tokens {
        let decision = evaluator.process_token(token)?;
        println!("{:<20} | {:?} | tokens={}",
            decision.prefix.chars().take(20).collect::<String>(),
            decision.effect,
            decision.tokens_processed
        );
    }

    println!("\n--- Test 2: PII Detection ---");

    // Policy that triggers on PII
    let policy_str2 = "forbid when dlp_facts.pii_confidence > 0.8\npermit when dlp_facts.pii_confidence < 0.8\n";
    let program2 = parse_chai(policy_str2)?;
    let mut evaluator2 = StreamingEvaluator::new(program2, HashMap::new());

    println!("\nPolicy: forbid when PII confidence > 0.8");
    println!("         permit when PII confidence < 0.8\n");

    let tokens2 = vec!["Her", " SSN", " is", " 123", "-45", "-6789"];
    println!("Dangerous token sequence (contains SSN reference):");

    for token in tokens2 {
        let decision = evaluator2.process_token(token)?;
        println!("{:<20} | Effect: {:?}",
            decision.prefix.chars().take(20).collect::<String>(),
            decision.effect
        );
    }

    if let Some(final_decision) = evaluator2.get_decision() {
        println!("\nFinal decision: {:?}", final_decision.effect);
        println!("Reason: {}", final_decision.reason);
    }

    Ok(())
}
