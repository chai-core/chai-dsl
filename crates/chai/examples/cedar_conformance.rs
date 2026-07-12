//! Capability audit + conformance against Cedar's own functional test corpus.
//!
//! For each tractable Cedar `tiny_sandbox`, we write the equivalent policy in
//! OUR Chai surface syntax, parse it, then run it against Cedar's recorded
//! request/entity/decision cases. This tells us two things honestly:
//!   1. CAN we even express the policy in our surface language? (capability)
//!   2. Do we produce Cedar's decisions? (conformance)
//!
//! Sandboxes using Cedar extension functions (`ip()`, `decimal()`), `is` type
//! tests, or rich context records are out of our language's scope and are
//! listed as such rather than faked.

use chai_dsl::ast::{ChaiProgram, Value};
use chai_dsl::entity::{normalize_uid, EntityStore};
use chai_dsl::{eval_with_store, parse_chai};
use std::collections::HashMap;

const BASE: &str =
    "third_party/cedar/cedar-policy-cli/sample-data/tiny_sandboxes";

/// (sandbox dir, our Chai policy). Quote-free UIDs (see `cedar_uid`).
fn policies() -> Vec<(&'static str, &'static str)> {
    vec![
        // Now written in natural Cedar-shaped syntax: entity-UID literals
        // (User::"alice") and action list literals ([Action::"view", ...]).
        (
            "sample1",
            "permit when principal == User::\"alice\" and action == Action::\"view\" and resource in Album::\"jane_vacation\"\n",
        ),
        (
            "sample2",
            "permit when principal == User::\"bob\" and action in [Action::\"view\", Action::\"edit\"] and resource.owner == principal\n",
        ),
        (
            "sample3",
            "permit when principal == User::\"bob\" and action in [Action::\"view\", Action::\"edit\"] and resource in Album::\"jane_vacation\"\n",
        ),
        (
            "sample4",
            "permit when principal == User::\"bob\" and action == Action::\"view\"\n",
        ),
        (
            "sample6",
            "permit when principal in UserGroup::\"guardians\" and action == Action::\"view\" and resource == ScreenTime::\"activity\" and principal.account.age >= 18\n",
        ),
        (
            // Uses the `is` type-test operator.
            "sample9",
            "permit when action == Action::\"view\" and resource is Photo and principal == resource.owner\n",
        ),
        (
            "sample10",
            "permit when action == Action::\"eat\" and principal.hungry_level >= resource.min_hungry_level\n\
             forbid when action == Action::\"eat\" and (principal.hungry_level < 0 or resource.min_hungry_level < 0 or principal.hungry_level + resource.min_hungry_level >= 100)\n",
        ),
    ]
}

const OUT_OF_SCOPE: &[(&str, &str)] = &[
    ("sample5", "Cedar IP extension functions (ip/isInRange/isLoopback)"),
    ("sample7", "rich context records / nested record equality"),
    ("sample8", "Cedar decimal() extension function"),
    ("sample11", "empty policy set"),
];

fn build_context(req: &serde_json::Value) -> HashMap<String, Value> {
    let mut ctx = HashMap::new();
    for key in ["principal", "action", "resource"] {
        if let Some(s) = req.get(key).and_then(|v| v.as_str()) {
            ctx.insert(key.to_string(), Value::EntityUid(normalize_uid(s)));
        }
    }
    ctx
}

fn decision_str(program: &ChaiProgram, ctx: HashMap<String, Value>, store: &EntityStore) -> String {
    match eval_with_store(program, ctx, store) {
        Ok(d) => match d.effect {
            chai_dsl::ast::Effect::Allow => "allow".to_string(),
            _ => "deny".to_string(),
        },
        Err(e) => format!("error: {e}"),
    }
}

fn main() {
    println!("=== Cedar conformance via Chai surface syntax ===\n");

    let mut total = 0;
    let mut correct = 0;
    let mut parse_failures = 0;

    for (name, policy) in policies() {
        print!("[{name}] ");
        let program = match parse_chai(policy) {
            Ok(p) => p,
            Err(e) => {
                parse_failures += 1;
                println!("PARSE FAILED, capability gap: {}", e.to_string().lines().last().unwrap_or(""));
                continue;
            }
        };

        let path = format!("{BASE}/{name}/tests-combined.json");
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => {
                println!("(no tests-combined.json)");
                continue;
            }
        };
        let cases: serde_json::Value = serde_json::from_str(&raw).unwrap();

        let mut n = 0;
        let mut ok = 0;
        for case in cases.as_array().unwrap() {
            let expected = case.get("decision").and_then(|d| d.as_str()).unwrap_or("?");
            let store = EntityStore::from_cedar_entities_json(
                case.get("entities").unwrap_or(&serde_json::Value::Null),
            )
            .unwrap_or_default();
            let ctx = build_context(case.get("request").unwrap());
            let got = decision_str(&program, ctx, &store);
            n += 1;
            total += 1;
            if got == expected {
                ok += 1;
                correct += 1;
            } else {
                println!("\n    case {n}: got {got}, expected {expected}");
            }
        }
        println!("{ok}/{n} cases match Cedar");
    }

    println!("\n--- out of language scope (not faked) ---");
    for (name, why) in OUT_OF_SCOPE {
        println!("[{name}] skipped: {why}");
    }

    println!(
        "\nCONFORMANCE: {correct}/{total} cases match Cedar across expressible sandboxes \
         ({parse_failures} parse failures)"
    );
}
