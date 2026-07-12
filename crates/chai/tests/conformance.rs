//! Cedar conformance as a real test gate: our engine must match Cedar's recorded
//! decisions on its `tiny_sandboxes` corpus. Skips if the Cedar clone is absent.

use chai_dsl::ast::{ChaiProgram, Value};
use chai_dsl::entity::{normalize_uid, EntityStore};
use chai_dsl::{eval_with_store, parse_chai};
use std::collections::HashMap;

const BASE: &str = "third_party/cedar/cedar-policy-cli/sample-data/tiny_sandboxes";

/// (sandbox, our Chai policy); same set the example uses, in Cedar-shaped syntax.
fn policies() -> Vec<(&'static str, &'static str)> {
    vec![
        ("sample1", "permit when principal == User::\"alice\" and action == Action::\"view\" and resource in Album::\"jane_vacation\"\n"),
        ("sample2", "permit when principal == User::\"bob\" and action in [Action::\"view\", Action::\"edit\"] and resource.owner == principal\n"),
        ("sample3", "permit when principal == User::\"bob\" and action in [Action::\"view\", Action::\"edit\"] and resource in Album::\"jane_vacation\"\n"),
        ("sample4", "permit when principal == User::\"bob\" and action == Action::\"view\"\n"),
        ("sample6", "permit when principal in UserGroup::\"guardians\" and action == Action::\"view\" and resource == ScreenTime::\"activity\" and principal.account.age >= 18\n"),
        ("sample9", "permit when action == Action::\"view\" and resource is Photo and principal == resource.owner\n"),
    ]
}

fn build_context(req: &serde_json::Value) -> HashMap<String, Value> {
    let mut ctx = HashMap::new();
    for key in ["principal", "action", "resource"] {
        if let Some(s) = req.get(key).and_then(|v| v.as_str()) {
            ctx.insert(key.to_string(), Value::EntityUid(normalize_uid(s)));
        }
    }
    ctx
}

#[test]
fn matches_cedar_corpus() {
    if !std::path::Path::new(BASE).exists() {
        eprintln!("skipping: Cedar corpus not present at {BASE}");
        return;
    }

    let mut total = 0;
    let mut correct = 0;

    for (name, policy) in policies() {
        let program: ChaiProgram = parse_chai(policy).unwrap_or_else(|e| panic!("{name} policy must parse: {e}"));
        let path = format!("{BASE}/{name}/tests-combined.json");
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cases: serde_json::Value = serde_json::from_str(&raw).unwrap();

        for case in cases.as_array().unwrap() {
            let expected = case.get("decision").and_then(|d| d.as_str()).unwrap();
            let store = EntityStore::from_cedar_entities_json(
                case.get("entities").unwrap_or(&serde_json::Value::Null),
            )
            .unwrap_or_default();
            let ctx = build_context(case.get("request").unwrap());
            let got = match eval_with_store(&program, ctx, &store).unwrap().effect {
                chai_dsl::ast::Effect::Allow => "allow",
                _ => "deny",
            };
            total += 1;
            if got == expected {
                correct += 1;
            } else {
                panic!("{name}: got {got}, Cedar says {expected} for {:?}", case.get("request"));
            }
        }
    }

    assert!(total >= 17, "expected at least 17 conformance cases, ran {total}");
    assert_eq!(correct, total, "all conformance cases must match Cedar");
    eprintln!("conformance: {correct}/{total} match Cedar");
}
