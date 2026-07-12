//! DRT (D3, emission layer): differentially test `EmissionEnforcer` against the
//! EXECUTED Lean emission model (`formal/EmitOracle.lean`, i.e. `ChaiProofs.steps`).
//! Requires: `cd formal && lake build chai_emit_oracle`. Skips if absent.
//!
//! v1 covers allow/downgrade/defer/deny/requireHuman. `redact` is scoped out: the
//! model always releases it, but the Rust masker drops when it localizes no span,
//! so the two agree only up to that documented over-approximation.

use chai_dsl::ast::Value;
use chai_dsl::{parse_chai, EmissionEnforcer, EmitAction, EntityStore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

/// (Lean effect name, fact selector). A per-step fact `facts.eff` picks exactly one
/// rule of the selector policy, forcing that effect.
const EFFECTS: &[(&str, &str)] = &[
    ("allow", "allow"),
    ("downgrade", "downgrade"),
    ("defer", "defer"),
    ("deny", "deny"),
    ("requireHuman", "human"),
];

const SELECTOR_POLICY: &str = "\
@id(\"a\") permit when facts.eff == \"allow\"
@id(\"g\") downgrade when facts.eff == \"downgrade\"
@id(\"f\") defer when facts.eff == \"defer\"
@id(\"d\") deny when facts.eff == \"deny\"
@id(\"h\") require_human when facts.eff == \"human\"
";

fn action_name(a: &EmitAction) -> &'static str {
    match a {
        EmitAction::Emit(_) => "emit",
        EmitAction::Buffer => "buffer",
        EmitAction::Redact(_) => "redact",
        EmitAction::Drop => "drop",
        EmitAction::RequireHuman => "requireHuman",
    }
}

struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

fn oracle_path() -> PathBuf {
    // Crate is at crates/chai; formal/ is at the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../formal/.lake/build/bin/chai_emit_oracle")
}

fn facts_for(eff_sel: &str) -> HashMap<String, Value> {
    let inner: Value = Value::Dict([("eff".to_string(), Value::String(eff_sel.to_string()))].into());
    HashMap::from([("facts".to_string(), inner)])
}

#[test]
fn drt_emission_matches_executed_lean_model() {
    let oracle = oracle_path();
    if !oracle.exists() {
        eprintln!("skipping drt_emission: oracle not built (cd formal && lake build chai_emit_oracle)");
        return;
    }
    let program = parse_chai(SELECTOR_POLICY).expect("selector policy should parse");
    let store = EntityStore::new();

    let mut rng = Lcg(0x0f0e_0d0c_0b0a_0908);
    let cases = 3000;

    // Build each case as a random effect stream. Keep the per-step selectors (for
    // the engine) and the Lean effect-name line (for the oracle).
    let mut streams: Vec<Vec<usize>> = Vec::with_capacity(cases);
    let mut oracle_input = String::new();
    for _ in 0..cases {
        let len = 1 + rng.below(6) as usize; // 1..=6 chunks
        let mut idxs = Vec::with_capacity(len);
        let mut names = Vec::with_capacity(len);
        for _ in 0..len {
            let k = rng.below(EFFECTS.len() as u64) as usize;
            idxs.push(k);
            names.push(EFFECTS[k].0);
        }
        streams.push(idxs);
        oracle_input.push_str(&names.join(" "));
        oracle_input.push('\n');
    }

    // Run the executed Lean emission model once over all cases.
    // Per-process filename so concurrent test runs don't race on a shared file.
    let tmp = std::env::temp_dir().join(format!("chai_drt_emit_in.{}.txt", std::process::id()));
    std::fs::write(&tmp, &oracle_input).expect("write oracle input");
    let out = Command::new(&oracle)
        .stdin(std::fs::File::open(&tmp).expect("open oracle input"))
        .output()
        .expect("run oracle");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        out.status.success(),
        "oracle process failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lean_lines: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
    assert_eq!(lean_lines.len(), cases, "oracle returned the wrong number of lines");

    // Drive the real enforcer and compare the action-name sequence.
    for (c, idxs) in streams.iter().enumerate() {
        let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());
        let mut got: Vec<&str> = Vec::with_capacity(idxs.len());
        for &k in idxs {
            let (_, sel) = EFFECTS[k];
            let a = enf.step("x", facts_for(sel));
            got.push(action_name(&a));
        }
        let expected: Vec<&str> = lean_lines[c].split(' ').filter(|s| !s.is_empty()).collect();
        assert_eq!(
            got, expected,
            "case {c}: engine and Lean emission model differ; effects={:?}",
            idxs.iter().map(|&k| EFFECTS[k].0).collect::<Vec<_>>()
        );
    }
}
