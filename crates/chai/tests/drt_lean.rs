//! DRT (D3-full): differentially test the real engine against the EXECUTED Lean
//! model (`formal/DrtOracle.lean`, i.e. `ChaiProofs.decision`), not a Rust
//! transcription of it. This is the cedar-drt move: the proven Lean model is the
//! oracle, run as a process, and the production engine is checked against it.
//!
//! Requires the oracle to be built: `cd formal && lake build chai_oracle`.
//! Skips (does not fail) if the binary is absent, matching the repo convention for
//! tests that need an external artifact.
//!
//! Scope: matched, unmatched, and errored rules over the full effect chain
//! (effect-tagged errors: a strict restrictive error contributes its effect, a
//! permit error is inert). The emission machine is the next DRT stage.

use chai_dsl::ast::Effect;
use chai_dsl::{eval_with_store, parse_chai, EntityStore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

/// (policy keyword, Lean effect token for a matched rule). `forbid` and `deny`
/// both map to the Lean `deny` (the model has no separate Forbid).
const EFFECTS: &[(&str, &str)] = &[
    ("permit", "allow"),
    ("downgrade", "downgrade"),
    ("redact", "redact"),
    ("defer", "defer"),
    ("require_human", "requireHuman"),
    ("deny", "deny"),
    ("forbid", "deny"),
];

fn effect_of_lean(s: &str) -> Effect {
    match s {
        "allow" => Effect::Allow,
        "downgrade" => Effect::Downgrade,
        "redact" => Effect::Redact,
        "defer" => Effect::Defer,
        "requireHuman" => Effect::RequireHuman,
        "deny" => Effect::Deny,
        other => panic!("oracle returned an unknown verdict: {other:?}"),
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../formal/.lake/build/bin/chai_oracle")
}

#[test]
fn drt_engine_matches_executed_lean_model() {
    let oracle = oracle_path();
    if !oracle.exists() {
        eprintln!("skipping drt_lean: oracle not built (cd formal && lake build chai_oracle)");
        return;
    }

    let mut rng = Lcg(0x0123_4567_89ab_cdef);
    let cases = 5000;

    // Build all policies and the matching oracle input, one case per line.
    let mut policies: Vec<String> = Vec::with_capacity(cases);
    let mut oracle_input = String::new();
    for _ in 0..cases {
        let n_rules = 1 + rng.below(6) as usize;
        let mut src = String::new();
        let mut tokens: Vec<String> = Vec::new();
        for i in 0..n_rules {
            let (kw, lean_eff) = EFFECTS[rng.below(EFFECTS.len() as u64) as usize];
            // 0 = matched, 1 = unmatched, 2 = errored (unbound `foo` faults the guard).
            match rng.below(3) {
                0 => {
                    src.push_str(&format!("@id(\"r{i}\") {kw} when true\n"));
                    tokens.push(format!("M:{lean_eff}"));
                }
                1 => {
                    src.push_str(&format!("@id(\"r{i}\") {kw} when false\n"));
                    tokens.push("U".to_string());
                }
                _ => {
                    src.push_str(&format!("@id(\"r{i}\") {kw} when foo == 1\n"));
                    // A permit error is inert (contributes 0, like `errored allow`);
                    // a restrictive error contributes its effect (strict default).
                    tokens.push(if kw == "permit" {
                        "E:allow".to_string()
                    } else {
                        format!("E:{lean_eff}")
                    });
                }
            }
        }
        policies.push(src);
        oracle_input.push_str(&tokens.join(" "));
        oracle_input.push('\n');
    }

    // Run the executed Lean model once over all cases (stdin from a temp file so a
    // large input cannot deadlock against a full stdout pipe).
    // Per-process filename so concurrent test runs don't race on a shared file.
    let tmp = std::env::temp_dir().join(format!("chai_drt_oracle_in.{}.txt", std::process::id()));
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
    let verdicts: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
    assert_eq!(verdicts.len(), cases, "oracle returned the wrong number of verdicts");

    // Compare the real engine to the Lean model, case by case.
    let store = EntityStore::new();
    for (i, src) in policies.iter().enumerate() {
        let program = parse_chai(src).expect("policy should parse");
        let decision = eval_with_store(&program, HashMap::new(), &store).expect("eval should succeed");
        let expected = effect_of_lean(verdicts[i]);
        assert_eq!(
            decision.effect, expected,
            "engine and executed Lean model disagree\npolicy:\n{src}lean_verdict={}",
            verdicts[i]
        );
    }
}
