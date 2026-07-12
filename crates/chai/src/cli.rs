//! Shared implementation for the `chai` CLI (`src/bin/chai.rs`).
//!
//! Subcommands are lint, test, eval, repl. `serve` lives in the binary behind
//! the `server` feature. Each returns a process exit code.

use chai_core::analysis::unreachable_rules;
use chai_core::ast::Value;
use chai_core::entity::json_to_value;
use crate::{eval_with_strategy, parse_chai, parse_chai_with_mode, EntityStore};
use std::collections::HashMap;
use std::io::{self, Write};

/// Read a CLI policy argument. A path if it exists on disk, else inline text.
fn read_policy_arg(s: &str) -> String {
    if std::path::Path::new(s).exists() {
        std::fs::read_to_string(s).unwrap_or_default()
    } else {
        format!("{s}\n")
    }
}

/// `chai lint <policy>`. Parse plus dead-rule analysis. Exit 1 on issues.
pub fn lint(path: &str) -> i32 {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return 2;
        }
    };
    let program = match parse_chai(&src) {
        Ok(p) => p,
        Err(e) => {
            println!("{path}: error: parse failed: {e}");
            return 1;
        }
    };
    let dead = unreachable_rules(&program);
    if dead.is_empty() {
        println!("{path}: OK, parses cleanly, no unreachable rules");
        return 0;
    }
    for id in &dead {
        println!("{path}: warning: rule `{id}` is unreachable, its condition can never hold");
    }
    println!("{path}: {} warning(s)", dead.len());
    1
}

/// `chai test <tests.json> [--trace]`. Scenario assertions. With `trace`, prints
/// the reason, rule-trace, and errors behind each decision. Exit 1 on any failure.
pub fn run_tests(path: &str, trace: bool) -> i32 {
    let spec: serde_json::Value = match std::fs::read_to_string(path).map_err(|e| e.to_string()).and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string())) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let policy_src = if let Some(p) = spec.get("policy").and_then(|v| v.as_str()) {
        p.to_string()
    } else if let Some(pf) = spec.get("policy_file").and_then(|v| v.as_str()) {
        std::fs::read_to_string(pf).unwrap_or_default()
    } else {
        eprintln!("test file needs `policy` or `policy_file`");
        return 2;
    };
    let (strategy, program) = match parse_chai_with_mode(&policy_src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("policy parse error: {e}");
            return 1;
        }
    };
    let store = EntityStore::new();
    let scenarios = spec.get("scenarios").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let (mut pass, mut fail) = (0u32, 0u32);
    for sc in &scenarios {
        let name = sc.get("name").and_then(|v| v.as_str()).unwrap_or("<unnamed>");
        let expect = sc.get("expect").and_then(|v| v.as_str()).unwrap_or("Allow");
        let ctx: HashMap<String, Value> = match sc.get("context") {
            Some(serde_json::Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), json_to_value(v))).collect(),
            _ => HashMap::new(),
        };
        // An evaluation error is a scenario failure, not a reason to panic the
        // whole run.
        let d = match eval_with_strategy(&program, ctx, &store, strategy) {
            Ok(d) => d,
            Err(e) => {
                println!("  [FAIL] {name}  eval error: {e}");
                fail += 1;
                continue;
            }
        };
        let got = format!("{:?}", d.effect);
        if got == expect {
            println!("  [PASS] {name}  ({got})");
            pass += 1;
        } else {
            println!("  [FAIL] {name}  expected {expect}, got {got}");
            fail += 1;
        }
        if trace {
            println!("         reason: {}", d.reason);
            if !d.rule_trace.is_empty() {
                println!("         rules:  {}", d.rule_trace.join(", "));
            }
            if !d.errors.is_empty() {
                println!("         errors: {}", d.errors.join("; "));
            }
        }
    }
    println!("\n{pass} passed, {fail} failed");
    if fail > 0 {
        1
    } else {
        0
    }
}

/// `chai eval <policy> <context-json>`. One-shot decision with diagnostics.
pub fn eval(policy_arg: &str, ctx_json: &str) -> i32 {
    // Honor the `mode` directive so a `mode first_match` (ACL) policy is not
    // silently evaluated under the default deny-override strategy.
    let (strategy, program) = match parse_chai_with_mode(&read_policy_arg(policy_arg)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("policy parse error: {e}");
            return 1;
        }
    };
    let ctx = match crate::embed::context_from_json(ctx_json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bad context JSON: {e}");
            return 2;
        }
    };
    match eval_with_strategy(&program, ctx, &EntityStore::new(), strategy) {
        Ok(d) => {
            println!("{:?}  ({})", d.effect, d.reason);
            if !d.rule_trace.is_empty() {
                println!("rules: {}", d.rule_trace.join(", "));
            }
            if !d.errors.is_empty() {
                println!("errors: {}", d.errors.join("; "));
            }
            0
        }
        Err(e) => {
            eprintln!("eval error: {e}");
            1
        }
    }
}

/// `chai fmt <policy> [--write]`. Validate then tidy a policy. Collapses runs of
/// whitespace to single spaces (string-aware, so string contents are untouched)
/// and trims each line. Idempotent. Prints to stdout, or rewrites with `--write`.
pub fn fmt(path: &str, write: bool) -> i32 {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return 2;
        }
    };
    if let Err(e) = parse_chai(&src) {
        eprintln!("{path}: refusing to format, parse error: {e}");
        return 1;
    }
    let out: String = src.lines().map(normalize_line).collect::<Vec<_>>().join("\n") + "\n";
    if write {
        match std::fs::write(path, &out) {
            Ok(_) => println!("formatted {path}"),
            Err(e) => {
                eprintln!("write error: {e}");
                return 2;
            }
        }
    } else {
        print!("{out}");
    }
    0
}

/// Collapse runs of spaces/tabs to one, only outside string literals (our
/// grammar has no `"` inside strings, so toggling on `"` is reliable). Then trim.
fn normalize_line(line: &str) -> String {
    let mut out = String::new();
    let (mut in_str, mut prev_space) = (false, false);
    for c in line.chars() {
        if c == '"' {
            in_str = !in_str;
            out.push(c);
            prev_space = false;
        } else if !in_str && (c == ' ' || c == '\t') {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

/// `chai repl [policy]`. Interactive authoring and testing.
pub fn repl(policy_path: Option<&str>) -> i32 {
    let mut policy_src = match policy_path {
        Some(p) => std::fs::read_to_string(p).unwrap_or_else(|_| "permit when true\n".into()),
        None => "permit when true\n".into(),
    };
    println!("chai repl, :help for commands");
    loop {
        print!("chai> ");
        io::stdout().flush().ok();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match line {
            ":q" | ":quit" => break,
            ":help" => repl_help(),
            ":show" => match parse_chai(&policy_src) {
                Ok(_) => println!("{}\n(parses OK)", policy_src.trim()),
                Err(e) => println!("{}\n(PARSE ERROR: {e})", policy_src.trim()),
            },
            _ if line.starts_with(":p ") => {
                policy_src = format!("{}\n", &line[3..]);
                match parse_chai(&policy_src) {
                    Ok(_) => println!("policy set."),
                    Err(e) => println!("parse error: {e}"),
                }
            }
            _ if line.starts_with(":load ") => match std::fs::read_to_string(line[6..].trim()) {
                Ok(s) => {
                    policy_src = s;
                    println!("loaded.");
                }
                Err(e) => println!("load error: {e}"),
            },
            _ if line.starts_with('{') => {
                let _ = eval(&policy_src.clone(), line);
            }
            _ => println!("? unknown, :help"),
        }
    }
    0
}

fn repl_help() {
    println!(":p <policy>   set policy   |  :load <path>  load file");
    println!(":show         show policy  |  :q  quit");
    println!("{{json}}        evaluate, e.g.  {{\"subject\":{{\"trust_tier\":4}},\"action\":\"write\"}}");
}
