//! The `chai` CLI for the toolkit (lint / test / eval / repl / serve).
//!
//!   chai lint  policy.chai
//!   chai test  tests.json
//!   chai eval  policy.chai '{"subject":{"trust_tier":4},"action":"write"}'
//!   chai repl  [policy.chai]
//!   chai serve [policy] [addr]      # needs: cargo build --features server --bin chai

use chai_dsl::cli;

fn usage() {
    eprintln!("chai, a verified policy language and emission-governance toolkit\n");
    eprintln!("usage: chai <command> [args]\n");
    eprintln!("  lint  <policy.chai>             static checks (parse + dead-rule analysis)");
    eprintln!("  test  <tests.json> [--trace]   run scenario assertions (--trace shows reasoning)");
    eprintln!("  eval  <policy> <context-json>  one-shot decision + diagnostics");
    eprintln!("  fmt   <policy> [--write]       validate + tidy a policy");
  eprintln!("  repl  [policy.chai]            interactive authoring/testing");
    eprintln!("  serve [policy] [addr]          run the PDP sidecar (needs --features server)");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("lint") => match args.get(2) {
            Some(p) => cli::lint(p),
            None => {
                usage();
                2
            }
        },
        Some("test") => {
            let trace = args.iter().any(|a| a == "--trace");
            match args.iter().skip(2).find(|a| !a.starts_with("--")) {
                Some(p) => cli::run_tests(p, trace),
                None => {
                    usage();
                    2
                }
            }
        }
        Some("eval") => match (args.get(2), args.get(3)) {
            (Some(p), Some(c)) => cli::eval(p, c),
            _ => {
                usage();
                2
            }
        },
        Some("fmt") => {
            let write = args.iter().any(|a| a == "--write");
            match args.iter().skip(2).find(|a| !a.starts_with("--")) {
                Some(p) => cli::fmt(p, write),
                None => {
                    usage();
                    2
                }
            }
        }
        Some("repl") => cli::repl(args.get(2).map(String::as_str)),
        Some("serve") => serve(&args),
        Some("-h") | Some("--help") | Some("help") | None => {
            usage();
            0
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n");
            usage();
            2
        }
    };
    std::process::exit(code);
}

#[cfg(feature = "server")]
fn serve(args: &[String]) -> i32 {
    use std::sync::Arc;
    let policy = args
        .get(2)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .or_else(|| std::env::var("CHAI_POLICY_FILE").ok().and_then(|p| std::fs::read_to_string(p).ok()))
        .unwrap_or_else(|| "permit when true\n".to_string());
    let addr = args
        .get(3)
        .cloned()
        .or_else(|| std::env::var("CHAI_ADDR").ok())
        .unwrap_or_else(|| "0.0.0.0:8731".to_string());
    let program = match chai_dsl::parse_chai(&policy) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("parse error: {e}");
            return 1;
        }
    };
    let state = Arc::new(chai_dsl::server::AppState {
        program,
        store: chai_dsl::EntityStore::new(),
        afc: chai_dsl::Afc::with_default_detectors(),
        token: std::env::var("CHAI_SIDECAR_TOKEN").ok(),
    });
    chai_dsl::server::serve_blocking(&addr, state);
    0
}

#[cfg(not(feature = "server"))]
fn serve(_: &[String]) -> i32 {
    eprintln!("`chai serve` needs the server feature: cargo build --features server --bin chai");
    2
}
