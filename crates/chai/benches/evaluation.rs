//! Real measurement harness for the Chai/ESP evaluator.
//!
//! Every number here comes from actually calling `parse_chai` / `eval` on real
//! input via criterion. Nothing is hardcoded or simulated.

use chai_dsl::ast::{ChaiProgram, Value};
use chai_dsl::{eval, parse_chai};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;

#[path = "production_policies.rs"]
mod production_policies;

/// Generate a synthetic single-line policy with `n` permit rules.
fn synthetic_policy(n: usize) -> String {
    let mut p = String::with_capacity(n * 40);
    for i in 0..n {
        // vary the threshold so rules are not byte-identical
        p.push_str(&format!("permit when dlp_facts.pii < 0.{}\n", (i % 9) + 1));
    }
    p
}

/// A context where pii is high enough that NO permit rule matches -> worst case
/// (the evaluator must scan every rule before defaulting to deny).
fn worst_case_context() -> HashMap<String, Value> {
    let mut ctx = HashMap::new();
    let mut dlp = HashMap::new();
    dlp.insert("pii".to_string(), Value::Float(0.99));
    ctx.insert("dlp_facts".to_string(), Value::Dict(dlp));
    ctx
}

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse");
    for &n in &[10usize, 100, 1_000, 10_000] {
        let src = synthetic_policy(n);
        group.throughput(criterion::Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &src, |b, src| {
            b.iter(|| parse_chai(black_box(src)).unwrap());
        });
    }
    group.finish();
}

fn bench_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_worst_case");
    for &n in &[10usize, 100, 1_000, 10_000] {
        let prog = parse_chai(&synthetic_policy(n)).unwrap();
        let ctx = worst_case_context();
        group.throughput(criterion::Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &prog, |b, prog: &ChaiProgram| {
            b.iter(|| eval(black_box(prog), ctx.clone()).unwrap());
        });
    }
    group.finish();
}

fn bench_production(c: &mut Criterion) {
    use production_policies::PRODUCTION_POLICIES;
    let mut group = c.benchmark_group("production_parse");
    for pol in PRODUCTION_POLICIES {
        // Only benchmark policies that actually parse.
        if parse_chai(pol.policy).is_err() {
            continue;
        }
        group.bench_function(pol.name, |b| {
            b.iter(|| parse_chai(black_box(pol.policy)).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parse, bench_eval, bench_production);
criterion_main!(benches);
