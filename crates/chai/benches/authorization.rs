//! Cedar-style benchmark: authorization-decision latency over an entity store.
//!
//! This is the metric the Cedar paper reports (~15µs/decision @ ~950 entities),
//! and the one that matters for this domain (flat rule-count throughput does
//! not). We generate a folder hierarchy + users + documents at several
//! scales and measure the cost of a single authorization decision, stressing
//! the transitive-`in` path (the gdrive view-inheritance rule).
//!
//! Each measured decision includes building the 3-entry request context, which
//! is part of a real per-request cost.

use chai_dsl::ast::Value;
use chai_dsl::{eval_with_store, parse_chai, Entity, EntityStore};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;

const POLICY: &str = "\
permit action \"read\" when resource in principal.viewable
permit action \"read\" when resource in principal.owned_documents or resource in principal.owned_folders
permit action \"write\" when resource in principal.owned_documents
permit action \"change_owner\" when principal.owned_documents contains resource
permit action \"read\" when resource.is_public
";

/// Deterministic LCG so store generation is reproducible across runs.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % n.max(1)
    }
}

/// Build a store of roughly `scale` entities: a branching folder tree, filler
/// documents and users, plus two probe principals. Returns (store, probe depth).
fn build(scale: usize) -> (EntityStore, usize) {
    const BRANCH: usize = 8;
    let n_folders = (scale / 5).max(2);
    let n_users = (scale / 10).max(2);
    let n_docs = scale.saturating_sub(n_folders + n_users).max(1);

    let mut s = EntityStore::new();

    // Folder tree: folder:0 is root; folder i's parent is folder (i / BRANCH).
    s.insert(Entity::new("folder:0"));
    for i in 1..n_folders {
        s.insert(Entity::new(format!("folder:{i}")).parent(format!("folder:{}", i / BRANCH)));
    }

    let mut rng = Lcg(0x9E3779B97F4A7C15);

    // Filler documents scattered across folders.
    for j in 0..n_docs {
        let f = rng.next(n_folders);
        s.insert(
            Entity::new(format!("doc:{j}"))
                .parent(format!("folder:{f}"))
                .attr("is_public", Value::Bool(false)),
        );
    }
    // Probe document under the deepest-indexed folder (longest parent chain).
    s.insert(
        Entity::new("doc:probe")
            .parent(format!("folder:{}", n_folders - 1))
            .attr("is_public", Value::Bool(false)),
    );

    // Filler users, each with view access to one random folder.
    for k in 0..n_users {
        let f = rng.next(n_folders);
        s.insert(
            Entity::new(format!("user:{k}"))
                .attr(
                    "viewable",
                    Value::List(vec![Value::EntityUid(format!("folder:{f}"))]),
                )
                .attr("owned_documents", Value::List(vec![]))
                .attr("owned_folders", Value::List(vec![])),
        );
    }

    // Probe principals: `viewer` can see the root (so it can reach any doc
    // transitively, worst-case allow); `nobody` can see nothing (worst-case
    // deny that scans the read/owner/public rules).
    s.insert(
        Entity::new("user:viewer")
            .attr(
                "viewable",
                Value::List(vec![Value::EntityUid("folder:0".into())]),
            )
            .attr("owned_documents", Value::List(vec![]))
            .attr("owned_folders", Value::List(vec![])),
    );
    s.insert(
        Entity::new("user:nobody")
            .attr("viewable", Value::List(vec![]))
            .attr("owned_documents", Value::List(vec![]))
            .attr("owned_folders", Value::List(vec![])),
    );

    // Depth of the probe doc's chain to root.
    let mut depth = 1; // doc -> its folder
    let mut cur = n_folders - 1;
    while cur != 0 {
        cur /= BRANCH;
        depth += 1;
    }

    (s, depth)
}

fn req(principal: &str, action: &str, resource: &str) -> HashMap<String, Value> {
    let mut c = HashMap::new();
    c.insert("principal".to_string(), Value::EntityUid(principal.into()));
    c.insert("action".to_string(), Value::String(action.into()));
    c.insert("resource".to_string(), Value::EntityUid(resource.into()));
    c
}

fn bench_authz(c: &mut Criterion) {
    let program = parse_chai(POLICY).expect("policy parses");
    let mut group = c.benchmark_group("authz_decision");

    for &scale in &[100usize, 1_000, 10_000] {
        let (store, depth) = build(scale);

        // Worst-case ALLOW: transitive walk from the probe doc up to the root.
        group.bench_with_input(
            BenchmarkId::new("allow_transitive", format!("{scale}ent_depth{depth}")),
            &store,
            |b, store| {
                b.iter(|| {
                    eval_with_store(
                        black_box(&program),
                        req("user:viewer", "read", "doc:probe"),
                        store,
                    )
                    .unwrap()
                });
            },
        );

        // Worst-case DENY: scans the matching-action rules, all fail.
        group.bench_with_input(
            BenchmarkId::new("deny_scan", format!("{scale}ent")),
            &store,
            |b, store| {
                b.iter(|| {
                    eval_with_store(
                        black_box(&program),
                        req("user:nobody", "read", "doc:probe"),
                        store,
                    )
                    .unwrap()
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_authz);
criterion_main!(benches);
