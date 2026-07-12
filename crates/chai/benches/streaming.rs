//! Governed-streaming throughput: the per-chunk cost of the full runtime stack
//! (incremental AFC detectors -> ESP decision -> Emission enforcement) over a
//! stream, with the in-process bundled detectors.
//!
//! This is the overhead Chai itself adds per streamed chunk. End-to-end latency
//! with an EXTERNAL detector (Presidio ~ms, Llama Guard ~hundreds of ms) is
//! dominated by that detector, not by this stack; this bench isolates what the
//! engine owns. Numbers land in BENCHMARKS.md from a real run of this file.

use chai_dsl::{parse_chai, EmissionEnforcer, EntityStore, StreamingAfc};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;

const POLICY: &str = "\
@id(\"secret\") deny   when dlp_facts.secrets_found == true
@id(\"pii\")    redact when dlp_facts.pii_confidence > 0.4
@id(\"ok\")     permit when true
";

/// A representative stream: mostly clean prose with occasional PII/secret markers,
/// so the governor exercises emit, redact, and drop paths.
fn make_stream(n: usize) -> Vec<String> {
    let samples = [
        "The quarterly report shows steady growth this period ",
        "please contact the team about your ssn and email ",
        "here is the summary of findings and the next steps ",
        "note the api_key: token is not included in this message ",
        "regards and thanks for your time earlier today ",
    ];
    (0..n).map(|i| samples[i % samples.len()].to_string()).collect()
}

fn bench_governed_stream(c: &mut Criterion) {
    let program = parse_chai(POLICY).unwrap();
    let store = EntityStore::new();

    let mut group = c.benchmark_group("governed_stream");
    group.sample_size(30);
    for &n in &[10usize, 100, 1_000] {
        let stream = make_stream(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &stream, |b, stream| {
            b.iter(|| {
                let mut afc = StreamingAfc::new();
                let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());
                for chunk in stream {
                    let facts = afc.push(chunk).to_context();
                    let _ = enf.step(chunk, facts);
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_governed_stream);
criterion_main!(benches);
