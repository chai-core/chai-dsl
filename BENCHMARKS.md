# Benchmarks & Conformance (measured)

Every number here was produced by running the code on this machine via
`criterion`. Nothing is estimated, projected, or copied from another paper.
Reproduce with the commands at the bottom.

> Note: this file replaces earlier documents (`EMPIRICAL_EVALUATION.md`,
> `COMPARATIVE_ANALYSIS.md`, etc.) that contained fabricated numbers. Those were
> deleted. If a figure isn't here, we haven't measured it.

## 1. Authorization decision latency (the metric that matters)

Cedar-style: a fixed gdrive-shaped policy evaluated against an entity store of
varying size, stressing the transitive-`in` (view-inheritance) path. Each
measured decision includes building the request context.

| Store size | hierarchy depth | ALLOW (transitive `in`) | DENY (rule scan) |
|---|---|---|---|
| 100 entities | 3 | 1.06 µs | 0.79 µs |
| 1,000 entities | 4 | 1.17 µs | 0.80 µs |
| 10,000 entities | 5 | 1.24 µs | 0.80 µs |

Latency is essentially **flat in store size** (100× entities → +0.18 µs),
because decision cost tracks hierarchy depth and set sizes, not entity count
(HashMap lookups are O(1); the `in` walk is O(depth)). Growth is linear in
depth (~0.09 µs/level); no exponential blowup.

## 2. Same-machine head-to-head vs Cedar

Cedar (`cedar-policy` v-from-source) built and benchmarked on this same machine:

| Engine | workload | decision latency |
|---|---|---|
| **Cedar `is_authorized`** | 6 entities, 2 policies, depth ~3 | **1.76 µs** |
| **Ours `eval_with_store`** | 100 entities, depth 3 | 1.06 µs |
| **Ours** | 10,000 entities, depth 5 | 1.24 µs |

Same order of magnitude, ours slightly lower. **This is not a claim that we are
"faster"**: Cedar does strictly more per decision (typed entities, restricted
expressions, extension functions, full diagnostics, a more general expression
language). Honest reading: *comparable decision latency, with a simpler
evaluator and a narrower language.*

## 3. Parse / eval scaling (synthetic, flat rule list)

| n rules | parse | eval (worst case, all rules scanned) |
|---|---|---|
| 10 | 11.3 µs | 0.99 µs |
| 100 | 110 µs | 8.8 µs |
| 1,000 | 1.17 ms | 86.7 µs |
| 10,000 | 12.8 ms | 0.865 ms |

Both linear. Parsing dominates evaluation (~15×); you parse once and evaluate
many times. (A flat 10k-rule list is not a realistic policy: real policies have
few rules and many entities, per §1, but it bounds the parser and evaluator.)

## 3b. Governed streaming throughput (the full runtime stack)

The number a streaming deployment feels is not one decision but the per-chunk cost
of the whole stack: incremental AFC detectors → ESP decision → Emission
enforcement, run over a stream. Measured with the in-process bundled detectors
(`crates/chai/benches/streaming.rs`):

| stream length | total | per chunk | throughput |
|---|---|---|---|
| 10 chunks | 28.7 µs | 2.87 µs | 349 K chunks/s |
| 100 chunks | 262 µs | 2.62 µs | 382 K chunks/s |
| 1,000 chunks | 2.61 ms | 2.61 µs | 383 K chunks/s |

Flat per chunk (~2.6 µs): the incremental AFC keeps O(chunk) state and the decision
is O(rules). This is the overhead **Chai itself** adds per streamed chunk.

**End-to-end is detector-dominated, not engine-dominated.** With an external
detector in the loop, its own latency dwarfs this stack: Presidio is milliseconds
and Llama Guard is an LLM call at hundreds of milliseconds per chunk, i.e. 10³ to
10⁵ times this 2.6 µs. So the engine is never the bottleneck; the levers for
end-to-end latency are detector choice, batching, and how aggressively `defer`
buffers. A timed end-to-end harness against a live Presidio/Llama Guard is future
work (it needs those services running, like the scripts under `eval/`).

## 4. Conformance against Cedar's own test corpus

We ran our engine against Cedar's bundled `tiny_sandboxes` functional tests
(`request + entities + expected decision`), writing each policy in our Chai
surface syntax.

- **21 / 21 cases match Cedar** across the 7 sandboxes expressible in our
  language (sample1-4, 6, 9, 10). sample9 uses the `is` entity-type-test
  operator, which the engine now supports.
- **4 sandboxes out of language scope** (listed, not faked):
  - sample5: IP extension functions (`ip`, `isInRange`, `isLoopback`)
  - sample7: rich context records / nested record equality
  - sample8: `decimal()` extension function
  - sample11: empty policy set

Plus our own gdrive ReBAC model: **7 / 7 cases correct** (including
folder-inherited view access via transitive `in`).

## 5. Honest caveats

- The §2 comparison is same-machine but **not same-workload** (Cedar's bench
  has 6 entities / 2 policies; ours scales entities up). Both measure only the
  decision call, with setup outside the timed loop.
- §1 stores use **small grant-sets** (1 folder per user). True worst case is
  O(|grant-set| × depth); large grant-sets + deep trees would cost more. Not yet
  measured.
- §1 uses a **single representative policy**. Not a policy-diversity sweep.
- These latency/scaling numbers measure the **decision core only**. Chai's
  schema validator (`src/schema.rs`), z3 SMT analysis (`src/smt.rs`, validated vs
  an independent oracle), and Lean proofs (`formal/`, no `sorry`) are real and
  shipped, but they are **offline / static** (not on the hot path), so they are
  excluded from this microbenchmark by design, not absent.

## 6. Reproduce

```sh
# our benchmarks
cargo bench --bench authorization
cargo bench --bench evaluation

# our conformance against Cedar's corpus
cargo run --example cedar_conformance
cargo run --example gdrive

# same-machine Cedar baseline
cd third_party/cedar
cargo bench -p cedar-policy --bench cedar_benchmarks -- is_authorized
```
