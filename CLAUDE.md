# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`chai_dsl` is a readable, Cedar-shaped policy language plus a three-layer runtime
for governing what an agent (e.g. an LLM) may emit, streaming and fail-closed:

```
Chai (agent) → AFC (facts) → ESP (policy) → Emission (enforcement) → sink
```

The **source-of-truth specs** are the plain files `goal` (the DSL design) and
`three_layer` (the LaTeX architecture spec: Chai/AFC/ESP/Emission, decision
algebra, streaming protocol, security invariants). `main.tex` is a *separate*
academic framing (an obligation calculus); it is **not** the build target; do
not implement from it unless explicitly told to.

## Commands

Rust is installed via rustup; the binary may be at `~/.cargo/bin/cargo` if not on PATH.

**Workspace layout.** The repo is a Cargo workspace with two crates:
`crates/chai-core` (package `chai-core`) is the verified engine (parser, evaluator,
emission, entity, taint, template, schema, analysis, pam, smt); `crates/chai`
(package kept as **`chai_dsl`**, so the wasm artifact and integrations stay stable)
is the runtime/exposure layer (afc, cli, server, mcp, wire surfaces, sdk glue) and
re-exports the engine. `formal/` and `third_party/` are separate. Engine module
paths are under `crates/chai-core/src/`, runtime modules under `crates/chai/src/`.
Feature/example/bench/wasm commands target the top crate, hence `-p chai_dsl`.

```sh
cargo build                                   # builds the whole workspace
cargo test                                    # all tests (both crates + integration)
cargo test --lib                              # library unit tests only
cargo test <name>                             # single test, e.g. cargo test mode_directive
cargo run -p chai_dsl --example full_pipeline      # Chai→AFC→ESP→Emission, end to end
cargo run -p chai_dsl --example cedar_conformance  # our engine vs Cedar's corpus (expect 21/21)
cargo run -p chai_dsl --example gdrive             # Cedar gdrive ReBAC (expect 7/7)
cargo bench -p chai_dsl --bench authorization      # decision-latency benchmark (criterion)
cargo bench -p chai_dsl --bench evaluation         # parse/eval scaling
cargo test -p chai_dsl --features cedar-diff       # differential vs the real Cedar crate
cargo test -p chai_dsl --features server           # HTTP sidecar (axum/tokio) tests
cargo build -p chai_dsl --features postgres        # PgStore EntityResolver (needs a live DB to test)
cargo test  -p chai_dsl --features postgres --test postgres  # live PG test (seed per crates/chai/src/pg_store.rs; skips if no DB)
cargo test  -p chai_dsl --features redis    --test redis     # live Redis test (self-seeding; skips if no Redis)
cargo build -p chai_dsl --release --features capi  # native C ABI cdylib for in-process embedding (integrations/embed/)
```

Continuous differential testing (production engine vs the executed Lean model) runs
in CI (`.github/workflows/ci.yml`, the `drt` job). Locally: build the oracles with
`cd formal && lake build chai_oracle chai_emit_oracle`, then
`cargo test -p chai_dsl --test drt_decision --test drt_lean --test drt_emission`.

Formal proofs of the decision core live in `formal/` (Lean 4, no Mathlib):

```sh
cd formal && ~/.elan/bin/lake build           # determinism, fail-closed, Cedar-reduction
```

The SMT analysis (`crates/chai-core/src/smt.rs`, feature `smt`) needs libz3 (`brew install z3`)
and these env vars so the `z3-sys` build finds it (Homebrew on Apple Silicon):

```sh
export LIBRARY_PATH=/opt/homebrew/lib:$LIBRARY_PATH
export CPATH=/opt/homebrew/include:$CPATH
export Z3_SYS_Z3_HEADER=/opt/homebrew/include/z3.h
export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib
cargo test -p chai_dsl --features smt
```

Cedar baseline (same-machine head-to-head) lives in `third_party/cedar`, which is
**excluded from our workspace** (`[workspace] exclude = ["third_party"]` in
Cargo.toml) so `cargo test` does not recurse into it. To run Cedar's own bench:
`cd third_party/cedar && cargo bench -p cedar-policy --bench cedar_benchmarks -- is_authorized`.

The browser playground in `integrations/playground/` is a static site. It runs the
engine compiled to WASM with no backend. Build the wasm and serve it locally:

```sh
cargo build -p chai_dsl --release --target wasm32-unknown-unknown --features wasm --lib
cp target/wasm32-unknown-unknown/release/chai_dsl.wasm integrations/playground/
python3 -m http.server -d integrations/playground 8788   # index.html is the REPL, tour.html the guide
```

The WASM export is a raw C-ABI module (`crates/chai/src/wasm.rs`, exports `chai_alloc`,
`chai_free`, `chai_evaluate`), no wasm-bindgen. The JS glue loads it with
`WebAssembly.instantiate(arrayBuffer)`, so the served MIME type is irrelevant, and
all asset paths are relative, so the site works under a subpath.

GitHub Pages hosts the site via `.github/workflows/pages.yml`. On every push to
`main` the workflow rebuilds the wasm in CI and publishes the playground to
`https://chai-core.github.io/chai-dsl/` (REPL at `/`, tour at `/tour.html`). The committed
`integrations/playground/chai_dsl.wasm` exists only for local serving. The deploy
rebuilds from source, so the live site never drifts from the engine. To update the
live site, change the playground files or the engine and push to `main`. Enabling
this once needs Pages source set to GitHub Actions in repo settings.

## Architecture (the parts that span multiple files)

The decision pipeline is four composable layers; each is a module and they are
deliberately decoupled (the "separation of inference from control" invariant):

- **ESP: the decision engine** (`evaluator.rs` + `entity.rs` + `parser.rs`).
  `parse_chai` (Pest grammar, inline in `parser.rs`) → AST (`ast.rs`) →
  `eval_with_store(program, context, &EntityStore)` → `Decision`. ReBAC works
  via `EntityStore`: entities have `{uid, attrs, parents}` and `is_in` walks the
  parent chain transitively, which is how `resource in principal.viewable` and
  group membership resolve. `Value::EntityUid` is distinct from `String` so the
  evaluator knows to resolve attributes/hierarchy against the store.

- **Emission** (`emission.rs`). `EmissionEnforcer::step(chunk, facts)` runs ESP
  and drives the streaming state machine: emit / buffer / redact / drop / halt.
  Fail-closed: errors and the no-match default both deny; an unapproved buffer is
  dropped at `finish()`.

- **AFC** (`afc.rs`). `Afc::compute(prefix, t)` produces a `FactBundle` of typed
  `Evidence{value, source, method, confidence, timestamp}` (`⟨v,σ,m,c,τ⟩`) across
  six namespaces (dlp/safety/grounding/schema/tooltrace/risk). `Detector`s run
  over the prefix; `Aggregator`s (e.g. Risk) run *after*, reading the bundle.
  `FactBundle::to_context()` flattens to the `HashMap<String,Value>` ESP consumes.
  Facts are *injected* into Emission so the two layers stay separable. The
  bundled detectors are heuristics; `Afc::with_external(presidio, llama_guard)`
  plugs in real Presidio/Llama Guard via `RemoteCall` adapters that parse those
  tools' native output and record `Source::Callee` evidence (do not run the
  model/library in-process or fabricate its output).

- **Chai** (`chai.rs`). `run_chai(...)` drives an `Agent` (pluggable; real LLM or
  `ScriptedAgent`) through AFC→ESP→Emission, accumulating the prefix and tool
  calls. Subject/object live in the eval context, so subject checks are ordinary
  ESP rules, not a separate path.

`fact_calculator.rs` and `streaming.rs` are earlier/superseded modules; prefer
`afc.rs` and `emission.rs`.

## Critical conventions (hard-won; do not regress these)

- **No fabricated numbers, ever.** Every performance figure must come from a real
  `criterion` run. `BENCHMARKS.md` is the *only* place for perf numbers and they
  must be reproducible. (Earlier fabricated docs were deleted; do not recreate
  that pattern.) When comparing to Cedar, use the same-machine baseline, and state
  honestly that Cedar does more per decision; do not claim "faster".

- **Conformance is the regression oracle.** `examples/cedar_conformance.rs` runs
  our engine against Cedar's bundled `tiny_sandboxes` corpus and must stay
  **21/21**. Sandboxes needing features we lack (ip/decimal extensions, context
  records) are listed as out-of-scope, not faked.

- **Default eval strategy is `DenyOverride`** (Cedar semantics; most-restrictive
  wins, order-independent). Changing the default breaks conformance. `FirstMatch`
  (ipfw/firewall) is explicit opt-in via `mode first_match` or
  `eval_with_strategy`. Decision algebra resolves by the lattice
  `DENY > REQUIRE_HUMAN > DEFER > REDACT > DOWNGRADE > ALLOW` (this reduces to
  Cedar deny-overrides for permit/forbid-only policies; keep it that way).

- **Fail-closed + visible errors.** A condition that errors must surface in
  `Decision.errors` and never silently become a clean deny. `parse_chai` returns
  a hard error on a malformed statement rather than dropping it.

## Parser/grammar gotchas

- The Pest grammar is inline in `parser.rs` as a raw string with `r##"..."##`
  delimiters, needed because the grammar contains `"#"` (for `#` comments).
- DSL **string literals cannot contain `"`** (the grammar has no escape). Cedar
  UIDs like `User::"alice"` are therefore parsed by the dedicated `entity_lit`
  rule and stored **quote-free** as `User::alice`. When loading Cedar entity
  JSON, `normalize_uid` strips quotes so store keys and request bindings line up.
- After grammar edits, always re-run `cargo run --example cedar_conformance`.

## Deferred work

See `BACKLOG.md` for what's parked vs. cleared. Genuinely still-parked items:
finer-grained taint (v1 is verbatim-token), SSE wire transport for the streaming
governor, wider Cedar differential coverage, a SpiceDB/OpenFGA `EntityResolver`,
HTTP-sidecar hardening (TLS/load), typed `context` records. These are deferred,
not forgotten; don't silently "discover" them as new gaps.

## Implemented: do NOT re-list these as gaps

These were once deferred and are now **done and verified** (`cargo test` + the
feature suites + `cd formal && lake build`, all green as of 2026-07-05):

- **Schema validator** (`schema.rs`): static policy type-checking.
- **SMT / equivalence analysis** (`smt.rs`, feature `smt`): z3 reachability +
  equivalence, validated against an independent complete oracle.
- **Formal proofs** (`formal/`, Lean 4, no `sorry`): determinism, fail-closed,
  forbid-overrides, exact Cedar reduction, emission state machine, PAM guard,
  taint monotonicity. So engine correctness is **both** mechanically proven (the
  deterministic control plane) **and** differentially tested vs. Cedar (a
  PAC-style empirical guarantee over the wider language).
- **PAM guard combinator** (`pam.rs`) and the **ACL / firewall first-match knob**
  (`mode first_match` / `EvalStrategy::FirstMatch`): two alternate policy
  paradigms offered alongside the default Cedar deny-overrides. These are a
  deliberate feature (one language, multiple policy shapes), not scaffolding.
- **Rate-limit + auth-freshness** (`agent_verifier.rs`, `RateLimiter`).

Genuinely **NOT** implemented (by design): YAML/JSON policy interchange (goal-doc
"Form 3"). Cedar *language* features ARE implemented: `ip()`/`decimal()` extension
types + method-call syntax in `evaluator.rs`, policy templates in `template.rs`,
action groups via transitive `in`.
