# Backlog: parked, on purpose

Known-incomplete items, deferred deliberately (not silently dropped). Each notes
why it matters and roughly what closing it takes. Nothing here is claimed as
done elsewhere; the **Cleared** section is what's finished.

## Cleared

- ✅ Real rate-limit + auth-freshness (`RateLimiter`, tested): replaces the old
  `agent_verifier` stubs.
- ✅ Schema + validator (`schema.rs`, tested): static policy type-checking.
- ✅ Lightweight policy analysis: dead-rule/contradiction detection (`analysis.rs`).
- ✅ Cedar differential widened: principal groups, multi-level hierarchy, **ip**
  ext type; 4000 cases vs real Cedar (`tests/differential.rs`).
- ✅ Postgres `EntityResolver` written + compiles behind `postgres` feature
  (only the live-DB integration test remains; see Blocked).
- ✅ **z3-backed SMT analysis** (`src/smt.rs`, feature `smt`): reachability +
  equivalence. Sound+complete over the encoded fragment (boolean combinations of
  linear/polynomial-real comparisons `+ - *` / path-vs-path, entity/string
  equality, boolean atoms), `None` outside it. Validated by an **independent,
  complete oracle** (exact-integer reference over the [0,1]² × bool × open-entity
  grid) asserting EXACT two-way agreement across 6000 conditions, plus a perf/scale
  study to N=800 terms.
- ✅ **Formal Lean proofs** (`formal/`, Lean 4, no Mathlib, `lake build`, no
  `sorry`, axioms = `propext`/`Quot.sound`):
  - `Decision.lean`: determinism/order-independence, fail-closed, forbid-overrides,
    exact reduction to Cedar deny-overrides.
  - `Emission.lean`: halt-absorbing, release-requires-authorizing-effect, finish
    never emits, end-to-end `release_needs_matched_allow`.
  - `PamGuard.lean`, PAM guard combinator (safe variant): order-independence,
    fail-closed, mandatory-dominance, `requisite≡required`.
  - Bridged to the real Rust by property tests (`tests/emission_invariants.rs`,
    `tests/pam_guard.rs`).
- ✅ **PAM guard combinator**: proven + implemented + tested (`src/pam.rs`,
  4681 exhaustive vs independent oracle + 4000-case proof bridges). Two-level
  design: guard gates the rule; effect resolves via the lattice.
- ✅ **MCP decision-point contract (PDP)**, `src/mcp_contract.rs`: JSON-RPC
  `tools/call` + tool-result wire layer → mapped request → verdict, fail-closed.
  Unit + integration tested (`tests/mcp_contract.rs`: contract-vs-engine
  differential, arg binding, result governance).
- ✅ **Runnable sidecar** (`examples/sidecar.rs`, feature `server`): serves the
  PDP over HTTP.
- ✅ **Live FastMCP integration (PEP→PDP)**, `integrations/fastmcp/`: middleware
  calls the sidecar; real end-to-end run enforces call-deny + result
  emit/redact/drop (4/4). FastMCP is the PEP; we are the PDP it calls.
- ✅ **Live DLP detector eval**: real Microsoft Presidio (`en_core_web_lg`) end to
  end through our adapter, 460-case seeded corpus, F1 88.3% (`DETECTOR_EVAL.md`).
- ✅ (bonus) **5** real bugs found+fixed by hard tests: IPv6 equality, decimal
  overflow, unary `not` dropped by the parser, the Cedar `decimal` extension
  not parsed from entity JSON (attribute decimals loaded as records → method
  errored → spurious allow; caught by the widened differential), and a **redact
  fail-open**: a `Redact` verdict whose span-masker localized no PII span emitted
  the chunk *verbatim* (ESP said "unsafe, redact"; enforcement removed nothing and
  released the raw prefix). Now fail-closed: a redaction that removes nothing
  drops the chunk (`emission.rs`, `redact_with_no_maskable_span_is_fail_closed`);
  caught by `examples/full_pipeline.rs`. Two tests had silently baked in the old
  behavior (`mcp.rs`, `tests/mcp_contract.rs`) and were corrected to real PII.
- ✅ (bonus) **3** more real bugs found by applying the `code_eval` review
  framework, two reproduced live (`CODE_EVAL_RESULTS.md`): the parser silently
  dropped arithmetic (`+ - * / %`) so `a + b == 8` evaluated as `a == 8`; the
  `like` glob panicked on multibyte UTF-8 (an availability hole in the enforcer);
  and a JSON-RPC batch array slipped past the tool-call gate on all three
  transports (an authorization bypass). All fixed with regression tests, plus a
  shared `gate_intercepted_body`, overflow-safe arithmetic, an ICAP allocation
  cap, and a constant-time bearer check.

## Cleared (continued)

- ✅ **Taint / dataflow.** `src/taint.rs` (monotone taint set, distinctive-token
  labeling, `sink_facts` projection) wired into `lib.rs`; unit + property +
  integration tested (`tests/taint_props.rs`) + adversarial (`tests/exfiltration.rs`,
  with an honest known-miss); **proven** (`formal/ChaiProofs/Taint.lean`:
  `session_monotone`, `tainted_sink_denied`, `clean_sink_defers`). The labeling is
  now v2 (laundering-resistant), cleared below; the proven enforcement is unchanged.

## Still parked / future (lower priority)

- ✅ **README links-on-top (vLLM-style).** Badges (playground / Lean-proofs /
  license) and an all-links bar (Docs · Quick start · Playground · Tour · RAG
  example · Deploy · Benchmarks · verified) now sit above the fold. A "Latest News"
  block is N/A until there is news.

- **Fragment-aware taint.** v2 defeats case, whitespace/punctuation splitting, and
  base64/hex encoding. A secret interleaved with filler text stays a measured miss
  (`tests/exfiltration.rs`), since normalization concatenates the filler. Fragment
  reassembly would close it without touching the proven enforcement.

## agentgateway bit-to-bit: ✅ DONE (verified live)

- ✅ **Live three-component run passes** (`integrations/agentgateway/`): a real MCP
  server behind agentgateway (Docker), agentgateway's HTTP `extAuthz` +
  `includeRequestBody` forwarding each `tools/call` to our sidecar `/extauthz`.
  Result: `read` permitted → agentgateway **200**; `write` denied → agentgateway
  **403 DirectResponse**, byte-identical to the direct PDP (`/extauthz` read→200,
  write→403) and to FastMCP. **Bit-to-bit verified.** `/extauthz` gates
  `tools/call` and passes MCP plumbing (initialize/list/notifications) through.
- *Scope:* tool-**call** authorization (the bit-to-bit target). Result governance
  is not possible via `extAuthz` (request-authz can't modify responses); see the
  ICAP direction below for that.

## (superseded) agentgateway: earlier blocked notes

- **Resolved the open question** (`integrations/agentgateway/README.md`): Docker
  daemon now up; agentgateway 1.3.1 pulled + config validates. agentgateway's
  native `mcpAuthorization` is built-in CEL (tool-name + JWT only, **no args**, no
  delegation), BUT HTTP `extAuthz` with `includeRequestBody` **forwards the MCP
  JSON-RPC body to an external PDP** → delegation is viable.
- ✅ Sidecar `/extauthz` endpoint built + tested (`server.rs`, verdict ↔ engine
  decision, fail-closed). ✅ `extAuthz`→sidecar config validated.
- ⬜ **Remaining (the actual bit-to-bit run):** stand up a real MCP server behind
  agentgateway, route tool calls, assert `agentgateway ≡ engine ≡ FastMCP`. Needs a
  host-reachable MCP server + the differential harness.
- *Honest scope:* `extAuthz` covers tool-**call** authorization (the bit-to-bit
  target); it does NOT do result governance (request-authz can't redact responses);
  that stays a FastMCP capability. SSE multiplexing needs live confirmation.
- ~~Postgres live-DB integration test~~ ✅ **DONE**: `tests/postgres.rs`
  (feature `postgres`) verifies attr / has_attr / transitive `in` (recursive CTE)
  + a full ReBAC decision against a real Postgres (Homebrew `postgresql@16`).
  Skips gracefully when no DB is reachable. Re-run live 2026-07-05 (2/2).
- ✅ **Redis-backed `EntityResolver`** (`src/redis_store.rs`, feature `redis`):
  attributes in a hash, parent edges in a set, transitive `in` by client-side BFS,
  fail-closed. Verified live against real Redis 8.8.0 (`tests/redis.rs`, 2/2,
  self-seeding, skips when no Redis). The resolver is the plug point: `EntityStore`
  (in-memory), `PgStore`, `RedisStore`, or any `EntityResolver` all drop into the
  evaluator and every deployment surface unchanged.
- ✅ **In-process C ABI** (`src/ffi.rs`, feature `capi`): `chai_decide` (honors the
  `mode` directive, so deny-override and ACL both work) and `chai_pam_decide`,
  returning JSON. One shared `embed::evaluate_json` also powers the WASM build.
  In-process samples for C, C++, Go (cgo), and Python (ctypes) in
  `integrations/embed/`, each running all three paradigms.
- **Live SAFETY detector eval** (Llama Guard / Lakera): needs a GPU or paid API +
  off-box egress. Note: Llama Guard is runnable locally via Ollama on Apple
  Silicon; a scored benchmark measures the *vendor's* accuracy, so the parity item
  is a live integration smoke test, not an accuracy benchmark (`DETECTOR_EVAL.md`).

## Cleared (continued)

- ✅ **Fault injection / trust-boundary** (`integrations/fastmcp/fault_test.py`,
  8/8). The PEP→PDP link is broken every way (explicit deny, PDP 500, non-JSON,
  wrong-shape verdict, unreachable, timeout, and a mid-call "chaos" failure) and
  the PEP **fails closed** in every case. Middleware hardened to deny on any
  failure to obtain a well-formed verdict (`ChaiEnforcement._ask`).

## Cleared (continued)

- ✅ **Span-masking redaction obligation.** `emission.rs::redact` now masks only
  the PII spans (email/SSN/card/phone/IP via `regex`) and keeps the rest, instead
  of nuking the whole prefix (`[REDACTED:N chars]`). Unit-tested + verified live
  through FastMCP (`'customer ssn [SSN] email [EMAIL] on file'`). Detector-supplied
  spans (Presidio start/end) can extend it; these patterns are the always-on base.
- ✅ **Sidecar hardening: bearer-token auth.** `server.rs` gains optional
  `Authorization: Bearer` enforcement (`AppState.token`, fail-closed `401` via
  middleware); `CHAI_SIDECAR_TOKEN` env enables it in the runnable sidecar; the
  FastMCP middleware sends it. Tested (`bearer_token_is_enforced`). (TLS / load
  still parked.)
- ✅ **Cedar differential: `decimal()` + records.** `tests/differential.rs` now
  carries a `decimal()` cost attribute and a record (`meta.level`) on every
  resource, with policy terms cross-checked vs real Cedar across the 400-case
  proptest run. Found+fixed the 4th bug (above).
- ✅ **Streaming prefix-enforcement (core)**: `StreamingResultGovernor`
  (`src/mcp_contract.rs`) drives the proven Emission state machine over a chunked
  tool result: clean prefixes emit, the chunk that trips a deny is dropped, and an
  unapproved buffer is dropped at `finish` (fail-closed). Integration-tested
  (`tests/mcp_contract.rs`). **Remaining:** wire it to the actual streamable-
  HTTP/SSE transport in the proxy/sidecar (below).

## Cleared (continued)

- ✅ **ICAP server (REQMOD + RESPMOD)**: `src/icap.rs` (feature `icap`, std-only),
  runnable via `examples/icap.rs`, verified end-to-end by a minimal ICAP client
  (`integrations/icap/icap_test.py`, 6/6): OPTIONS advertises methods; REQMOD
  authorizes a `tools/call` body (allow→204, deny→403); RESPMOD **redacts the
  response body** (span-masked `[SSN]`/`[EMAIL]`) or withholds it. This is the
  surface that carries content adaptation through standard proxies (Squid/DLP),
  which ext-authz can't do. (Non-preview; preview/ieof/trailers are a documented gap.)
- ✅ **`chai test --trace`** + sample scripts (`samples/`): print-while-testing
  (reason/rules/errors per scenario) and runnable example policies+tests.

## Cleared (continued)

- ✅ **ext-authz gRPC (Envoy-compatible)**, `src/grpc_authz.rs` (feature `grpc`,
  via `envoy-types`/`tonic`): implements the Envoy External Authorization v3
  `Check` API so Chai drops into Envoy/Istio/agentgateway over gRPC. Verified
  in-process (read→OK/0, write→PermissionDenied/7, plumbing→OK). Full protocol
  set now: HTTP sidecar · ext-authz HTTP (live agentgateway) · ext-authz gRPC ·
  ICAP · WASM.
- ✅ **`chai fmt`**: string-aware whitespace-normalizing formatter (validate +
  tidy, idempotent); **LICENSE** (MIT) + **CI** (`.github/workflows/ci.yml`:
  tests, feature builds, conformance, z3, Lean proofs).
- ✅ **Live Llama Guard smoke**: real `llama-guard3:1b` via Ollama →
  `safe`/`unsafe\nS1`, parseable by the `LlamaGuardDetector` adapter
  (`integrations/llama_guard/smoke.py`, 2/2). The safety-integration check
  (vendor accuracy benchmark remains out of scope, by design).
- ✅ **WASM playground**: guided rule-builder + raw toggle + help/examples + REPL
  authoring + copy/share/export, real engine in-browser (`integrations/playground/`).

## Cleared (continued)

- ✅ **SSE wire transport.** `mcp_contract::{parse_sse_events, govern_sse}` frames a
  streamable-HTTP/SSE tool-result stream into chunks, drives the proven
  `StreamingResultGovernor` over them, and re-frames the governed output as SSE
  (released prefixes → `data:` events; withheld chunks → verdict-only comments;
  unapproved buffer dropped at end-of-stream). Exposed at the sidecar as
  `POST /filter_tool_result_sse` (`server.rs`). Unit + integration + endpoint
  tested (`parse_sse_events_spec_shapes`, `sse_stream_governed_and_reframed`,
  `filter_sse_endpoint_governs_stream`).
- ✅ **Full chaos run.** `integrations/fastmcp/chaos_test.py` (12/12) starts the
  REAL sidecar subprocess and, over a run of many calls, freezes it (SIGSTOP →
  timeout fail-closed → SIGCONT recovery), kills it (fail-closed), and restarts it
  (clean recovery). The PEP never fails open. The longer systemic complement to
  the single-process `fault_test.py`.

## Still parked (lower priority)

- **Cedar differential: wider coverage.** Deeper hierarchies, `decimal()`/records
  cross-checked vs Cedar (ip is done; these have boundary unit tests). First-match
  mode needs a non-Cedar reference. *Closing it:* widen the scenario generator.
- **Cedar's own bar.** Cedar fuzzes against a formal Lean model far wider than our
  generated cases. Our decision/emission cores are now Lean-proven and the z3
  encoding is differentially tested, but the *full language* is not mechanized.
- **SpiceDB / OpenFGA adapter.** Same `EntityResolver` trait, for Zanzibar-scale
  ReBAC. Only needed if relationship volume outgrows Postgres.
- **HTTP sidecar hardening (partly done).** Auth is done (constant-time bearer
  token). Request bodies are now bounded (`CHAI_MAX_BODY_BYTES`, default 1 MiB,
  rejected 413 before any handler, fail-closed; `server.rs` test). TLS/network
  posture is documented in `router()` (terminate at a proxy or mesh mTLS, keep the
  PDP private). Remaining: real load/soak testing, and concrete obligation handlers
  (real alerting/logging/span-masking) which are app-level — the executor exists,
  the handlers don't.
- **Incremental AFC for external detectors.** `StreamingAfc` is O(chunk) for local
  heuristics; external (`Callee`) detectors are inherently per-call.
- **YAML/JSON policy interchange (goal-doc "Form 3").** Consciously dropped.

## Cleared (continued)

- ✅ **Typed `context` records.** `schema.rs` types named records (`Ty::RecordOf`,
  `add_record`/`add_context`), including **nested** records, and type-checks
  field access / comparisons against them. Undeclared context stays `Unknown`
  (back-compat, no false errors). Tested (`accepts_well_typed_context`,
  `catches_context_type_mismatch`, `catches_unknown_context_field`,
  `types_nested_context_records`, `undeclared_context_stays_unknown`).
- ✅ **Finer-grained taint (v2, laundering-resistant).** `src/taint.rs` adds a
  normalized taint set + base64/hex decode at match time, defeating case /
  whitespace / punctuation splitting and encoding laundering (the old v1
  known-miss now blocks). Deeper interleaved-filler laundering remains a measured
  miss. Unit + adversarial tested (`tests/exfiltration.rs`); the proven monotone
  projection (verbatim set) is unchanged, so `Taint.lean` still bridges.
