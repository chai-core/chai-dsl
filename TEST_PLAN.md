# Functional test plan: MCP proxy, dataflow/taint, PAM guard

Companion to the proofs (`formal/`) and the accuracy evals (`DETECTOR_EVAL.md`).
This covers the **functional** behavior of the three new surfaces. It reuses the
methods already load-bearing in this repo rather than inventing a process.

**The test pyramid, bottom-up.** Proofs and differentials are the *apex*, sitting
above the base: they assume the units work. So every component gets, in order:

| Layer | Method | Already used in | Good for |
|---|---|---|---|
| **base** | **Unit tests** (one function, isolated, many, fast) | `src/*.rs` `#[cfg(test)]` mods (e.g. `emission.rs`, `afc.rs`, `evaluator.rs`) | each function does what it says; every error branch |
| **base** | **Integration tests** (components wired, real I/O) | `tests/*.rs`, `examples/full_pipeline.rs` | the seams hold: AFC→ESP→Emission, sidecar over HTTP, adapter↔engine |
| mid | **Conformance corpus** (frozen oracle, stays green) | `examples/cedar_conformance.rs` (21/21) | regression against a known-good set |
| mid | **Generative differential** vs an *independent* oracle | `tests/differential.rs`, `src/smt.rs` | semantic correctness on inputs nobody hand-picked |
| apex | **Property test bridging a proof** | `tests/emission_invariants.rs` | the *real code* obeys a *Lean-proven* invariant |
| cross | **Boundary / adversarial** hard cases | `tests/rigor.rs` | real bugs at the edges |
| cross | **Live eval, honest numbers** | `examples/detector_eval.rs` | the heuristic/probabilistic parts |
| cross | **Fail-closed / fault injection** | `tests/rigor.rs`, emission tests | the security-critical "must deny" paths |

Rule of thumb per component: **most** tests are UT, **many** are IT, a **handful**
are differential/property/proof-bridge. If a section below has proofs but no unit
tests, it is incomplete.

**Ownership rule (what we actually test).** We test *our* behavior: message→request
mapping, decision-contract fidelity, enforcement, taint propagation/enforcement,
the PAM evaluator. We do **not** re-benchmark vendor accuracy (Presidio/Llama
Guard/the proxies' own correctness); that's theirs, established separately.

**No-fabrication rule.** Every number lands in `DETECTOR_EVAL.md`/`BENCHMARKS.md`
from a real run. Adversarial suites report **miss rate honestly**: where taint
matching still misses (e.g. a secret interleaved with filler) it says so; it does
not claim completeness.

---

## 1. PAM guard combinator (`PamGuard.lean` is proven; functional bridges proof→code)

Files: `src/pam.rs` `#[cfg(test)]` (units), `tests/pam_guard.rs` (the rest).

**Unit tests (the base, most of the count):**
- **Tag parsing:** each of `required|requisite|sufficient|optional` → correct
  `Flag`; unknown tag / missing colon / empty guard → **hard parse error** (never
  a silent pass).
- **Single sub-condition eval:** `required: <cond>` evaluates `<cond>` against a
  context to the right boolean; a sub-condition that *errors* → guard denies
  (fail-closed), no panic.
- **`passes` on hand-cases (truth table by hand):** `[]`→deny, `[(optional,T)]`→
  deny, `[(required,T)]`→pass, `[(required,F)]`→deny, `[(sufficient,T)]`→pass,
  `[(sufficient,F)]`→deny, `[(required,T),(sufficient,F)]`→pass,
  `[(required,F),(sufficient,T)]`→deny. One assertion each.

**Integration tests:**
- A `permit` rule with a PAM guard, parsed via `parse_chai`, evaluated through the
  full pipeline against a real context → expected `Effect`.
- PAM guard reading live AFC facts (`dlp_facts.*`, `risk_facts.*`) end to end.
- PAM guard + several rules → deny-override resolution is correct (PamGuard ×
  `Decision` wired together).

**Then the apex (semantic/proof) layer:**

1. **Exhaustive truth-table differential (complete oracle).** For every guard up
   to size N (all `{required,requisite,sufficient,optional}` × `{pass,fail}`
   combinations, finite, so exhaustive ⇒ a *complete* decision procedure), assert
   the Rust evaluator's verdict equals an **independent** reference computing the
   AND/OR formula `(∃gate) ∧ (∀mandatory pass) ∧ (¬∃sufficient ∨ ∃sufficient pass)`.
   *Pass:* exact agreement for all guards ≤ N (target N=5 → all combos), random
   beyond. Mirrors the `src/smt.rs` independent-grid method.
2. **Proof-bridging property test.** Over thousands of random guards assert the
   four `PamGuard.lean` theorems hold in the Rust code:
   - `passes_perm`: shuffle the stack ⇒ identical verdict (this is the *safe-variant*
     assertion; it would **fail** for faithful PAM, documenting the choice);
   - `not_passes_nil`: empty / all-`optional` ⇒ deny;
   - `mandatory_fail_denies`: inject a failed `required`/`requisite` ⇒ deny;
   - `required_requisite_same_class`: swap `required`↔`requisite` ⇒ identical verdict.
3. **Parser / boundary / fail-closed.** Malformed tag ⇒ hard parse error (never a
   silent pass, the `parse_chai` discipline). Mixed guards, duplicate tags, a lone
   `optional`, a lone failing `sufficient`.
4. **Composition.** A passing guard's effect resolves through the deny-override
   lattice exactly as `eval_rules` does (integration of PamGuard × `Decision`).

---

## 2. MCP proxy integration

Decision-point contract: `MCP message → request mapping → verdict {allow|deny|redact|transform}`.

Files that exist: `src/mcp_contract.rs` (the PDP contract plus `#[cfg(test)]`
units), the `tests/mcp_contract.rs` integration suite (in-process). A live-proxy
suite (`tests/mcp_integration.rs` behind its own feature) is planned and not built
yet. It would need a running proxy and stay out of the default tree.

**Unit tests (the base):**
- **JSON-RPC decode:** valid `tools/call` → struct; missing `method`/`id`/`params`
  → error; wrong `"jsonrpc"` version → error; batch array; oversized/garbage → error.
- **Message→request mapping, per method:** each field extracted correctly: tool
  name, structured args, resource URI, prompt name, identity/scopes from the auth
  token. One test per field, including absent/null.
- **Verdict serialization:** `allow|deny|redact|transform` → correct JSON-RPC
  response / error shape.
- **Redaction fn:** masks the PII span, leaves the rest byte-identical; empty/no-PII
  → unchanged.
- **Arg binding:** nested tool args → context so a policy `tool.args.to.domain`
  resolves; missing path → fail-closed, not panic.
- **SSE framing (`parse_sse_events`):** the SSE spec shapes (`data:`-only events,
  multi-line `data:`, `event:`/`id:`/comment lines, blank-line dispatch, a
  trailing event without a final blank line), each parsing to the right event set.

**Integration tests (in-process, no external proxy):**
- Sidecar (`server.rs`/axum) serves a decision request over HTTP → correct verdict
  (in-process client).
- Full contract end to end: raw MCP message bytes → mapping → `eval` → verdict
  response, no proxy.
- Result-governance pipeline: tool *result* → AFC → ESP → Emission as one wired
  flow → governed bytes out.
- **SSE governance (`govern_sse`):** a streamed tool result → clean prefixes leave
  as `data:` events; a chunk carrying a secret is **withheld**; unapproved buffer
  is **fail-closed** dropped at end of stream (the streaming analogue of
  result-governance, through the proven Emission state machine).
- **Sidecar SSE endpoint (`filter_sse_endpoint_governs_stream`):** the same stream
  driven over HTTP via `POST /filter_tool_result_sse` yields the governed events.

**Then the apex layer:**

1. **Request-mapping conformance.** A frozen corpus of real MCP messages
   (`tools/call`, `tools/list`, `resources/read`, `prompts/get`,
   `sampling/createMessage`) → assert each maps to the expected
   `(subject, object, action, context)`. *Oracle:* hand-checked against the MCP
   spec, frozen like the Cedar corpus. *Pass:* corpus stays green.
2. **Contract-vs-engine differential.** For random (policy, mapped request),
   `decision-via-contract == eval_with_store(direct)`. The adapter must **not**
   change semantics, only transport. Generative, independent of (1).
3. **Cross-proxy differential (VERIFIED LIVE).** Same policy and same MCP request
   routed through agentgateway and FastMCP, asserting an identical verdict that
   also matches the in-process engine. Confirmed **bit-to-bit**: agentgateway ≡
   engine ≡ FastMCP (a `read` tool call → 200/allow, a `write` → 403/deny). The
   core is proxy-independent: the deploy surface does not change the decision.
4. **Result governance (the differentiator).** Tool result containing PII ⇒
   redacted before reaching the client; clean result ⇒ verbatim passthrough;
   streaming result ⇒ prefix-enforced through the (proven) Emission state machine.
   Assert the *bytes that leave* match the policy.
5. **Fail-closed matrix**: the security-critical paths, each must **deny**, never
   allow:
   - sidecar unreachable / timeout;
   - malformed or non-JSON-RPC message;
   - unknown tool / unmapped action;
   - partial/truncated streaming frame;
   - verdict channel corrupted (fault injection, see §4 trust boundary);
   - **redact with nothing to mask** (`redact_with_no_maskable_span_is_fail_closed`,
     `src/emission.rs`): when the masker localizes no span, the chunk is **dropped**,
     never released unmasked.
6. **Latency budget.** Criterion bench (`benches/`) for decision overhead on the
   hot path, fast-path (no heavy detector) vs heavy-path (AFC live). Numbers →
   `BENCHMARKS.md`. *Pass:* bounded, documented overhead; no fabricated figures.

---

## 3. Dataflow / taint

Split per the architecture: **labeling = AFC (heuristic, eval'd)**, **propagation =
monotone (property-tested)**, **enforcement = ESP/Emission (proven; integration-tested)**.

Files that exist: `src/taint.rs` `#[cfg(test)]` (units), `tests/taint_props.rs`
(integration plus property), `tests/exfiltration.rs` (adversarial). A labeling
eval (`eval/taint_eval.py` + `examples/taint_eval.rs`) is planned and not built yet.

**Unit tests (the base):**
- **Label attach:** untrusted source → data carries a taint label; trusted → none.
- **Taint-set ops:** add / lookup / union; **add never removes** (the monotone
  primitive, unit-checked before the property test leans on it).
- **Sink match:** a tool-call arg containing a tainted value → flagged; a clean arg
  → not.
- **Fact projection:** taint state → the `tooltrace.*` fact ESP reads.
- **Missing state → fail-closed:** absent taint info ⇒ label as tainted, never clean.

**Integration tests:**
- Two-step session wired through real components: result A (untrusted) → taint
  propagates → call B (sink) → ESP reads the taint fact → **deny**.
- Same flow **with** a permitting policy → allow; **without** → deny.
- AFC produces taint facts that ESP consumes: the inference→control seam, end to end.

**Then the apex / adversarial layer:**

1. **Labeling eval (PLANNED, heuristic, honest numbers).** Labeled corpus of
   (tool-result, is-untrusted) → measure taint-labeling precision/recall, same
   shape as the Presidio eval. Result → `DETECTOR_EVAL.md`. *This is the part that
   is the tool's/heuristic's quality, not a correctness claim.*
2. **Monotonicity property test (bridges evidence-monotonicity).** Over random
   session traces, assert the taint set only **grows**: `taint(t) ⊆ taint(t+1)`.
   This is the Rust check of the monotone-facts invariant the proofs rely on.
3. **Enforcement differential.** Random (taint facts, sink policy) ⇒ runtime
   verdict equals the proven model: tainted→sink with no permitting policy ⇒
   **deny**; with a permitting policy ⇒ allow; non-tainted ⇒ unaffected.
4. **Adversarial exfiltration suite (`tests/exfiltration.rs`).** Hand-built and
   generated agent traces:
   - **negative (must block):** read untrusted doc → attempt external send;
     multi-hop laundering; tainted value embedded in a larger arg;
   - **positive (must allow):** legitimate non-tainted flows, which guard against
     **over-blocking** (a redaction tool that drops all traffic scores 100% on
     "block exfil" while being useless; the positive set prevents that lie);
   - **report a miss rate (v2).** Matching is now **normalized** (case /
     whitespace / punctuation splitting are folded out) with **base64 + hex
     decode**, so the laundering that the coarse verbatim v1 missed is now caught:
     `catches_whitespace_and_case_laundering` and
     `catches_base64_and_hex_encoding` both block. The remaining **measured** miss
     is a secret interleaved with filler text (a deeper miss, kept as an honest
     documented case in `tests/exfiltration.rs`); the suite still **measures and
     reports** rather than claiming completeness.
5. **Fail-closed.** Taint state unavailable/errored ⇒ treat data as **tainted** ⇒
   deny the sink. Never fail-open.

---

## 4. Cross-cutting

- **Trust-boundary fault injection, IMPLEMENTED** (`integrations/fastmcp/fault_test.py`,
  8/8). The end-to-end MCP guarantee assumes the proxy faithfully delivers every
  message and applies our verdict (see `formal/README.md` scope). We probe the
  PEP→PDP link with a controllable mock PDP and assert the PEP **fails closed** in
  every failure mode: explicit deny, PDP 500, non-JSON body, wrong-shaped verdict,
  PDP unreachable, and PDP timeout. The middleware is hardened to fail-closed
  explicitly (`ChaiEnforcement._ask`): any failure to obtain a well-formed verdict
  blocks the operation. We can't prove the proxy; we prove we degrade safely.

- **§5 Chaos, IMPLEMENTED** (`integrations/fastmcp/chaos_test.py`, 12/12).
  Systemic / mid-session failure against the *real* sidecar process: SIGSTOP-hang
  ⇒ timeout fail-closed ⇒ SIGCONT recovery; kill ⇒ fail-closed; restart ⇒
  recovery. Asserts fail-closed throughout the outage and clean recovery when the
  PDP returns. (The in-process "PDP fails mid-call" case, where authorize succeeds
  but the PDP dies before result governance ⇒ the result is blocked, is also covered by
  the fault-injection matrix above.)
- **CI gates (must stay green, like 21/21 conformance):**
  - `cargo test` (default tree), which *is* the UT + IT base: every `#[cfg(test)]`
    unit module and every `tests/*.rs` integration test, plus `--features smt`;
  - `cargo run --example cedar_conformance` = 21/21;
  - `cd formal && lake build` (no `sorry`);
  - `tests/pam_guard.rs`, `tests/emission_invariants.rs` (proof-bridges);
  - `tests/mcp_contract.rs`, `tests/taint_props.rs`.
  - Live suites (the planned `mcp-integration` proxy tests, the evals) run on
    demand, not in the default gate (they need proxies / Python / models).
- **Regression corpus growth.** Every real bug found becomes a frozen case (the
  `rigor.rs` discipline); IPv6/decimal/unary-`not`-class bugs don't recur.

## Honesty ledger (what each claim rests on, and does NOT establish)

| Claim | Validated by | Does NOT establish |
|---|---|---|
| PAM verdict is correct + order-independent | proof + exhaustive truth-table + proof-bridge | nothing beyond the safe variant (faithful PAM is a different, weaker model) |
| MCP decision is faithful to the engine | contract-vs-engine differential (`tests/mcp_contract.rs`) + 3-way cross-proxy differential verified live (agentgateway ≡ engine ≡ FastMCP; read→200 / write→403) | that the proxy itself is correct (trusted PEP boundary) |
| Tainted→sink is blocked | proven enforcement + adversarial suite | that *labeling* catches all taint (heuristic; miss rate reported) |
| Fail-closed everywhere | fault-injection matrix | liveness/availability under attack |
| Performance overhead | criterion, in `BENCHMARKS.md` | behavior under production load (not load-tested) |
