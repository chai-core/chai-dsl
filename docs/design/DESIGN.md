# Chai: Design Doc (for the platform & proxy team)

Audience: engineers building (a) an **agentic system** and (b) an **MCP proxy**
that integrate with Chai. This explains the architecture, the contracts you
build against, your responsibilities at the trust boundary, and how to extend it.

For *usage* see [`user-guide/`](../../user-guide/). For the *proofs* see
[`formal/README.md`](../../formal/README.md). This doc is the "how it fits
together and what you must uphold" view.

---

## 1. The big picture

Chai is a **verified Policy Decision Point (PDP)** for agent emission and
actions. It decides; something else (your agent runtime, your MCP proxy) enforces.

```
                        ┌─────────── Chai (PDP) ───────────┐
 agent draft / tool ───►│  AFC        ESP            Emission   │──► verdict
 call / tool result     │  (facts)  (decision)   (stream enforce)│
                        └───────────────────────────────────────┘
                                   ▲ you call us
        ┌──────────────────────────┴───────────────────────────┐
        │  YOUR agentic runtime  /  YOUR MCP proxy  (the PEP)    │
        │  in the data path; APPLIES the verdict; trusted        │
        └───────────────────────────────────────────────────────┘
```

Four layers, each a module, deliberately decoupled (the "separation of inference
from control" invariant):

| Layer | Responsibility | Module | Determinism |
|---|---|---|---|
| **Chai** | drive an agent through the pipeline | `chai.rs` | n/a |
| **AFC** | output/result → typed evidence facts | `afc.rs` | probabilistic (detectors) |
| **ESP** | `(subject, object, facts) → Decision` | `evaluator.rs`, `parser.rs`, `entity.rs` | **deterministic, proven** |
| **Emission** | per-prefix emit/buffer/redact/drop/halt | `emission.rs` | **deterministic, proven** |

Plus cross-cutting: `pam.rs` (guard combinator), `taint.rs` (dataflow),
`mcp.rs` + `mcp_contract.rs` (the MCP boundary), `server.rs` (the HTTP sidecar).

**Design rule that keeps it verifiable:** *inference* (probabilistic facts:
PII/safety/taint labeling) lives in AFC and is empirically tested; *control*
(the decision + emission) is a pure fold and is mechanically proven. Never let
control mutate state mid-evaluation; that breaks the proofs.

---

## 2. The data model you build against

A request the PDP evaluates:

```
⟨ subject s, object o, draft/result x, context C ⟩
```

- **subject** is the acting agent: `principal` (UID, for ReBAC) + `subject`
  attributes (trust_tier, role, capabilities) for ABAC.
- **object** is the emission/action target: action (tool name), channel,
  destination, audience, persistence.
- **facts F** are `AFC(x, s, o, C)`: typed evidence `⟨v, σ, m, c, τ⟩` across six
  namespaces (dlp / safety / grounding / schema / tooltrace / risk).
- **context C** is session metadata, taint state, anything your runtime knows.

All of this is just keys in the eval `HashMap<String, Value>`. Subject/object
checks are therefore ordinary policy rules on the same decision path as everything else.

`Decision { effect, reason, reason_codes, obligations, rule_trace, errors }` is
the verdict **and** the audit trail. `effect ∈ {Allow, Deny, Redact, Defer,
Downgrade, RequireHuman}`; default Deny.

---

## 3. Contracts you implement / call

### 3a. If you're building the AGENTIC RUNTIME

You consume the PDP. Hook points, tightest to loosest:

1. **`Agent` trait + `run_chai`**: let Chai drive your LLM; you implement
   `Agent`. Easiest if you're greenfield.
2. **`EmissionEnforcer::step(chunk, facts)`**: you own the token loop; call this
   per chunk and act on the `EmitAction`. Use when you already have a stream.
3. **`eval_with_store` / `authorize_tool_call` / `filter_tool_result`**: direct
   decisions; you assemble the context.

Your responsibilities:
- **Compute or inject facts** (AFC): run detectors, attach taint, build the fact
  context. Keep taint **monotone** within a session.
- **Honor the verdict**: `Drop`/`RequireHuman` must actually stop output;
  `Redact` must release the transformed text, not the original.
- **Maintain session state** (one `TaintTracker` per session; auth-freshness).

### 3b. If you're building the MCP PROXY (the PEP)

You are in the MCP data path and call the PDP. The PDP ships in several **deploy
surfaces**; pick the one that matches your data path:

- **in-process crate**: embed the engine directly (Rust);
- **HTTP sidecar** (`server.rs`): the JSON API below;
- **ext-authz**: agentgateway external authorization over **HTTP and gRPC**;
- **ICAP**: **REQMOD + RESPMOD** for content-adaptation proxies;
- **WASM**: the engine compiled to a raw C-ABI module (`src/wasm.rs`);
- **MCP PDP**: the MCP-native contract (`mcp_contract.rs`).

The sidecar contract (or embed the crate in-process for Rust):

```
POST /authorize_tool_call     {subject_uid, subject_attrs, tool, args, resource?}
                           ->  {effect, reason, rule_trace, errors}
POST /filter_tool_result      {subject_uid, subject_attrs, tool, result}
                           ->  {action, released, effect, reason}
POST /filter_tool_result_sse  {subject_uid, subject_attrs, tool, sse}
                           ->  governed SSE stream (data events)
```

For a **streaming** tool result, `/filter_tool_result_sse` is the SSE analogue
of `/filter_tool_result`: it is backed by `mcp_contract::parse_sse_events`
(SSE framing) + `govern_sse` (prefix-enforced through the proven Emission state
machine), so clean prefixes flow through as `data:` events and a chunk that
trips a rule is withheld; fail-closed at end of stream.

Per intercepted MCP message:

1. **`tools/call`** → map to `{subject (from the OAuth/JWT identity you hold),
   tool=params.name, args=params.arguments}` → `POST /authorize_tool_call`. If
   `effect != Allow`, **block** the call (return an MCP error). Else forward.
2. **tool result** → extract text content → `POST /filter_tool_result`. Apply:
   - `emit` → forward verbatim;
   - `redact` → forward `released` (the masked text) instead;
   - `drop`/`buffer`/`require_human` → **do not forward** the result.

A reference implementation exists for FastMCP
(`integrations/fastmcp/chai_middleware.py`); mirror its shape.

**You must uphold (the trusted-PEP contract, the proofs depend on it):**
- **Completeness:** call the PDP on *every* relevant message. A bypassed message
  is unenforced.
- **Fidelity:** apply the verdict exactly. Don't downgrade a `drop` to a log line.
- **Fail-closed:** if the PDP is unreachable / errors / times out, **deny/drop**,
  never fail-open. (The PDP already fail-closes on its side; you must too.)
- **Identity:** you own authn (OAuth 2.1/JWT). The PDP *consumes* the identity you
  pass; it does not establish it.

**Bit-to-bit target:** a request through your proxy must yield byte-identical
verdicts to the engine and to FastMCP. We test this as a three-way differential.

---

## 4. Decision semantics (what the proofs guarantee you)

- **Most-restrictive-wins lattice:** `DENY > REQUIRE_HUMAN > DEFER > REDACT >
  DOWNGRADE > ALLOW`; reduces to Cedar deny-overrides for permit/forbid policies.
- **Order-independent** under the default `deny_override` strategy: no rule can
  be shadowed by ordering (`decision_perm`). `first_match` is opt-in and
  order-dependent; use it only when you want priority semantics.
- **Fail-closed everywhere:** no match → Deny; an errored rule is **effect-tagged**
  (a strict restrictive rule contributes its effect, so a failed `forbid` denies:
  `restrictive_error_restricts`; a permit/`lenient` error is inert:
  `permit_error_inert`); emission releases only via an authorizing effect
  (`release_effect`); a `require_human` outcome seals the stream even when a deny
  wins (`seal_on_presence_perm`); halt is sealed (`sealed_stream`); end-to-end,
  output reaches the sink only on an explicit permit (`release_needs_matched_allow`).
- **Resolver backends fail closed too:** the `EntityResolver` trait is fallible;
  a Postgres/Redis timeout, connection failure, or malformed response during an
  `in`/attribute lookup becomes the `Err` outcome for that rule (the same
  effect-tagged path as a detector failure), never a silent `false`/`None` that
  could let a `forbid … in …` rule quietly not fire.
- **Algebra extensions (all proven):** obligations accumulate from every matched
  releasing rule at-or-below the verdict (`obligations_complete`, so redact+downgrade
  both apply); an evidence-tier gate (`requires attested`) blocks a rule from firing
  on weaker evidence (`attested_gate_sound`); monotone session budgets keep released
  spend within a cap (`spend_bounded`); endorsement composes an attested approval
  with the Approve transition; and an opt-in k-lookahead window makes a substring
  within *k* chunks release atomically (`substring_atomic`).
- **Redact fail-closes too:** if the masker localizes no span to redact, the
  chunk is **dropped** rather than released unmasked.
- **Taint:** monotone (`session_monotone`); a tainted sink is denied regardless of
  permits (`tainted_sink_denied`).

All `formal/`, no `sorry`, axioms = `propext`/`Quot.sound`. The Rust↔Lean
correspondence is argued by inspection and checked empirically by property tests
(`tests/emission_invariants.rs`, `tests/pam_guard.rs`, `tests/taint_props.rs`).

---

## 5. Extension points

| Want to… | Implement / use |
|---|---|
| add a detector (PII, safety, custom) | the `Detector` trait → `Afc::compose` / `with_external` |
| back entities with a real store | the `EntityResolver` trait (in-mem / Postgres / SpiceDB) |
| change resolution semantics | `mode deny_override` / `mode first_match` (or add a proven strategy) |
| multi-factor guards | the `pam` combinator (proven) |
| new obligation handler (redact spans, alert) | the `ObligationExecutor` seam (`runtime.rs`) |

When adding a resolution strategy or combinator, keep it a **pure fold over the
rule list reading upstream facts**; that's the constraint that keeps it provable.

**Static analysis / validation surfaces** (offline, not on the decision hot path):

- **schema validator** (`src/schema.rs`): typed context records, including
  **nested** records, validated against a declared schema before evaluation;
- **dead-rule / contradiction analysis** (`src/analysis.rs`): flags rules that
  can never fire and mutually contradictory rules;
- **z3 SMT** (`src/smt.rs`): equivalence / property analysis, validated vs an
  **independent oracle** (~6000 conditions).

---

## 6. Non-functional requirements

- **Latency:** ~1.2 µs/decision at 10k entities in-process (`BENCHMARKS.md`).
  Over the sidecar add one local hop. AFC detectors (Presidio/Llama Guard) are the
  real cost; run them async / fast-path calls that don't need them.
- **Availability / fail-closed:** a PDP outage must degrade to *deny* rather than allow.
  Plan for it (timeouts, circuit-breaker → deny). Chaos/fault-injection tests are
  in `TEST_PLAN.md §4`.
- **Auditability:** persist `rule_trace`/`reason`/`errors` per decision; the
  emission path retains per-step history.
- **Security boundary:** the PDP trusts the PEP to deliver messages and apply
  verdicts; the PEP trusts the PDP's decision. Identity/transport are the PEP's.

---

## 7. What's done vs in-flight (so you can plan)

- **Done:** ESP engine (+ proven), Emission (+ proven), PAM (+ proven), taint
  (module + tests + proven), MCP contract (PDP), sidecar, **live FastMCP PEP**,
  **agentgateway bit-to-bit interop (verified live)**, **SSE/streaming
  enforcement (shipped)**, **fault-injection (8/8) + chaos (12/12)**, **live
  safety-detector eval (Llama Guard smoke done)**, schema validator + dead-rule /
  contradiction analysis, z3 SMT (validated vs an independent oracle,
  ~6000 conditions), Presidio eval.
- **In-flight / planned:** sidecar hardening (auth/TLS). See
  [`BACKLOG.md`](../../BACKLOG.md) and [`TEST_PLAN.md`](../../TEST_PLAN.md).

---

## 8. Integration checklist (proxy team)

- [ ] Map MCP `tools/call` → `/authorize_tool_call`; block on non-Allow.
- [ ] Map tool result → `/filter_tool_result`; apply emit/redact/drop.
- [ ] Pass the authenticated identity (uid + attrs) on every call.
- [ ] Fail closed on PDP timeout/error.
- [ ] Don't forward `drop`/`buffer`/`require_human` results.
- [ ] Add to the cross-proxy differential (verdicts must match the engine).
- [ ] Maintain one taint session per agent session; merge `sink_facts` into args.
