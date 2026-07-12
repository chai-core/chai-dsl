# Chai User Guide

This guide is for someone who wants to **use** Chai: embed it, deploy it, or
put it in front of an agent / MCP system. It is example-driven: every section has
runnable code or commands.

> **Prefer to learn by doing?** Take **[A Tour of Chai](../integrations/playground/tour.html)**,
> a Go-tour-style interactive walkthrough (serve `integrations/playground/`,
> open `tour.html`). Every lesson has live, editable examples that run the real
> engine inline (compiled to WASM) and load straight into the playground/REPL.
> This page is the in-depth reference; the tour is the fast, hands-on path.

## The problem Chai governs

An agent that answers questions and calls tools can get three things wrong:

1. It can **leak a secret or PII** in its output.
2. It can **obey an instruction injected through untrusted data** (a poisoned
   document, a hostile ticket, a malicious issue body).
3. It can **take an action it is not authorized to take** (call a tool, spend
   money, touch a resource it should not).

Chai splits the work of catching these into two planes:

- an **evidence plane** runs detectors (PII, safety, taint) over the agent's
  output and reports typed facts,
- a **decision plane** reads those facts and decides what happens: emit, buffer,
  redact, drop, or halt.

The two planes are kept separate on purpose. The decision plane is small and
mechanically proven in Lean; the evidence plane is heuristic and tested. When
anything fails, a detector timing out or crashing, a condition erroring, no rule
matching, the answer is **deny**. A failure never leaks. This is the fail-closed
invariant, and every surface in the toolkit holds it.

## Aria, the running example

This guide teaches through one story, threaded across every page. **Aria** is a
customer-support agent. She answers customer questions from internal docs and can
call tools like `lookup_account` and `issue_refund`. The customer's ticket text
is **untrusted**.

One policy, [`samples/aria.chai`](../samples/aria.chai), covers all three failure
modes at once:

```
@id("untrusted-agent") forbid        when subject.trust_tier < 2
@id("refund-cap")      forbid        when action == "issue_refund" and args.amount > 100
@id("injected")        forbid        when tooltrace.tainted_sink == true
@id("secret")          deny          when dlp_facts.secrets_found == true
@id("harm")            require_human when safety_facts.harm > 0.6
@id("pii")             redact        when dlp_facts.pii_confidence > 0.4
@id("clean")           permit        when dlp_facts.pii_confidence <= 0.4
```

Read the rules against the three failure modes:

- **Output governance** (leaking): `secret`, `pii`, `clean` read facts about the
  content Aria is about to emit.
- **Authorization** (unauthorized action): `untrusted-agent` and `refund-cap`
  gate who may act and how much they may spend.
- **Dataflow / taint** (injected instruction): `injected` denies any action once
  the request has been tainted by untrusted ticket text.
- **Human review**: `harm` halts for a person when the safety signal is high.

Because these decisions run on a streaming prefix and default to deny, the same
policy also gives you streaming enforcement and fail-closed behavior for free.
[Getting started](01-getting-started.md) runs this exact policy and watches it
produce Allow, then Redact, then Deny.

## What is this: a library or a tool?

**Both: a library first, with tools wrapped around it.**

- The core is a Rust crate, `chai_dsl`: a Cedar-shaped **policy language** plus a
  **verified decision + streaming-enforcement engine**, an **alignment-fact layer**
  (AFC), and **dataflow/taint** tracking.
- On top of it ship runnable **tools**: an HTTP **sidecar** (a Policy Decision
  Point you call from any language) and **MCP proxy integrations** (FastMCP and
  agentgateway both verified live, bit-to-bit identical verdicts).

The mental model is Cedar: Cedar is a library/language, *Amazon Verified
Permissions* is the product. Chai is the same shape, one layer up, governing
**what an agent may do and emit**, beyond static authorization.

Ways to consume it (pick based on your stack):

| You want to… | Use | Latency | Language |
|---|---|---|---|
| embed decisions in a Rust app | the `chai_dsl` crate | lowest (in-process) | Rust |
| embed decisions via FFI | the **native C ABI** (`--features capi`) | lowest (in-process) | C, C++, Go, Python |
| call decisions from any language | the **sidecar** (HTTP) + five **client SDKs** (Python, TypeScript, Go, C, C++) | one local hop | any |
| enforce policy on MCP traffic | a **proxy integration** (PEP→PDP; FastMCP or agentgateway) | one local hop | any (proxy speaks MCP) |
| gate at an Envoy/proxy authz hook | **ext-authz** HTTP + gRPC (`--features grpc`) | one local hop | any |
| scrub HTTP bodies inline | **ICAP** REQMOD + RESPMOD (`--features icap`) | one local hop | any |
| try policies with no backend | the **WASM playground** (engine compiled to WASM) | in-browser | n/a |

For authoring `.chai` files, editor tooling in
[`integrations/editors/`](../integrations/editors/) provides syntax highlighting: a
VS Code extension (TextMate grammar), a Vim syntax file, and a highlight.js
definition, all sharing one token model. See [Deployment](03-deployment.md) for the
in-process C ABI and the client SDKs in full.

## The hero use cases

Each has its own detailed, example-driven page under [`use-cases/`](use-cases/):

1. **[RAG Q&A / summarizer governance](use-cases/rag-qna-governance.md)**: the
   common case. Retrieval access control (only answer from docs this user may see) +
   PII/secret masking on the answer + injection defense, with runnable LangChain and
   LlamaIndex examples.
2. **[Agent-emission governance](use-cases/agent-emission-governance.md)**: control
   what an LLM streams out (redact PII, block secrets, defer/halt for human
   review), fail-closed, on the token stream.
3. **[MCP enforcement point](use-cases/mcp-enforcement-point.md)**: authorize tool
   *calls* and govern tool *results* (the differentiator: scrub returned data
   before the model sees it). You are the PDP a proxy calls.
4. **[Dataflow / exfiltration prevention](use-cases/dataflow-exfiltration.md)**:
   stop untrusted tool output from reaching a sensitive sink (prompt-injection
   containment) via taint tracking.
5. **[Cedar-style authorization](use-cases/cedar-style-authorization.md)**: plain
   RBAC/ABAC/ReBAC for any app; differential-tested against real Cedar.
6. **[Policy analysis](use-cases/policy-analysis.md)**: "did this refactor change
   any decision?" equivalence + reachability (z3) and dead-rule detection, for
   authors and CI.

## Read next

- **[Getting started](01-getting-started.md)**: install, build, your first policy
  and decision, run the test suite.
- **[Policy language](02-policy-language.md)**: the DSL in depth, with many
  examples (RBAC/ABAC/ReBAC, both resolution strategies, PAM guards).
- **[Deployment](03-deployment.md)**: embed as a library, run the sidecar, wire it
  behind FastMCP / agentgateway.

## What it is *not* (honest scoping)

- **Not an identity provider**: it *consumes* agent identity (OAuth/JWT scopes),
  it does not issue it.
- **Not a full MCP gateway**: it doesn't terminate transports; the proxy does.
  We are the decision point the proxy calls.
- **Not a detector**: it doesn't classify PII/safety itself; it *wraps* real
  detectors (Microsoft Presidio for PII, Llama Guard for safety, both verified
  live) behind a stable trait.

## Deeper references

| Doc | What |
|---|---|
| [`BENCHMARKS.md`](../BENCHMARKS.md) | measured performance + methodology |
| [`DETECTOR_EVAL.md`](../DETECTOR_EVAL.md) | live detector accuracy (real Presidio run) |
| [`TEST_PLAN.md`](../TEST_PLAN.md) | the functional test methodology |
| [`formal/README.md`](../formal/README.md) | the Lean proofs (what's mechanized) |
| [`BACKLOG.md`](../BACKLOG.md) | what's done, blocked, and parked |
