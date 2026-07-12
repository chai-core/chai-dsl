# Security Policy

Chai is a security component: a policy engine that governs what an agent may emit,
fail-closed. Please treat vulnerability reports accordingly.

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button (Security tab →
Advisories) so a fix can ship before disclosure. Do not open a public issue for a
security bug. Include a reproduction, the affected feature/commit, and the impact
you observed. We aim to acknowledge within a few days.

## Scope

In scope: any way to make the engine emit content a policy should have blocked,
produce an `Allow` where the semantics require deny/error, bypass fail-closed
handling, or crash the enforcement point into an open state. Also in scope: parser
or wire-surface (HTTP/gRPC/ICAP/C-ABI/WASM) issues that affect a decision.

## Trusted base (out of scope by design)

Some parts are trusted rather than proven, and issues there are limitations, not
engine bugs. These are documented in the README's Limitations and will move into a
dedicated threat model:

- **Detectors.** Detection accuracy belongs to the plugged-in tool (Presidio,
  Llama Guard, Lakera). A missed entity is a detector recall limitation. The
  bundled heuristics are illustrative, not classifiers.
- **Evidence integrity.** Facts derived from adversarial text can be poisoned
  (e.g. prompt injection against an LLM detector). The attested evidence tier is
  the mitigation; signature verification for attested facts is trusted.
- **Transforms.** A redaction/downgrade release is proven *authorized*, but the
  mask's correctness is not proven.
- **Resolver freshness.** An external entity resolver can be stale relative to the
  source of truth.
- **Taint.** Verbatim and common encodings are caught; paraphrase laundering is a
  measured miss.

## Verification status

The deterministic decision core is mechanically proven in Lean (`formal/`) and
differentially tested against Cedar. The Lean-to-Rust correspondence currently
rests on inspection and property tests; continuous differential testing against the
Lean model is planned. See the README's "What's verified (and how)".
