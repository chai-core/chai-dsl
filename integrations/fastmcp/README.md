# FastMCP integration: FastMCP (PEP) → Chai sidecar (PDP)

Demonstrates the architecture: **FastMCP is the proxy/PEP** (in the MCP data
path); **we are the PDP it calls.** `chai_middleware.py` is FastMCP middleware
that, on every tool call and result, asks the Chai sidecar for a verdict and
*enforces* it: blocking a denied call, dropping/blocking a denied result, or
substituting redacted content.

This is the first live proof of the PEP→PDP boundary. It is **proxy-agnostic by
construction**: the middleware only speaks the sidecar's HTTP contract, so the
same PDP serves agentgateway (Rust) next, unchanged.

## Run it

```sh
# 1. Start the PDP sidecar (the verified decision engine) with the demo policy:
cargo run --features server --example sidecar           # -> http://127.0.0.1:8731

# 2. In another shell, run the live end-to-end test (PEP → PDP → enforcement):
cd integrations/fastmcp
PYTHONPATH=. ../../eval/.venv/bin/python demo_test.py
```

The venv is the one from `DETECTOR_EVAL.md` plus `fastmcp` + `httpx`:
`../../eval/.venv/bin/pip install fastmcp httpx`.

## What it verifies (observed, real run)

A high-trust agent and a low-trust agent call one tool that returns clean / PII /
secret data, through FastMCP with the enforcement middleware:

```
[PASS] clean result emitted verbatim            -> 'row count: 42'
[PASS] PII result span-masked (PII gone, rest kept)
       -> 'customer ssn [SSN] email [EMAIL] on file'
[PASS] secret result blocked                    -> blocked: ToolError
[PASS] low-trust call denied                    -> denied: ToolError
4/4 checks passed
```

So end to end, on real MCP machinery: call authorization (low-trust denied before
the tool runs), and result governance (clean passes, PII redacted, secret
dropped), all decided by the Rust PDP, enforced by the FastMCP PEP.

## Resilience: the PEP fails closed

Two harnesses stress the PEP→PDP link, both asserting the enforcement point never
fails open:

```sh
PYTHONPATH=. ../../eval/.venv/bin/python fault_test.py   # mock PDP, broken 7 ways -> 8/8 fail closed
PYTHONPATH=. ../../eval/.venv/bin/python chaos_test.py    # REAL sidecar, killed/frozen mid-session -> 12/12
```

`fault_test.py` breaks the link every way (explicit deny, PDP 500, non-JSON,
wrong-shape verdict, unreachable, timeout, mid-call chaos) and the PEP blocks in
each. `chaos_test.py` starts the real Rust sidecar and, over a run of calls,
freezes it (`SIGSTOP` → timeout fail-closed → `SIGCONT` recovery), kills it
(fail-closed), and restarts it (clean recovery).

## Trust boundary (honest)

We prove/test the *decision*; FastMCP performs the *enforcement*. The end-to-end
guarantee is conditional on FastMCP faithfully (a) invoking the middleware on
every tool call/result and (b) applying the returned verdict, the standard
"trusted PEP" boundary (`formal/README.md`). The middleware itself is the small,
auditable adapter; the verified core is the sidecar it calls.

## Notes

- In-memory `Client(server)` transport is used so MCP transport itself isn't a
  variable; the middleware, the HTTP hop, and the PDP are exactly as in
  production.
- The demo tool declares no typed return, so a policy-*redacted* result isn't
  rejected by FastMCP's structured-output validation. A typed tool would need the
  middleware to also rewrite `structured_content` on redaction.
