# Deployment

Several ways to run Chai, from tightest-coupled to most-decoupled. Pick by your
stack and latency budget: embed in-process (A, Rust crate or native C ABI), run
the HTTP sidecar (B), front an MCP proxy (C), gate an Envoy/proxy authz hook via
ext-authz (D), scrub HTTP bodies inline via ICAP (E), or try policies in the
browser via the WASM playground (F).

## A. Embed in-process

Lowest latency, no network hop. Two forms of the same engine: the Rust crate for
Rust embedders, and a native C ABI for C, C++, Go, and Python via FFI.

### Rust crate

Link the crate and call the engine directly.

```toml
[dependencies]
chai_dsl = { path = "." }
# optional features:
# chai_dsl = { path = ".", features = ["smt"] }   # z3 policy analysis
```

Load the policy + entities once, then evaluate per request:

```rust
use chai_dsl::{parse_chai, eval_with_store, EntityStore};

let program = parse_chai(&std::fs::read_to_string("policy.chai")?)?;   // load once
let store   = EntityStore::new();                                       // or from_cedar_entities_json

// per request:
let decision = eval_with_store(&program, request_ctx, &store)?;
```

For streaming emission, hold an `EmissionEnforcer` per stream (see
[agent-emission governance](use-cases/agent-emission-governance.md)).

### Native C ABI (C / C++ / Go / Python via FFI)

The same engine as the Rust library, the sidecar, and the WASM build, exposed as a
shared library with a small C ABI. Build it with the `capi` feature:

```sh
cargo build --release --features capi
# -> target/release/libchai_dsl.{dylib,so}
```

The ABI ([`integrations/embed/chai.h`](../integrations/embed/chai.h)) is four C
functions. Everything takes and returns JSON strings, and it is fail-closed:

```c
// Runs a policy. Honors the `mode` directive, so it covers both the default
// Cedar deny-override AND the ACL first_match mode.
char *chai_decide(const char *policy, const char *context_json);

// Runs a PAM guard. guard_json is a JSON array of {"flag":..., "when":...} entries.
char *chai_pam_decide(const char *guard_json, const char *context_json);

void  chai_free_string(char *s);   // free a returned string
const char *chai_version(void);
```

Minimal C use:

```c
#include "chai.h"
char *out = chai_decide("permit when subject.trust_tier >= 2",
                        "{\"subject\":{\"trust_tier\":4}}");
printf("%s\n", out);            // Allow
chai_free_string(out);
```

Samples in [`integrations/embed/`](../integrations/embed/) run all three paradigms
(regular deny-override, ACL first_match, PAM), verified:

- C: `integrations/embed/c/` (`make run`)
- C++: `integrations/embed/cpp/` (`make run`)
- Go (cgo): `integrations/embed/go/` (`go run .`)
- Python (ctypes): `integrations/embed/python/inproc.py`

All print: deny-override trust 4 -> Allow / trust 1 -> Deny; ACL read -> Allow /
write -> Deny; PAM junior $50 -> pass / junior $9999 -> fail.

## B. Run the sidecar (any language, over HTTP)

The PDP as a daemon. Build the runnable example or embed `server::router`/
`serve_blocking` in your own binary.

```sh
# demo policy on 127.0.0.1:8731
cargo run --features server --example sidecar

# your policy, your address
cargo run --features server --example sidecar -- ./policy.chai 0.0.0.0:8731
```

### API

```
POST /authorize_tool_call
  body  {subject_uid, subject_attrs, tool, args, resource?}
  reply {effect, reason, rule_trace, errors}

POST /filter_tool_result
  body  {subject_uid, subject_attrs, tool, result}
  reply {action, released, effect, reason}

POST /filter_tool_result_sse
  body  a streamed SSE tool-result stream
  reply governed SSE: released prefixes as `data:` events, withheld chunks as SSE
        comments, unapproved buffer dropped at end-of-stream (fail-closed)
```

Both are **fail-closed**: an internal error returns deny/drop. Example:

```sh
curl -s -X POST http://127.0.0.1:8731/filter_tool_result \
  -H 'content-type: application/json' \
  -d '{"subject_uid":"Agent::a1","subject_attrs":{"trust_tier":5},
       "tool":"vault.read","result":"password: hunter2"}'
# {"action":"drop","released":null,"effect":"Deny",...}
```

Embed it in your own service:

```rust
use chai_dsl::server::{router, AppState, serve_blocking};
use chai_dsl::{parse_chai, Afc, EntityStore};
use std::sync::Arc;

let state = Arc::new(AppState {
    program: parse_chai(&policy_src)?,
    store: EntityStore::new(),
    afc: Afc::with_default_detectors(),
});
serve_blocking("0.0.0.0:8731", state);            // or mount router(state) in your axum app
```

### Client SDKs

Five client SDKs in [`integrations/clients/`](../integrations/clients/) wrap the
sidecar HTTP API. All are fail-closed and share the same two calls
(`authorize`/`allowed` and `govern_result`/`govern`); the Python, TypeScript, and
Go clients expose a `govern()` helper that returns the adapted (redacted) content.
Verified live against the sidecar: Python 5/5, TypeScript 4/4, Go/C/C++ run
correct.

- Python: `python/chai_client.py`
- TypeScript: `typescript/chai-client.ts` (Node 22+ strips types)
- Go: `go/chai_client.go` (`go run ./example`)
- C: `c/chai_client.{h,c}` (libcurl; `make run`)
- C++: `cpp/chai_client.hpp` (header-only, libcurl; `make run`)

> **Hardening (not done):** the sidecar has no auth/TLS and isn't load-tested. Put
> it behind your own mTLS/network policy for production. See `BACKLOG.md`.

## C. MCP enforcement point (PEP → PDP)

A proxy speaks MCP; its middleware/hook calls your sidecar per tool call/result
and applies the verdict. You don't build the proxy; you supply the decision.

### FastMCP (Python): working today

Complete integration in [`integrations/fastmcp/`](../integrations/fastmcp/):
`chai_middleware.py` (the PEP glue) + `demo_test.py` (a live end-to-end test).

```sh
# 1. PDP
cargo run --features server --example sidecar
# 2. PEP + demo
cd integrations/fastmcp
PYTHONPATH=. ../../eval/.venv/bin/python demo_test.py
```

Wire it into your own FastMCP server:

```python
from chai_middleware import ChaiEnforcement
server.add_middleware(ChaiEnforcement(
    "http://127.0.0.1:8731",
    {"uid": "Agent::a1", "attrs": {"trust_tier": 5}},
))
```

The middleware authorizes each `tools/call`, runs the result through the sidecar,
and blocks / drops / substitutes-redacted accordingly. (FastMCP gives already-
parsed tool name + args, so the middleware calls the normalized endpoints, no raw
JSON-RPC needed on that path.)

### agentgateway (Rust): verified live

The same sidecar serves agentgateway unchanged (it's the same PDP contract), and
this is now **verified bit-to-bit**: a request routed through agentgateway
produces byte-identical verdicts to the engine and to FastMCP (read → 200 allow,
write → 403 deny), a strict three-way cross-proxy differential, byte-identical to
the direct PDP and to FastMCP.

## D. ext-authz (Envoy / proxy external-authorization hook)

For infra that already speaks Envoy's `ext_authz` contract, Chai exposes the same
PDP as an external-authorization service over **HTTP and gRPC**. Build with the
`grpc` feature:

```sh
cargo test --features grpc      # the ext-authz gRPC surface + its tests
```

The proxy calls the ext-authz endpoint per request; an allow lets the request
through, a deny short-circuits it. Fail-closed, same as the sidecar.

## E. ICAP (inline HTTP body scrubbing)

For scrubbing HTTP request/response bodies inline, Chai speaks **ICAP** with both
**REQMOD** (request modification) and **RESPMOD** (response modification). Build
with the `icap` feature:

```sh
cargo test --features icap      # the ICAP REQMOD/RESPMOD surface + its tests
```

An ICAP-capable proxy hands bodies to Chai, which applies the emission verdict
(pass / redact / block) before the body continues. Fail-closed.

## F. WASM playground (no backend)

The engine compiles to WASM and runs entirely in the browser: the playground in
[`integrations/playground/`](../integrations/playground/) is a static site with no
server. Useful for authoring and sharing policies. Serve it locally:

```sh
cargo build --release --target wasm32-unknown-unknown --features wasm --lib
cp target/wasm32-unknown-unknown/release/chai_dsl.wasm integrations/playground/
python3 -m http.server -d integrations/playground 8788   # index.html REPL, tour.html guide
```

## Choosing

The full set of surfaces, in-process versus out-of-process:

| Surface | In/out of process | For |
|---|---|---|
| Rust crate `chai_dsl` | in-process | Rust embedders, lowest latency |
| Native C ABI (`capi`) | in-process | C, C++, Go, Python via FFI |
| WASM | in-process (browser/Node) | client-side, the playground |
| HTTP sidecar + 5 client SDKs | out of process | any language |
| ext-authz HTTP + gRPC | out of process | Envoy / Istio / agentgateway |
| ICAP REQMOD/RESPMOD | out of process | Squid / DLP proxies |
| MCP PDP (FastMCP, agentgateway) | out of process | MCP tool-call/result governance |

Latency and identity, for the three most common surfaces:

| | A. In-process | B. Sidecar | C. MCP proxy |
|---|---|---|---|
| latency | lowest | one local hop | one local hop |
| language | Rust, or C/C++/Go/Python via the C ABI | any | any (proxy speaks MCP) |
| best for | apps embedding authz/emission | polyglot services | governing MCP agent traffic |
| identity | you provide in context | you provide in body | proxy provides (OAuth/JWT) |

## Operational notes

- **Audit:** every decision carries `rule_trace` + `reason` + `errors`. Log them;
  the runtime also retains per-step decision history in the emission path.
- **Policy reload:** load policy once at startup; for hot-reload, swap the
  `program`/`AppState` behind your own mechanism.
- **Detectors:** the default AFC detectors are heuristics. For production swap in
  Presidio/Llama Guard via `Afc::with_external(...)` (see
  [agent-emission governance](use-cases/agent-emission-governance.md)).
