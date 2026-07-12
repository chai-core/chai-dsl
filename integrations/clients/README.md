# Chai client SDKs

Thin, fail-closed clients that call the Chai **sidecar** (the Policy Decision
Point) over HTTP, from four languages. Every client shares the same two calls:

- `authorize` / `allowed`: gate a tool call (returns the decision, or a bool).
- `govern_result` / `govern`: govern a tool result (emit / redact / drop /
  buffer / require_human), returning the possibly-redacted content to forward.

Every call is **fail-closed**: any error (PDP unreachable, timeout, non-2xx,
unparseable response) returns a deny / drop, never an allow.

## Run the samples

Start the sidecar first (it serves the demo policy, `trust_tier >= 3` may act):

```sh
cargo run --features server --example sidecar     # http://127.0.0.1:8731
```

Then run any client sample:

| Language | Files | Run |
|---|---|---|
| Python | [`python/chai_client.py`](python/chai_client.py) | `cd python && PYTHONPATH=. python test_client.py` |
| TypeScript | [`typescript/chai-client.ts`](typescript/chai-client.ts) | `node typescript/test.ts` (Node 22+ strips types) |
| Go | [`go/chai_client.go`](go/chai_client.go) | `cd go && go run ./example` |
| C | [`c/chai_client.h`](c/chai_client.h), [`c/chai_client.c`](c/chai_client.c) | `cd c && make run` |
| C++ | [`cpp/chai_client.hpp`](cpp/chai_client.hpp) (header-only) | `cd cpp && make run` |

The C and C++ clients need **libcurl** (`curl-config` on PATH; `brew install curl`
or your distro's `libcurl-dev`). All four print the same demo:

```
trust 4, db.write -> ALLOW
trust 1, db.write -> DENY
secret result     -> drop
clean result      -> emit, content="row count 12"
dead PDP          -> DENY   (fail-closed)
```

## Notes

- The Python, TypeScript, and Go clients expose a `govern()` / `Govern()`
  convenience that returns the adapted (redacted) content for emit/redact and
  `None` / `null` / `nil` when the result is withheld. The C and C++ clients write
  the released content into a caller buffer / `ResultDecision.released`.
- Python, TypeScript, and Go take native maps/objects for `subject_attrs` and
  `args`. The C and C++ clients take them as raw JSON strings (e.g.
  `{"trust_tier":4}`) to stay dependency-free beyond libcurl; string fields are
  JSON-escaped for you.
- A bearer token (the sidecar's `CHAI_SIDECAR_TOKEN`) is supported by every
  client constructor.
