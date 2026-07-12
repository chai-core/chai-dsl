# agentgateway integration: extAuthz → Chai PDP

Goal: **bit-to-bit interoperability**, so a tool call routed through agentgateway
produces the same allow/deny verdict as our engine and as FastMCP.

## How agentgateway authorizes MCP (researched)

agentgateway has **two** authorization mechanisms; only one supports delegating
to our PDP:

| Mechanism | What | Fits us? |
|---|---|---|
| `mcpAuthorization` | built-in **CEL** rules over `mcp.tool.name`, `mcp.tool.target`, `jwt.*` | ❌ no tool **arguments**, no external delegation, so it can't reproduce arg-level policy |
| `extAuthz` (http/grpc) | call an **external** authz service; `2xx` = allow, else deny; **`includeRequestBody`** forwards the JSON-RPC body | ✅ this is the delegation path |

So we use **HTTP `extAuthz` with `includeRequestBody`**: agentgateway forwards the
intercepted MCP `tools/call` (including its JSON-RPC body) to our sidecar, which
parses it (`mcp_contract::decide_tools_call`) and returns `200`/`403`.

Sources:
- [MCP authorization](https://agentgateway.dev/docs/standalone/main/mcp/mcp-authz/)
- [External authorization](https://agentgateway.dev/docs/standalone/main/configuration/security/external-authz/)

## The wiring

1. **Sidecar `/extauthz`** (`src/server.rs`) receives the forwarded request,
   reads identity from `x-chai-subject-uid` / `x-chai-subject-attrs` headers,
   decides, returns `200` (allow) or `403` (deny). Fail-closed. Tested
   (`extauthz_maps_decision_to_2xx_or_403`).
2. **agentgateway config** (`extauthz.yaml`, validated) attaches `extAuthz` to the
   route, pointing at the sidecar with `includeRequestBody`:

```yaml
binds:
- port: 3000
  listeners:
  - routes:
    - policies:
        extAuthz:
          host: host.docker.internal:8731
          protocol:
            http:
              path: '"/extauthz"'
          includeRequestBody:
            maxRequestBytes: 8192
            allowPartialMessage: true
      backends:
      - mcp:
          targets: [ ... a real MCP server ... ]
```

## Status

- ✅ Docker daemon up; agentgateway 1.3.1 pulled; config validates.
- ✅ Sidecar `/extauthz` endpoint built + tested (verdict ↔ engine decision).
- ✅ `extAuthz`→sidecar config validates.
- ✅ **Live bit-to-bit differential**, verified 2026-07-05. Real `mcp_server.py`
  (FastMCP streamable-HTTP, :9000) behind agentgateway 1.3.1 (Docker, :3000, this
  `live.yaml`), `extAuthz` → sidecar `/extauthz` (:8731, `policy.chai`). `read`
  permitted → 200, `write` denied → 403 (`live_test.py`, 2/2), byte-identical to
  the direct PDP (`/extauthz` read→200 / write→403) and to FastMCP.

## Honest scope

- **Call authorization** is the bit-to-bit target and is viable via `extAuthz`.
- **Result governance** (scrubbing returned data) is **not** covered by `extAuthz`
  (it authorizes the *request*, it can't redact the *response*). That remains a
  FastMCP-path capability; agentgateway response-transformation is a separate,
  unverified avenue.
- `extAuthz` is HTTP-request-level. It maps cleanly when each `tools/call` is an
  HTTP POST; SSE multiplexing needs live confirmation.
