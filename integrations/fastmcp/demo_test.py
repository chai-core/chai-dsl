"""End-to-end live test: FastMCP (PEP) → Chai sidecar (PDP) → enforced verdict.

Assumes the sidecar is running on 127.0.0.1:8731 with the demo policy:
    cargo run --features server --example sidecar

Runs a FastMCP server (in-memory client transport, so MCP itself isn't flaky)
with a tool that can return clean / PII / secret data, and asserts the middleware
enforces the PDP's verdict end to end.
"""
import asyncio
import sys

from chai_middleware import ChaiEnforcement
from fastmcp import Client, FastMCP

SIDECAR = "http://127.0.0.1:8731"

PAYLOADS = {
    "clean": "row count: 42",
    "pii": "customer ssn 123-45-6789 email bob@corp.com on file",
    "secret": "password: hunter2",
}


def make_server(trust_tier: int) -> FastMCP:
    server = FastMCP("demo")

    # No typed return ⇒ no output schema, so a policy-redacted result isn't
    # rejected by FastMCP's structured-output validation.
    @server.tool
    def read_record(kind: str):
        return PAYLOADS[kind]

    server.add_middleware(ChaiEnforcement(SIDECAR, {"uid": "Agent::a1", "attrs": {"trust_tier": trust_tier}}))
    return server


async def call(server, kind):
    async with Client(server) as client:
        res = await client.call_tool("read_record", {"kind": kind})
        return "".join(c.text for c in res.content if getattr(c, "type", None) == "text")


async def main():
    results = []

    def check(name, cond, detail=""):
        results.append((name, cond, detail))
        print(f"  [{'PASS' if cond else 'FAIL'}] {name} {detail}")

    # High-trust agent: calls are authorized; results are governed.
    hi = make_server(5)

    out = await call(hi, "clean")
    check("clean result emitted verbatim", out == PAYLOADS["clean"], f"-> {out!r}")

    out = await call(hi, "pii")
    masked = "123-45-6789" not in out and "bob@corp.com" not in out
    check("PII result span-masked (PII gone, rest kept)", out != PAYLOADS["pii"] and masked, f"-> {out!r}")

    try:
        await call(hi, "secret")
        check("secret result blocked", False, "-> NOT blocked")
    except Exception as e:
        check("secret result blocked", True, f"-> blocked: {type(e).__name__}")

    # Low-trust agent: the call itself is denied before the tool ever runs.
    lo = make_server(1)
    try:
        await call(lo, "clean")
        check("low-trust call denied", False, "-> NOT denied")
    except Exception as e:
        check("low-trust call denied", True, f"-> denied: {type(e).__name__}")

    passed = sum(1 for _, c, _ in results if c)
    print(f"\n{passed}/{len(results)} checks passed")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    asyncio.run(main())
