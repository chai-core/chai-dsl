"""Fault-injection / chaos test for the trust boundary (TEST_PLAN.md §4-5).

The end-to-end guarantee assumes the PEP applies the PDP's verdict. This suite
breaks the PEP→PDP link in every way we can and asserts the PEP FAILS CLOSED
(the tool call/result is blocked, never allowed) when it cannot obtain a
well-formed verdict.

Uses a controllable MOCK PDP (so we can make it misbehave on demand) plus an
unreachable address. No real sidecar needed.
"""
import asyncio
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from chai_middleware import ChaiEnforcement
from fastmcp import Client, FastMCP

# Mutable behavior the mock PDP follows; the test flips it per case.
MODE = {"authorize": "allow", "govern": "emit"}


class MockPDP(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, raw=False):
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body if raw else json.dumps(body).encode())

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        self.rfile.read(length)
        which = "authorize" if "authorize" in self.path else "govern"
        behavior = MODE[which]
        try:
            if behavior == "hang":
                time.sleep(3)  # exceed the client's short timeout
            if behavior == "500":
                return self._send(500, b"internal error", raw=True)
            if behavior == "garbage":
                return self._send(200, b"<html>not json</html>", raw=True)
            if behavior == "wrongshape":
                return self._send(200, {"unexpected": "field"})

            if which == "authorize":
                effect = "Allow" if behavior == "allow" else "Deny"
                return self._send(200, {"effect": effect, "reason": "mock", "rule_trace": [], "errors": []})
            else:
                self._send(200, {"action": behavior, "released": "ok", "effect": "Allow", "reason": "mock"})
        except (BrokenPipeError, ConnectionResetError):
            pass  # client gave up (e.g. timeout case); expected, not a failure


def start_mock():
    srv = HTTPServer(("127.0.0.1", 8799), MockPDP)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


async def call(sidecar, kind="emit", timeout=5.0):
    server = FastMCP("fault-demo")

    @server.tool
    def do(kind: str):
        return "payload"

    server.add_middleware(ChaiEnforcement(sidecar, {"uid": "Agent::a1", "attrs": {"trust_tier": 5}}, timeout=timeout))
    async with Client(server) as client:
        res = await client.call_tool("do", {"kind": kind})
        return "".join(c.text for c in res.content if getattr(c, "type", None) == "text")


async def main():
    start_mock()
    GOOD = "http://127.0.0.1:8799"
    DEAD = "http://127.0.0.1:9 1"  # unreachable (nothing listening on 9001-ish)
    DEAD = "http://127.0.0.1:9001"
    results = []

    async def expect_blocked(name, sidecar, *, mode=None, timeout=5.0):
        if mode:
            MODE.update(mode)
        try:
            await call(sidecar, timeout=timeout)
            results.append((name, False, "NOT blocked (failed OPEN!)"))
        except Exception as e:
            results.append((name, True, f"blocked: {type(e).__name__}"))

    async def expect_allowed(name, sidecar, *, mode=None):
        if mode:
            MODE.update(mode)
        try:
            out = await call(sidecar)
            results.append((name, out == "payload", f"-> {out!r}"))
        except Exception as e:
            results.append((name, False, f"unexpectedly blocked: {e}"))

    # control: a healthy PDP allows
    await expect_allowed("control: healthy PDP allows", GOOD, mode={"authorize": "allow", "govern": "emit"})

    # fault injection: each must FAIL CLOSED (block)
    await expect_blocked("explicit deny",              GOOD, mode={"authorize": "deny", "govern": "emit"})
    await expect_blocked("PDP returns 500",            GOOD, mode={"authorize": "500"})
    await expect_blocked("PDP returns garbage (non-JSON)", GOOD, mode={"authorize": "garbage"})
    await expect_blocked("PDP returns wrong shape",    GOOD, mode={"authorize": "wrongshape"})
    await expect_blocked("PDP unreachable",            DEAD, mode={"authorize": "allow", "govern": "emit"})
    await expect_blocked("PDP timeout (hang)",         GOOD, mode={"authorize": "hang"}, timeout=0.5)
    # chaos: authorize succeeds, but the PDP dies before result governance
    await expect_blocked("chaos: PDP fails mid-call (govern 500)", GOOD,
                         mode={"authorize": "allow", "govern": "500"})

    print()
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}  {detail}")
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    asyncio.run(main())
