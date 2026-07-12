"""Full chaos run: the REAL sidecar process, killed and frozen mid-session.

The `fault_test.py` sibling breaks a *mock* PDP link every way in one process.
This is the longer, systemic version: it starts the real Rust sidecar as a
subprocess and, over a run of many calls, subjects it to

  1. healthy         : calls succeed (baseline),
  2. partition/hang  : SIGSTOP freezes the PDP; calls must TIME OUT fail-closed;
                       SIGCONT thaws it and the session recovers,
  3. crash           : the PDP process is killed; calls must fail closed,
  4. recovery        : a fresh PDP is started; calls succeed again.

Invariant asserted throughout: the FastMCP PEP NEVER fails open. Whenever it
cannot obtain a well-formed verdict it blocks (ToolError). Run:

  ../../eval/.venv/bin/python chaos_test.py
"""
from __future__ import annotations

import asyncio
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from chai_middleware import ChaiEnforcement
from fastmcp import Client, FastMCP

REPO = Path(__file__).resolve().parents[2]
PORT = 8791
URL = f"http://127.0.0.1:{PORT}"
IDENTITY = {"uid": "Agent::a1", "attrs": {"trust_tier": 5}}  # demo policy -> allow
BIN = REPO / "target" / "debug" / "examples" / "sidecar"


def _port_open(port: int) -> bool:
    s = socket.socket()
    s.settimeout(0.3)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def wait_port(up: bool, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_open(PORT) == up:
            return True
        time.sleep(0.15)
    return False


def start_sidecar() -> subprocess.Popen:
    env = dict(os.environ, CHAI_ADDR=f"127.0.0.1:{PORT}")
    p = subprocess.Popen(
        [str(BIN)], cwd=str(REPO), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if not wait_port(up=True):
        raise RuntimeError("sidecar did not come up")
    return p


async def call(timeout: float = 3.0) -> str:
    """One tool call through a FastMCP PEP with the enforcement middleware.
    Returns the released text, or raises ToolError if the PEP fails closed."""
    server = FastMCP("chaos")

    @server.tool
    def do() -> str:
        return "payload"

    server.add_middleware(ChaiEnforcement(URL, IDENTITY, timeout=timeout))
    async with Client(server) as c:
        r = await c.call_tool("do", {})
        return "".join(b.text for b in r.content if getattr(b, "type", None) == "text")


async def expect_ok(label: str, results: list) -> None:
    try:
        out = await call()
        ok = out == "payload"
        results.append((label, ok, "" if ok else f"unexpected output {out!r}"))
    except Exception as e:
        results.append((label, False, f"failed open/blocked: {type(e).__name__}: {e}"))


async def expect_blocked(label: str, results: list, *, timeout: float = 2.0) -> None:
    try:
        await call(timeout=timeout)
        results.append((label, False, "NOT blocked, failed OPEN"))
    except Exception as e:
        # any ToolError/exception is the PEP failing closed, which is correct
        results.append((label, True, f"blocked: {type(e).__name__}"))


async def main() -> int:
    results: list = []
    proc = start_sidecar()
    try:
        # 1. healthy baseline (a few calls)
        for i in range(3):
            await expect_ok(f"healthy call {i + 1} allowed", results)

        # 2. partition / hang: freeze the PDP mid-session
        os.kill(proc.pid, signal.SIGSTOP)
        for i in range(3):
            await expect_blocked(f"hang (SIGSTOP) call {i + 1} fails closed", results, timeout=1.0)
        # thaw and recover
        os.kill(proc.pid, signal.SIGCONT)
        wait_port(up=True)
        await expect_ok("recovery after thaw allowed", results)

        # 3. crash: kill the PDP process
        proc.terminate()
        proc.wait(timeout=10)
        wait_port(up=False)
        for i in range(3):
            await expect_blocked(f"crash (killed PDP) call {i + 1} fails closed", results)

        # 4. recovery: bring up a fresh PDP
        proc = start_sidecar()
        for i in range(2):
            await expect_ok(f"recovery call {i + 1} allowed", results)
    finally:
        try:
            os.kill(proc.pid, signal.SIGCONT)  # in case still stopped
        except Exception:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}  {detail}")
    print(f"\n{passed}/{len(results)} checks passed; PEP fail-closed under chaos")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
