"""FastMCP enforcement middleware: the PEP→PDP glue.

FastMCP is the proxy/PEP (it sits in the MCP data path); this middleware calls
our Rust sidecar (the PDP) on every tool call and tool result, and *enforces* the
verdict: it blocks a denied call, drops/blocks a denied result, or substitutes
redacted content. We do not decide here; we ask the sidecar and apply.

Wire it with:  server.add_middleware(ChaiEnforcement(sidecar_url, identity))
"""
from __future__ import annotations

import httpx
import mcp.types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware
from fastmcp.tools.tool import ToolResult


class ChaiEnforcement(Middleware):
    def __init__(self, sidecar_url: str, identity: dict, timeout: float = 5.0, token: str | None = None):
        self.sidecar = sidecar_url.rstrip("/")
        self.identity = identity  # {"uid": ..., "attrs": {...}}
        self.timeout = timeout
        self.headers = {"authorization": f"Bearer {token}"} if token else {}

    def _id(self) -> dict:
        return {"subject_uid": self.identity["uid"], "subject_attrs": self.identity.get("attrs", {})}

    async def _ask(self, http, path: str, payload: dict, key: str):
        """Call the PDP and return its parsed verdict: FAIL-CLOSED.

        ANY failure to obtain a well-formed verdict (PDP unreachable, timeout,
        non-2xx, non-JSON, or a body missing the expected field) raises, which
        blocks the operation. The trust boundary requires the PEP to deny (never
        fail open) when it cannot get a decision.
        """
        try:
            resp = await http.post(f"{self.sidecar}{path}", json=payload, headers=self.headers)
            resp.raise_for_status()
            body = resp.json()
            verdict = body[key]  # KeyError if the shape is wrong -> fail closed
        except Exception as e:
            raise ToolError(f"PDP unavailable, failing closed ({type(e).__name__})") from e
        return body, verdict

    async def on_call_tool(self, context, call_next):
        name = context.message.name
        args = context.message.arguments or {}

        async with httpx.AsyncClient(timeout=self.timeout) as http:
            # 1) authorize the call (PEP -> PDP), fail-closed
            _, effect = await self._ask(
                http, "/authorize_tool_call", {**self._id(), "tool": name, "args": args}, "effect"
            )
            if effect != "Allow":
                raise ToolError(f"policy denied call to {name!r}: {effect}")

            # 2) run the tool
            result = await call_next(context)

            # 3) govern the returned data (PEP -> PDP), the differentiator, fail-closed
            text = "".join(c.text for c in (result.content or []) if getattr(c, "type", None) == "text")
            gov, action = await self._ask(
                http, "/filter_tool_result", {**self._id(), "tool": name, "result": text}, "action"
            )


        if action in ("drop", "buffer", "require_human"):
            raise ToolError(f"policy blocked result of {name!r} ({action}): {gov.get('reason', '')}")
        if action == "emit":
            return result  # released verbatim; preserve the original result intact
        if action == "redact":
            return ToolResult(content=[mt.TextContent(type="text", text=gov.get("released") or "")])
        return result
