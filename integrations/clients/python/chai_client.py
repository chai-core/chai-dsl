"""Chai PDP client for Python: call the sidecar from any Python service.

    from chai_client import ChaiClient
    chai = ChaiClient("http://127.0.0.1:8731")            # or with token=...
    if not chai.allowed(subject_uid="Agent::a1",
                        subject_attrs={"trust_tier": 4}, tool="db.write"):
        raise PermissionError("policy denied")

Every call is FAIL-CLOSED: any error (PDP down, timeout, bad response) returns a
Deny / drop, never an allow.
"""
from __future__ import annotations

import httpx


class ChaiClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8731", token: str | None = None, timeout: float = 5.0):
        self.base = base_url.rstrip("/")
        self.headers = {"authorization": f"Bearer {token}"} if token else {}
        self.timeout = timeout

    def authorize(self, *, subject_uid: str, tool: str, subject_attrs: dict | None = None,
                  args: dict | None = None, resource: str | None = None) -> dict:
        """Authorize a tool call. Returns the decision dict
        {effect, reason, rule_trace, errors}. Fail-closed on error."""
        payload = {"subject_uid": subject_uid, "subject_attrs": subject_attrs or {},
                   "tool": tool, "args": args or {}}
        if resource:
            payload["resource"] = resource
        return self._post("/authorize_tool_call", payload,
                          {"effect": "Deny", "reason": "PDP error (fail-closed)", "rule_trace": [], "errors": []})

    def govern_result(self, *, subject_uid: str, tool: str, result: str,
                      subject_attrs: dict | None = None) -> dict:
        """Govern a tool result. Returns {action, released, effect, reason};
        action ∈ emit|redact|drop|buffer|require_human. Fail-closed (drop)."""
        payload = {"subject_uid": subject_uid, "subject_attrs": subject_attrs or {},
                   "tool": tool, "result": result}
        return self._post("/filter_tool_result", payload,
                          {"action": "drop", "released": None, "effect": "Deny", "reason": "PDP error (fail-closed)"})

    def allowed(self, **kw) -> bool:
        return self.authorize(**kw).get("effect") == "Allow"

    def govern(self, **kw) -> tuple[str, str | None]:
        """Convenience over govern_result: returns (action, content) where
        `content` is the (possibly ADAPTED/redacted) text to forward for
        emit/redact, or None when withheld (drop/buffer/require_human)."""
        r = self.govern_result(**kw)
        action = r.get("action", "drop")
        content = r.get("released") if action in ("emit", "redact") else None
        return action, content

    def _post(self, path: str, payload: dict, deny: dict) -> dict:
        try:
            r = httpx.post(f"{self.base}{path}", json=payload, headers=self.headers, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception:
            return deny  # fail-closed
