"""Govern a LangChain RAG chain with Chai, without changing the chain.

Two boundaries, one policy (`rag.chai`), enforced through the Chai sidecar:

  1. Retrieval access control  -> chai.authorize(...)   per retrieved chunk
  2. Answer emission control    -> chai.govern(...)      per streamed chunk

Everything is fail-closed: if the sidecar is slow or down, the client returns a
deny/drop, never an allow.

Run:
  # 1. start the sidecar with this policy
  CHAI_POLICY_FILE=integrations/langchain/rag.chai \
    cargo run -p chai_dsl --features server --example sidecar   # serves :8731
  # 2. run this example (needs: pip install langchain-openai httpx; OPENAI_API_KEY)
  python integrations/langchain/rag_governed.py

This is illustrative wiring; adapt the retriever/LLM to your stack. The Chai calls
are the point, and they are stable.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Reuse the maintained Python client rather than re-implementing the HTTP calls.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
from chai_client import ChaiClient  # noqa: E402

chai = ChaiClient("http://127.0.0.1:8731")

# The asking user and the documents they are allowed to see. In production this
# comes from your auth layer / document ACLs, per request.
USER = "User::alice"
VIEWABLE = ["doc:handbook", "doc:pricing"]


def screen_retrieved(docs: list[dict]) -> list[dict]:
    """Drop any retrieved chunk the asking user is not allowed to see.

    `rag.chai` rule: `permit when args.doc in subject.viewable`. Default-deny means
    an unlisted doc is denied, so it never reaches the model."""
    allowed = []
    for d in docs:
        decision = chai.authorize(
            subject_uid=USER,
            tool="retrieve",
            args={"doc": d["id"]},
            subject_attrs={"viewable": VIEWABLE},
        )
        if decision.get("effect") == "Allow":
            allowed.append(d)
        else:
            print(f"[chai] retrieval denied: {d['id']} ({decision.get('reason')})")
    return allowed


def govern_answer(chunk: str) -> str | None:
    """Filter one streamed answer chunk. Returns the (possibly redacted) text to
    forward, or None to withhold it (drop/halt). `rag.chai` masks PII, denies
    secrets, and (with an injection detector wired) blocks injected content."""
    action, content = chai.govern(subject_uid=USER, tool="answer", result=chunk)
    if action in ("emit", "redact"):
        return content
    print(f"[chai] answer chunk withheld: {action}")
    return None


def main() -> None:
    # --- your retriever (swap for a real vector store) ---
    retrieved = [
        {"id": "doc:pricing", "text": "The Pro plan is $49/mo."},
        {"id": "doc:salaries", "text": "Bob's salary is $180,000 and SSN 123-45-6789."},
        {"id": "doc:handbook", "text": "Reach support at help@example.com."},
    ]
    context_docs = screen_retrieved(retrieved)  # doc:salaries is dropped here
    context = "\n".join(d["text"] for d in context_docs)

    # --- your LLM (swap for your provider) ---
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(model="gpt-4o-mini", streaming=True)
    prompt = f"Answer using only this context:\n{context}\n\nQuestion: What does support cost, and how do I reach them?"

    # Stream the answer through Chai chunk by chunk.
    for token in llm.stream(prompt):
        piece = govern_answer(token.content)
        if piece:
            print(piece, end="", flush=True)
    print()


if __name__ == "__main__":
    main()
