"""Govern a LlamaIndex RAG query with Chai, without changing the index.

Same two boundaries as the LangChain example, one policy
(`../langchain/rag.chai`), enforced through the Chai sidecar:

  1. Retrieval access control -> a NodePostprocessor calling chai.authorize(...)
  2. Answer emission control   -> chai.govern(...) over the streamed response

Fail-closed throughout.

Run:
  CHAI_POLICY_FILE=integrations/langchain/rag.chai \
    cargo run -p chai_dsl --features server --example sidecar   # serves :8731
  # needs: pip install llama-index httpx ; OPENAI_API_KEY
  python integrations/llamaindex/rag_governed.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
from chai_client import ChaiClient  # noqa: E402

chai = ChaiClient("http://127.0.0.1:8731")

USER = "User::alice"
VIEWABLE = ["doc:handbook", "doc:pricing"]


class ChaiAccessControl:
    """A LlamaIndex-style node postprocessor: keep only nodes the user may see.

    Wire it as `query_engine = index.as_query_engine(node_postprocessors=[ChaiAccessControl()])`.
    Each node's doc id is expected in `node.metadata["doc"]`."""

    def postprocess_nodes(self, nodes, query_bundle=None):
        kept = []
        for n in nodes:
            doc = n.node.metadata.get("doc", "")
            decision = chai.authorize(
                subject_uid=USER,
                tool="retrieve",
                args={"doc": doc},
                subject_attrs={"viewable": VIEWABLE},
            )
            if decision.get("effect") == "Allow":
                kept.append(n)
            else:
                print(f"[chai] retrieval denied: {doc}")
        return kept


def govern_answer(chunk: str) -> str | None:
    action, content = chai.govern(subject_uid=USER, tool="answer", result=chunk)
    if action in ("emit", "redact"):
        return content
    print(f"[chai] answer chunk withheld: {action}")
    return None


def main() -> None:
    from llama_index.core import Document, VectorStoreIndex

    docs = [
        Document(text="The Pro plan is $49/mo.", metadata={"doc": "doc:pricing"}),
        Document(text="Bob's salary is $180,000 and SSN 123-45-6789.", metadata={"doc": "doc:salaries"}),
        Document(text="Reach support at help@example.com.", metadata={"doc": "doc:handbook"}),
    ]
    index = VectorStoreIndex.from_documents(docs)
    engine = index.as_query_engine(
        streaming=True,
        node_postprocessors=[ChaiAccessControl()],  # doc:salaries is screened out
    )

    resp = engine.query("What does support cost, and how do I reach them?")
    for chunk in resp.response_gen:
        piece = govern_answer(chunk)
        if piece:
            print(piece, end="", flush=True)
    print()


if __name__ == "__main__":
    main()
