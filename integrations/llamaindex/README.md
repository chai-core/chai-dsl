# Chai + LlamaIndex

Govern a LlamaIndex RAG query with Chai without changing the index. Same two
boundaries as the [LangChain example](../langchain), both fail-closed:

- **Retrieval access control**: a node postprocessor (`ChaiAccessControl`) calls
  `chai.authorize` and keeps only the nodes the user may see.
- **Answer emission control**: `chai.govern` over the streamed response masks PII,
  refuses secrets, and (with an injection detector wired) blocks injected content.

## Files

- `rag_governed.py` — illustrative wiring using the maintained
  [`../clients/python/chai_client.py`](../clients/python).
- Policy: reuses [`../langchain/rag.chai`](../langchain/rag.chai).

## Run

```sh
CHAI_POLICY_FILE=integrations/langchain/rag.chai \
  cargo run -p chai_dsl --features server --example sidecar        # serves :8731

pip install llama-index httpx
export OPENAI_API_KEY=...
python integrations/llamaindex/rag_governed.py
```

Each retrieved node is expected to carry its doc id in `node.metadata["doc"]`. See
the LangChain README for notes on the access rule and injection detection.
