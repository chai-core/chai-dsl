# Chai + LangChain

Govern a LangChain RAG chain with Chai without changing the chain. Chai sits at two
boundaries, enforced through the sidecar, and both are fail-closed:

- **Retrieval access control** (`chai.authorize`): drop any retrieved chunk the
  asking user is not allowed to see, before it reaches the model.
- **Answer emission control** (`chai.govern`): mask PII, refuse secrets, and (with an
  injection detector wired) block prompt-injected content, per streamed chunk.

## Files

- `rag.chai` — the policy (retrieval access + answer PII/secrets, injection optional).
- `rag_governed.py` — illustrative wiring using the maintained
  [`../clients/python/chai_client.py`](../clients/python).

## Run

```sh
# 1. sidecar with this policy
CHAI_POLICY_FILE=integrations/langchain/rag.chai \
  cargo run -p chai_dsl --features server --example sidecar        # serves :8731

# 2. the example
pip install langchain-openai httpx
export OPENAI_API_KEY=...
python integrations/langchain/rag_governed.py
```

You should see `doc:salaries` denied at retrieval, and the SSN/email masked or the
chunk withheld in the answer.

## Notes

- The access rule uses `args.doc in subject.viewable` (a plain string set the app
  passes per request), so no entity graph needs seeding. If you already model
  documents as entities, `resource in principal.viewable` works too, backed by the
  entity store.
- Injection detection needs a detector in the sidecar's AFC (the built-in
  `InjectionDetector` or Lakera); with the default detectors the injection rule
  stays inert. Detection accuracy is always the plugged-in detector's, not Chai's.
