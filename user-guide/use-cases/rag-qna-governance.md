# RAG Q&A / summarizer governance

Most LLM apps are a retriever plus a model: pull the most relevant chunks from a
shared corpus, then answer or summarize. Three failure modes never show up in the
demo, and Chai handles all three with one policy at the answer boundary.

| Failure | Chai rule |
|---|---|
| Answers from documents the asker shouldn't see | `permit when args.doc in subject.viewable` |
| Leaks PII or a secret that lives in a document | `redact … dlp_facts.pii_confidence > 0.4`, `deny … dlp_facts.secrets_found` |
| A poisoned document hijacks it | `deny … injection_facts.injection_risk > 0.5` (needs an injection detector) |

## Two boundaries, one policy

A RAG app crosses Chai twice, and one policy file (`rag.chai`) governs both:

1. **Retrieval** (`authorize_tool_call`): before a retrieved chunk reaches the model,
   ask Chai whether this user may see it. The policy sees `args` (the chunk's doc id)
   and `subject` (the user's allowed set). Default-deny drops anything unlisted.
2. **Answer** (`filter_tool_result`): as the model streams, each chunk goes through
   Chai, which runs the detectors and applies redact / deny / emit. The policy sees
   the text and the detector facts (`dlp_facts`, and `injection_facts` if wired).

Rules that read detector facts are marked `lenient` so they stay inert on the
retrieval path, where those facts are absent, instead of denying it.

```
@id("access") permit when args.doc in subject.viewable
@id("pii")    redact lenient when dlp_facts.pii_confidence > 0.4
@id("secret") deny   lenient when dlp_facts.secrets_found == true
@id("clean")  permit lenient when dlp_facts.pii_confidence <= 0.4
@id("injection") deny lenient when injection_facts.injection_risk > 0.5
```

## Wire it in

Runnable examples that change no retrieval or generation code, only add the two Chai
calls around them:

- **LangChain**: [`integrations/langchain/`](../../integrations/langchain)
- **LlamaIndex**: [`integrations/llamaindex/`](../../integrations/llamaindex)

Both call the sidecar through the maintained Python client and are fail-closed: if
the sidecar is slow or down, retrieval denies and the answer chunk is withheld.

## Choices and caveats

- **Access rule form.** `args.doc in subject.viewable` compares plain strings the app
  passes per request, so nothing needs seeding. If you already model documents as
  entities with a hierarchy, `resource in principal.viewable` works too and walks the
  entity graph (the same ReBAC the gdrive conformance model uses).
- **Detection is the detector's.** The bundled detectors are heuristics. Wire Presidio
  for PII and the built-in `InjectionDetector` or Lakera for injection; their accuracy
  is theirs, the fail-closed enforcement is Chai's.
