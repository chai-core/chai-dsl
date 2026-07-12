# Use case: Agent-emission governance

**Goal:** control what an LLM agent *emits* (redact PII, block secrets, defer or
halt for human review), **fail-closed** and **streaming**, so unsafe content never
reaches the sink (the user, a channel, a log).

This is the original Chai thesis: a draft output is governed prefix-by-prefix as
it streams.

```
agent → AFC (facts about the prefix) → ESP (decide) → Emission (emit/buffer/redact/drop/halt) → sink
```

## The running example: Aria's streamed reply

Aria is a customer-support agent. She answers questions from internal docs and
streams the answer back to the customer. The same policy that authorizes her tool
calls also governs her text output. The output-governance rules are the last
three lines of [`samples/aria.chai`](../../samples/aria.chai):

```
@id("secret") deny   when dlp_facts.secrets_found == true
@id("harm")   require_human when safety_facts.harm > 0.6
@id("pii")    redact when dlp_facts.pii_confidence > 0.4
@id("clean")  permit when dlp_facts.pii_confidence <= 0.4
```

Aria drafts three different replies. The AFC layer computes DLP facts over each
prefix; ESP decides; Emission enforces. Three inputs, three verdicts:

| Aria's draft prefix | AFC fact | ESP rule | Emission action |
|---|---|---|---|
| "Your balance is $40." | `pii_confidence = 0.1` | `clean` | **Emit** verbatim |
| "We have your card on file, 4111 1111 1111 1111." | `pii_confidence = 0.7` | `pii` | **Redact** the span |
| "The internal API key is sk-live-abc123." | `secrets_found = true` | `secret` | **Deny**, drop the chunk |

You can reproduce each verdict with the CLI:

```sh
chai eval samples/aria.chai '{"subject":{"trust_tier":4},"dlp_facts":{"pii_confidence":0.1}}'
# Allow  (Allow by rule(s): clean)

chai eval samples/aria.chai '{"subject":{"trust_tier":4},"dlp_facts":{"pii_confidence":0.7}}'
# Redact (Redact by rule(s): pii)

chai eval samples/aria.chai '{"subject":{"trust_tier":4},"dlp_facts":{"secrets_found":true}}'
# Deny   (Deny by rule(s): secret)
```

The default evaluation strategy is Cedar deny-override, most-restrictive-wins, so
if a single prefix carries both PII and a secret, `secret`'s Deny beats `pii`'s
Redact. Order of the rules does not matter.

## When to use it

- You stream LLM output to users/channels and must guarantee PII/secrets never
  slip out, even mid-generation, even if a check errors.
- You want a single, auditable policy governing all output, decoupled from the
  model and the detectors.

## Driving the whole stack

`run_chai` drives an agent through AFC → ESP → Emission and accumulates only the
released output. Here Aria's second chunk trips the `secret` rule and is dropped:

```rust
use chai_dsl::{parse_chai, run_chai, Afc, AgentStep, ScriptedAgent, EntityStore};
use std::collections::HashMap;

let program = parse_chai(include_str!("../samples/aria.chai")).unwrap();
let store = EntityStore::new();
let afc = Afc::with_default_detectors();

let mut aria = ScriptedAgent::new(vec![
    AgentStep::text("Here is the summary. "),
    AgentStep::text("The internal API key is sk-live-abc123"),   // tripped -> never emitted
]);

let outcome = run_chai(&program, &store, HashMap::new(), &afc, &mut aria);
assert!(!outcome.released.contains("sk-live-abc123"));
// outcome.decisions is the per-step audit trail
```

`ScriptedAgent` is for tests/demos; in production you implement the `Agent` trait
over your real LLM stream.

## Driving the enforcer directly (your own loop)

If you already have a token/chunk stream, drive `EmissionEnforcer` yourself. You
inject the facts (compute them however you like), which keeps inference (facts)
and control (policy) cleanly separated.

```rust
use chai_dsl::{parse_chai, EmissionEnforcer, EmitAction, EntityStore, Afc};
use std::collections::HashMap;

let program = parse_chai(include_str!("../samples/aria.chai")).unwrap();
let store = EntityStore::new();
let afc = Afc::with_default_detectors();
let mut enf = EmissionEnforcer::new(&program, &store, HashMap::new());

for chunk in aria_stream {                  // your streaming source
    let facts = afc.compute(chunk, step).to_context();
    match enf.step(chunk, facts) {
        EmitAction::Emit(text)   => sink.write(&text),     // clean: release
        EmitAction::Redact(text) => sink.write(&text),     // pii: release masked
        EmitAction::Buffer       => {/* hold, decide later */}
        EmitAction::Drop         => {/* secret: discard */}
        EmitAction::RequireHuman => break,                 // harm: halt the stream
    }
}
let _ = enf.finish();   // any unapproved buffer is dropped, never emitted
```

## The guarantees (mechanically proven)

These are proven in `formal/ChaiProofs/Emission.lean`:

- **Fail-closed:** content reaches the sink only via an authorizing effect; an
  errored or no-match decision yields no output (`release_effect`). If Aria's DLP
  detector times out, the chunk is denied, it does not leak.
- **Redact is fail-closed too:** if the span-masker can't localize a PII span to
  mask, the chunk is **dropped**, never emitted unchanged. A redaction that
  removes nothing is not a redaction. This is the guarantee behind the `pii` row
  in the table: a Redact verdict never degrades into passing the card number
  through.
- **Halt is sealed:** after a `require_human` (Aria's `harm` rule), every later
  step is `Drop`: nothing else escapes (`sealed_stream`).
- **`finish()` never emits** buffered-but-unapproved content (`finish_no_release`).
- **End-to-end:** on permit/forbid policies, output is released only when an
  explicit permit matched (`release_needs_matched_allow`).

The Rust runtime is additionally checked against these invariants over 2000
randomized runs (`tests/emission_invariants.rs`).

## Using real detectors

`Afc::with_default_detectors()` uses heuristics (keyword/pattern/entropy), fine
for demos, labeled as such. That is what produced the `pii_confidence` and
`secrets_found` facts above. For production, plug real detectors behind the
`Detector` trait:

```rust
use chai_dsl::Afc;
// Presidio for PII, Llama Guard for safety, over a transport you supply
let afc = Afc::with_external(presidio_call, llama_guard_call);
```

The adapters parse those tools' native output and record `Callee`-sourced
evidence; you supply the transport (HTTP, subprocess). The detector's *accuracy*
is the tool's; our job is correct integration + fail-closed handling. Both
integrations are verified against the real tools: Presidio has a real eval (F1
88.3%: precision 88.8%, recall 87.8% over a 460-case seeded corpus), and Llama
Guard is checked with a live smoke test through Ollama (`llama-guard3:1b`): a
benign prompt returns `"safe"` and a harmful one `"unsafe\nS1"`, both
adapter-parseable (2/2). See [`DETECTOR_EVAL.md`](../../DETECTOR_EVAL.md) and
`examples/external_detectors.rs`.

## Extending Aria's output policy

The four rules above cover clean/redact/deny/human-review. The same fact
namespaces support tiered and channel-aware variants:

```
# Tiered response to safety risk (the `harm` rule split into three bands)
@id("block")   deny          when safety_facts.harm > 0.9
@id("review")  require_human when safety_facts.harm > 0.6
@id("soften")  downgrade     when safety_facts.harm > 0.3

# Grounding: defer ungrounded claims for more context
@id("ungrounded") defer when grounding_facts.support < 0.5

# Channel-aware DLP: stricter when Aria replies on a public channel
@id("public-pii") redact when object.channel == "public" and dlp_facts.pii_confidence > 0.2
```

## Run the demos

```sh
cargo run --example full_pipeline       # all four layers, fail-closed
cargo run --example emission            # streaming emit/buffer/redact/drop
cargo run --example afc                 # facts computed from the prefix
cargo run --example external_detectors  # Presidio + Llama Guard adapters
```
