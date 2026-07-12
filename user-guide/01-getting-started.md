# Getting started

From zero to a policy decision in a few minutes, then the full toolchain.

## 1. Prerequisites

- **Rust** (stable), via [rustup](https://rustup.rs). The binary may be at
  `~/.cargo/bin/cargo` if cargo isn't on your `PATH`.
- Optional, per feature:
  - **z3** for SMT policy analysis: `brew install z3` (see [policy analysis](use-cases/policy-analysis.md)).
  - **Lean (elan)** to re-check the proofs: [`elan`](https://github.com/leanprover/elan).
  - **Python 3.12 + a venv** for the MCP proxy integration and detector evals.

## 2. Build & test

```sh
git clone <repo> chai_dsl && cd chai_dsl

cargo build                  # build the library
cargo test                   # unit + integration tests (the UT/IT base)
cargo test --features smt     # + z3 policy analysis (needs libz3)
cargo test --features server  # + HTTP sidecar
cargo test --features grpc    # + ext-authz gRPC surface
cargo test --features icap    # + ICAP REQMOD/RESPMOD surface
cargo test --features cedar-diff   # differential vs the real Cedar crate
```

Sanity checks that should pass out of the box:

```sh
cargo run --example cedar_conformance   # our engine vs Cedar's corpus -> 21/21
cargo run --example gdrive               # Cedar gdrive ReBAC          -> 7/7
cargo run --example full_pipeline        # Chai -> AFC -> ESP -> Emission, end to end
```

Re-check the formal proofs (optional):

```sh
cd formal && lake build      # builds all proofs; no `sorry`
```

## 3. Your first decision (the CLI on Aria)

The fastest way to see a decision is `chai eval` against the running-example
policy, [`samples/aria.chai`](../samples/aria.chai) (the policy the
[guide overview](README.md) introduces). `chai eval` takes a policy (a file path
or inline text) and a JSON request context, and prints the verdict, the reason,
and which rules fired.

In a real deployment the `dlp_facts` / `safety_facts` / `tooltrace` values are
computed by the evidence plane (AFC) from Aria's output. Here we pass them in
directly so you can drive each rule by hand.

**Aria answers cleanly.** Trusted agent, no PII, no secret, no taint:

```sh
cargo run -q --bin chai -- eval "$(cat samples/aria.chai)" \
  '{"subject":{"trust_tier":3},"action":"answer","args":{"amount":0},
    "dlp_facts":{"pii_confidence":0.1,"secrets_found":false},
    "safety_facts":{"harm":0.0},"tooltrace":{"tainted_sink":false}}'
```

```
Allow  (Allow by rule(s): clean)
rules: clean
```

The `clean` rule (`pii_confidence <= 0.4`) is the only one whose condition holds,
so the answer goes out.

**Aria's answer contains PII.** Raise `pii_confidence` to `0.7`:

```sh
cargo run -q --bin chai -- eval "$(cat samples/aria.chai)" \
  '{"subject":{"trust_tier":3},"action":"answer","args":{"amount":0},
    "dlp_facts":{"pii_confidence":0.7,"secrets_found":false},
    "safety_facts":{"harm":0.0},"tooltrace":{"tainted_sink":false}}'
```

```
Redact  (Redact by rule(s): pii)
rules: pii
```

Now `pii` (`pii_confidence > 0.4`) fires. Redact outranks Allow, so the released
text is masked instead of sent verbatim.

**Aria's answer contains a secret.** Set `secrets_found` to `true`:

```sh
cargo run -q --bin chai -- eval "$(cat samples/aria.chai)" \
  '{"subject":{"trust_tier":3},"action":"answer","args":{"amount":0},
    "dlp_facts":{"pii_confidence":0.1,"secrets_found":true},
    "safety_facts":{"harm":0.0},"tooltrace":{"tainted_sink":false}}'
```

```
Deny  (Deny by rule(s): secret)
rules: secret
```

`secret` votes Deny, and Deny is the top of the lattice, so it wins outright.

Three requests, three different outcomes, from one policy. The
[policy language](02-policy-language.md) page walks the rest of the rules
(`injected`, `refund-cap`, `untrusted-agent`, `harm`) and the paradigms behind
them.

## 4. The same decision as a library

`Cargo.toml`:

```toml
[dependencies]
chai_dsl = { path = "." }   # or your version/source
```

The Rust API behind that CLI is `parse_chai` then `eval_with_store`:

```rust
use chai_dsl::{parse_chai, eval_with_store, EntityStore};
use chai_dsl::ast::{Effect, Value};
use std::collections::HashMap;

fn main() {
    // A policy: only trusted agents may call write tools.
    let policy = "\
@id(\"untrusted\") forbid when subject.trust_tier < 3
@id(\"ok\")        permit when subject.trust_tier >= 3
";
    let program = parse_chai(policy).expect("parse");
    let store = EntityStore::new();

    // The request context: who is asking, with what attributes.
    let mut ctx = HashMap::new();
    let mut subject = HashMap::new();
    subject.insert("trust_tier".to_string(), Value::Int(4));
    ctx.insert("subject".to_string(), Value::Dict(subject));

    let decision = eval_with_store(&program, ctx, &store).unwrap();
    assert!(matches!(decision.effect, Effect::Allow));
    println!("{:?}: {}", decision.effect, decision.reason);
    // Allow: Allow by rule(s): ok
}
```

Key types you just used:

- `parse_chai(&str) -> ChaiProgram`: parse policy text (hard error on malformed).
- `eval_with_store(program, context, &store) -> Decision`: the decision.
- `Decision { effect, reason, reason_codes, rule_trace, obligations, errors }`:
  the verdict **plus** a full audit trail (which rules fired, why).
- `Effect`: `Allow | Deny | Redact | Defer | Downgrade | RequireHuman` (most-
  restrictive-wins; default **deny**).

## 5. The whole stack (streaming, fail-closed)

`run_chai` drives an agent through AFC → ESP → Emission, accumulating only the
*approved* output:

```rust
use chai_dsl::{parse_chai, run_chai, Afc, AgentStep, ScriptedAgent, EntityStore};
use std::collections::HashMap;

let policy = "\
@id(\"secret\") deny   when dlp_facts.secrets_found == true
@id(\"pii\")    redact when dlp_facts.pii_confidence > 0.4
@id(\"clean\")  permit when dlp_facts.pii_confidence <= 0.4
";
let program = parse_chai(policy).unwrap();
let store = EntityStore::new();
let afc = Afc::with_default_detectors();   // heuristic detectors; swap in Presidio/Llama Guard later

let mut agent = ScriptedAgent::new(vec![
    AgentStep::text("Here is the summary. "),
    AgentStep::text("Your SSN is 123-45-6789"),   // tripped -> never reaches the sink
]);

let outcome = run_chai(&program, &store, HashMap::new(), &afc, &mut agent);
// outcome.released  -> only the safe prefix
// outcome.decisions -> the per-step audit trail
```

The guarantee here is mechanized: emission is **fail-closed**: nothing reaches
the sink without an explicit allow (proven in `formal/ChaiProofs/Emission.lean`).

## 6. Run the sidecar (call decisions from any language)

```sh
cargo run --features server --example sidecar           # -> http://127.0.0.1:8731
```

```sh
curl -s -X POST http://127.0.0.1:8731/authorize_tool_call \
  -H 'content-type: application/json' \
  -d '{"subject_uid":"Agent::a1","subject_attrs":{"trust_tier":4},"tool":"db.write"}'
# {"effect":"Allow","reason":"Allow by rule(s): ok","rule_trace":["ok"],...}
```

To govern a *streamed* SSE tool-result stream, post it to
`POST /filter_tool_result_sse`: released prefixes come back as `data:` events,
withheld chunks as SSE comments, and any unapproved buffer is dropped at
end-of-stream, fail-closed, like every other surface.

See [Deployment](03-deployment.md) for the sidecar API and proxy integrations, and
the [MCP enforcement use case](use-cases/mcp-enforcement-point.md) for the full
PEP→PDP flow.

## Where to go next

- New to the policy syntax? → [Policy language](02-policy-language.md)
- Building an agent? → [Agent-emission governance](use-cases/agent-emission-governance.md)
- Building/fronting an MCP server? → [MCP enforcement point](use-cases/mcp-enforcement-point.md)
