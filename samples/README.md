# Sample policies & tests

Run with the `chai` CLI:

```sh
cargo run --bin chai -- lint samples/emission.chai
cargo run --bin chai -- test samples/emission.tests.json --trace
cargo run --bin chai -- test samples/mcp_authz.tests.json
cargo run --bin chai -- eval samples/emission.chai '{"dlp_facts":{"pii_confidence":0.6}}'
```

- `emission.chai`: output governance (secrets / PII / harm / exfiltration).
- `mcp_authz.chai`: MCP tool-call authorization (trust tier + tool + args).
- `*.tests.json`: scenario assertions (`{context → expected effect}`) for `chai test`.

## The three policy paradigms, one decision

The running example is Aria, a customer-support agent. The same authorization
decision ("may this agent do this?") is shown in each of Chai's three shapes:

- `aria.chai`: the default Cedar deny-override paradigm. One policy covering
  authorization, PII redaction, secret denial, injection defense, and human
  review. Order-independent, most-restrictive-wins.
- `egress_acl.chai`: the ACL / firewall paradigm (`mode first_match`). An ordered
  tool allow/deny list where the first matching rule decides, so a specific allow
  placed before a broad deny takes priority.
- `cargo run --example pam_gate`: the PAM paradigm. Aria's refund gate as a stack
  of `required` / `sufficient` sub-checks (a library combinator, not DSL syntax).

```sh
cargo run --bin chai -- eval "$(cat samples/aria.chai)" \
  '{"subject":{"trust_tier":3},"action":"answer","args":{"amount":0},"dlp_facts":{"pii_confidence":0.7,"secrets_found":false},"safety_facts":{"harm":0.0},"tooltrace":{"tainted_sink":false}}'
#  Redact  (Redact by rule(s): pii)

cargo run --bin chai -- eval "$(cat samples/egress_acl.chai)" '{"action":"issue_refund","args":{"amount":50}}'
#  Allow  (First-match: rule allow-small decided)

cargo run --example pam_gate
```
