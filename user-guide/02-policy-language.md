# Policy language

Chai policies are **Cedar-shaped and readable**. This page is a reference with
lots of examples. Every snippet parses with `parse_chai`.

## Rule anatomy

A policy is a list of rules. The common form is a single line:

```
@id("name")  <effect>  when  <boolean condition>
```

- `@id("name")`: optional label, echoed back in `decision.rule_trace` for audit.
- `<effect>`: what this rule votes for if its condition holds (below).
- `when <condition>`: a boolean expression over the request. Omit `when` (or use
  `when true`) for an unconditional rule.

Rules are separated by `;` **or** a newline; both are accepted.

```
@id("always") permit when true
@id("never")  forbid when true
```

## Effects and how they combine

| Keyword | Effect | Meaning |
|---|---|---|
| `permit` | Allow | release |
| `forbid` / `deny` | Deny | block (both map to Deny) |
| `redact` | Redact | release a transformed/masked version |
| `defer` | Defer | buffer pending more context |
| `downgrade` | Downgrade | release a reduced version |
| `require_human` | RequireHuman | halt for human approval |

`redact` is **fail-closed**: when the span-masker cannot localize a PII span to
mask, it **drops** the chunk rather than emit it unchanged. A redaction that
removes nothing is not a redaction.

Multiple rules can match. They resolve by a **most-restrictive-wins** lattice:

```
DENY > REQUIRE_HUMAN > DEFER > REDACT > DOWNGRADE > ALLOW
```

If **no** rule matches, the decision is **Deny** (fail-closed). For permit/forbid-
only policies this reduces *exactly* to Cedar's deny-overrides, a fact that is
mechanically proven (`formal/ChaiProofs/Decision.lean::cedar_reduction`).

**Seal-on-presence.** The verdict above is the most-restrictive matched effect,
but `require_human` also has a stream-level consequence that is independent of the
join: whenever a `require_human` rule matches, the emission runtime **seals** the
stream for review, *even when a `deny` wins the verdict*. So a chunk that trips
both `secret` (Deny) and `harm` (RequireHuman) is both dropped (under Deny) and
seals the stream, and more-alarming evidence never yields a weaker stream-level
response than `require_human` alone
(`formal/ChaiProofs/Emission.lean::seal_on_presence_perm`).

## Three paradigms, one agent

The same rule-and-effect vocabulary supports three ways of combining rules. All
three are shown here on Aria, the customer-support agent from the
[guide overview](README.md). Every verdict below is produced by the real engine;
the commands reproduce them.

### Paradigm 1: deny-override, the default ([`samples/aria.chai`](../samples/aria.chai))

`mode deny_override` is the default and matches Cedar semantics: **every** rule is
evaluated, the most-restrictive vote wins, and the outcome is **order-independent**
(a rule can never be shadowed by where it sits in the file, proven order-independent).
This is the safe default for governing an agent, because you cannot weaken a deny by
reordering the policy.

Aria's whole policy runs this way:

```
@id("untrusted-agent") forbid        when subject.trust_tier < 2
@id("refund-cap")      forbid        when action == "issue_refund" and args.amount > 100
@id("injected")        forbid        when tooltrace.tainted_sink == true
@id("secret")          deny          when dlp_facts.secrets_found == true
@id("harm")            require_human when safety_facts.harm > 0.6
@id("pii")             redact        when dlp_facts.pii_confidence > 0.4
@id("clean")           permit        when dlp_facts.pii_confidence <= 0.4
```

Feeding it different requests (see [Getting started](01-getting-started.md) for the
full `chai eval` commands) gives, all verified against the engine:

| Request | Verdict | Rule that decides |
|---|---|---|
| clean answer (`pii_confidence` 0.1) | `Allow` | `clean` |
| answer with PII (`pii_confidence` 0.7) | `Redact` | `pii` |
| answer containing a secret | `Deny` | `secret` |
| `issue_refund` while the request is tainted | `Deny` | `injected` |
| `issue_refund` of $9999 | `Deny` | `refund-cap` |
| agent with `trust_tier` 1 | `Deny` | `untrusted-agent` |

When several rules match, the lattice decides. A tainted $9999 refund trips
`injected`, `refund-cap`, and (if the answer also carried PII) `pii`; Deny sits
above Redact, so the verdict is Deny regardless of order.

### Paradigm 2: ACL / first-match ([`samples/egress_acl.chai`](../samples/egress_acl.chai))

`mode first_match` reads the policy top to bottom like an ipfw ruleset: the
**first** matching rule decides and the rest are skipped. Order becomes the
control. This is more expressive than deny-override but makes ordering
security-critical, so declare it deliberately.

An egress allow/deny list for Aria's tool calls:

```
mode first_match

@id("allow-lookup") permit when action == "lookup_account"
@id("allow-small")  permit when action == "issue_refund" and args.amount <= 100
@id("deny-refund")  deny   when action == "issue_refund"
@id("deny-rest")    deny   when true
```

Verified with `chai eval` (the reason strings read `First-match: rule X decided`):

| Request | Verdict | Rule that decides |
|---|---|---|
| `lookup_account` | `Allow` | `allow-lookup` |
| `issue_refund` of $50 | `Allow` | `allow-small` |
| `issue_refund` of $9999 | `Deny` | `deny-refund` |
| any other tool | `Deny` | `deny-rest` |

```sh
cargo run -q --bin chai -- eval "$(cat samples/egress_acl.chai)" \
  '{"action":"issue_refund","args":{"amount":50}}'
# Allow  (First-match: rule allow-small decided)
# rules: allow-small
```

The $50 refund is allowed because `allow-small` sits **before** `deny-refund` and
wins the race. Move `deny-refund` up and the small refund would be blocked. Under
the default deny-override mode the broad `deny-refund` would always win instead;
ordering is exactly what makes ACL different.

### Paradigm 3: PAM stack, a proven combinator (`cargo run --example pam_gate`)

For a multi-factor **guard** (this action is allowed only if several tagged
checks agree), Chai provides a PAM-style combinator (`chai_dsl::pam`, tags
`required` / `requisite` / `sufficient` / `optional`), proven order-independent and
fail-closed in `formal/ChaiProofs/PamGuard.lean`. A guard passes when every
`required` / `requisite` check passes and, if any `sufficient` check is present,
at least one of them passes.

Aria's refund gate as a stack (see [`examples/pam_gate.rs`](../examples/pam_gate.rs)):

```
required:   subject.trust_tier >= 2
required:   tooltrace.tainted_sink == false
sufficient: subject.role == "senior"
sufficient: args.amount <= 100
```

Running `cargo run --example pam_gate` prints, verified:

| Scenario | Verdict |
|---|---|
| junior, untainted, $50 refund | `PASS` |
| junior, untainted, $9999 refund | `DENY` |
| senior, untainted, $9999 refund | `PASS` |
| junior, TAINTED, $50 refund | `DENY` |
| untrusted (tier 1), $50 refund | `DENY` |

A single failed `required` check fails the whole guard (the tainted and tier-1
rows). When a `sufficient` group is present, one member must pass: a large refund
needs the senior role, a small one clears on the amount. Order among the checks
never changes the verdict.

> **Status:** today the PAM stack is a **library combinator** (`chai_dsl::pam`),
> not yet policy-text grammar. Use it programmatically:

```rust
use chai_dsl::pam::{passes, Flag};

// identity_verified AND (risk_low OR human_approved); optional ignored
let verdict = passes(&[
    (Flag::Required,   identity_verified),
    (Flag::Sufficient, risk_low),
    (Flag::Sufficient, human_approved),
    (Flag::Optional,   cited),
]);
```

The intended policy-text form (planned) is:

```
permit when
  required:   subject.identity_verified
  requisite:  not safety_facts.harm
  sufficient: risk_facts.score < 0.3
  sufficient: subject.human_approved
  optional:   grounding_facts.cited
```

## Conditions: the expression language

**Operators:** `and` `or` `not` (`!`), comparisons `== != < <= > >=`, arithmetic
`+ - *`, membership `in`, `contains`, type test `is`.

**Values:** booleans, ints, decimals, strings, lists `[...]`, records `{...}`,
entity UIDs `Type::"id"`, and extension types `ip("...")` / `decimal("...")`.

### RBAC (role / attribute on the subject)

Aria's `untrusted-agent` rule (`forbid when subject.trust_tier < 2`) is exactly
this kind of subject-attribute check:

```
@id("admins")  permit when subject.role == "admin"
@id("tier")    permit when subject.trust_tier >= 3
@id("scoped")  permit when subject.capabilities contains "db.write"
```

### ABAC (attributes on subject, action, resource)

```
@id("read-public") permit when action == Action::"read" and resource.is_public
@id("biz-hours")   permit when context.hour >= 9 and context.hour < 18
@id("region")      forbid when resource.region != subject.region
```

### ReBAC (relationships via transitive `in`)

`in` walks the entity hierarchy (a doc inside a folder inside a folder; a user
inside a group). It is reflexive and transitive.

```
@id("group")     permit when principal in Group::"engineering"
@id("inherited") permit when action == Action::"read" and resource in principal.viewable
@id("owner")     permit when principal.owned_documents contains resource
@id("folder")    permit when resource in Folder::"shared"
```

Action groups work the same way:

```
@id("write-group") permit when action in [Action::"create", Action::"update", Action::"delete"]
```

### Extension types: `ip()` and `decimal()`

```
@id("internal") permit when principal.addr.isInRange(ip("10.0.0.0/24"))
@id("v6")       permit when principal.addr == ip("::1")
@id("limit")    forbid when resource.amount.greaterThan(decimal("1000.00"))
```

### Entity literals and `is`

```
@id("specific") permit when principal == User::"alice"
@id("type")     permit when resource is Photo
```

## Emission policies: reading alignment facts

For governing what an agent *emits* (or what a tool *returns*), conditions read
the **AFC fact namespaces** computed from the content:

| Namespace | Example facts |
|---|---|
| `dlp_facts` | `pii_confidence`, `secrets_found`, `pii_entities`, `entropy` |
| `safety_facts` | `harm`, `unsafe_categories` |
| `grounding_facts` | citation/support metrics |
| `schema_facts` | structural-validity results |
| `tooltrace` | `tainted_sink` (dataflow), attempted external actions |
| `risk_facts` | aggregated risk score |

Aria's output-governance rules are exactly this shape. `secret`, `harm`, `pii`,
and `clean` in [`samples/aria.chai`](../samples/aria.chai) read `dlp_facts` and
`safety_facts`; `injected` reads `tooltrace.tainted_sink`. A policy can read any
namespace the same way:

```
@id("secret")  deny          when dlp_facts.secrets_found == true
@id("pii")     redact        when dlp_facts.pii_confidence > 0.4
@id("harm")    require_human when safety_facts.harm > 0.7
@id("exfil")   forbid        when tooltrace.tainted_sink == true
@id("risk")    downgrade     when risk_facts.score > 0.6
@id("clean")   permit        when dlp_facts.pii_confidence <= 0.4
```

### Releasing a `defer`red chunk: the Approve transition

`defer` buffers a chunk; it is not a delayed drop. The **Approve transition**
releases a buffered chunk under a *re-decision* on new facts whose verdict
authorizes release (typically an attested approval fact). An unapproved buffer is
dropped at end of stream. In the runtime:

```rust
match enf.step(chunk, facts) {
    EmitAction::Buffer => { /* held pending review */ }
    _ => { /* emit / redact / drop / halt as usual */ }
}
// later, a human approves -> re-decide the buffer under approval facts:
let released = enf.approve(approval_facts);   // Emit(..) iff the re-decision authorizes
// never approved -> finish() drops it, fail-closed
```

A buffered release still requires an authorizing decision, now on the approval
facts (`formal/ChaiProofs/Emission.lean::approve_release_effect`).

## Extending the algebra: obligations, tiers, budgets

These extend the core without changing the resolution above (all proven).

**Obligations accumulate.** When the verdict releases, *every* matched releasing
rule at-or-below it applies its transform, not just the winner. A chunk matching
both `redact` (mask an SSN) and `downgrade` (strip a label) has both applied, so no
labelled text escapes (`obligations_perm` / `obligations_complete`).

**Evidence tiers.** Facts carry a provenance tier: `measured` (detector output) <
`derived` (runtime-computed: taint joins, counters, a clock) < `attested`
(signature-verified: approvals, tokens). A rule may require a minimum tier, and
fires only if the evidence it reads meets it:

```
permit requires attested when approval.valid == true   # never fires from a detector estimate
```

The tier of each fact is supplied by the caller in a reserved `__tiers` context
entry (`{"approval": "attested"}`); an unmarked fact defaults to `measured`.
Signature verification thereby joins the trusted base (`attested_gate_sound`).

**Session budgets.** Session state is monotone state a guard can read. The runtime
(`SessionBudget`) injects `session.spend`/`session.cap` and charges a release only
within the cap, so the released spend never exceeds the cap (`spend_bounded`):

```
forbid when session.spend + args.amount > session.cap
permit when true
```

**Endorsement** composes these: a deferred chunk is released by `approve()` only
under a re-decision whose facts include a **valid, attested** approval; an expired
approval reads as invalid and fails closed like missing evidence.

**k-lookahead** (opt-in) holds a sliding window of *k* chunks so a substring within
any *k* consecutive chunks releases atomically, closing the cross-chunk split leak
(`substring_atomic`); it costs *k* chunks of latency and is a variant, not the
default.

## Subject / object as ordinary context

Subject and object live in the eval context, so subject checks are *ordinary
rules*, not a separate code path:

```
@id("agent-cap") forbid when not (subject.capabilities contains action)
@id("channel")   forbid when object.channel == "public" and dlp_facts.pii_confidence > 0.2
```

## Errors are effect-tagged and fail-closed

A condition that cannot be evaluated (a type mismatch, a missing fact, a detector
or entity resolver that is down) **can never grant access**, and it is always
recorded in `decision.errors` so a broken policy is never mistaken for a clean
decision. What the error *does* to the decision is **effect-tagged**, following
XACML's `Indeterminate{D}`/`Indeterminate{P}`:

- An error on a **restrictive** rule (`forbid`/`deny`, `redact`, `require_human`,
  `defer`, `downgrade`) **contributes that rule's effect**. The reading is
  conservative: we could not check the condition that would have restricted, so
  we restrict. A failed `forbid` therefore *denies*.
- An error on a **`permit`** contributes nothing (a permit can never manufacture
  an allow), so it stays inert.

A malformed *statement* is a hard `parse_chai` error, not a dropped rule.

```rust
// A forbid whose guard errors denies (it does not silently vanish):
//   permit when true
//   forbid when tooltrace.tainted_sink == true   // taint tracker down -> Deny
let d = eval_with_store(&program, ctx, &store).unwrap();
assert!(matches!(d.effect, Effect::Deny));
assert!(!d.errors.is_empty());   // the failure is still visible
```

### `strict` / `lenient`: the availability escape hatch

Restrictive rules default to **strict** (an error contributes the effect). When an
absent fact is expected rather than a failure, for example an emission-plane rule
that is also evaluated in an authorization context where its `dlp_facts` are
legitimately absent, annotate the rule **`lenient`** so its error stays inert:

```
deny lenient   when dlp_facts.secrets_found == true    # error here is inert
require_human  when safety_facts.harm > 0.7            # strict (default): error seals
```

`strict` is also accepted explicitly. On a `permit` the annotation is a no-op,
since a permit error is inert either way. Run `cargo run --example
effect_tagged_errors` for the worked cases.
