# Use case: Cedar-style authorization

**Goal:** plain RBAC / ABAC / ReBAC authorization, whether or not there is an
agent involved. Chai's policy engine is **Cedar-shaped** and is
**differential-tested against the real Cedar crate**, so you can use it as a
readable, embeddable authorization engine in Rust.

## The running example: authorizing Aria's tool calls

Before Aria (a customer-support agent) runs a tool, ESP decides whether she may.
Two rules in [`samples/aria.chai`](../../samples/aria.chai) are ordinary
authorization, one attribute-based on the subject and one attribute-based on the
action arguments:

```
@id("untrusted-agent") forbid when subject.trust_tier < 2
@id("refund-cap")      forbid when action == "issue_refund" and args.amount > 100
```

`untrusted-agent` is ABAC on the principal (Aria must be at trust tier 2 or
higher). `refund-cap` is ABAC on the action and its arguments (no refund over
$100). Both are `forbid`, and under the default deny-override strategy a matching
`forbid` overrides every `permit`. Two requests, two denials:

```sh
chai eval samples/aria.chai \
  '{"subject":{"trust_tier":1},"action":"lookup_account","args":{}}'
# Deny (Deny by rule(s): untrusted-agent)

chai eval samples/aria.chai \
  '{"subject":{"trust_tier":4},"action":"issue_refund","args":{"amount":9999}}'
# Deny (Deny by rule(s): refund-cap)
```

A trusted agent making an in-cap refund matches neither `forbid`, so the request
falls through to the output-governance permits. Subject and action live in the
same eval context as everything else, so there is no separate authorization path:
an authorization check is just an ESP rule.

### Ordered allow/deny lists (ACL)

The default strategy is deny-override (most-restrictive-wins, order-independent).
When you want an ordered firewall-style allow/deny list, opt in with
`mode first_match`; the first matching rule wins and order is the control.
[`samples/egress_acl.chai`](../../samples/egress_acl.chai) is Aria's tool egress
list:

```
mode first_match
@id("allow-lookup") permit when action == "lookup_account"
@id("allow-small")  permit when action == "issue_refund" and args.amount <= 100
@id("deny-refund")  deny   when action == "issue_refund"
@id("deny-rest")    deny   when true
```

```sh
chai eval samples/egress_acl.chai '{"action":"issue_refund","args":{"amount":50}}'
# Allow (First-match: rule allow-small decided)

chai eval samples/egress_acl.chai '{"action":"issue_refund","args":{"amount":9999}}'
# Deny  (First-match: rule deny-refund decided)
```

The $50 refund is allowed because `allow-small` sits ahead of `deny-refund`.
Under the default deny-override mode the broad `deny-refund` would win instead;
ordering is what distinguishes an ACL.

## When to use it

- You need fine-grained access control (roles, attributes, relationships) and want
  a small, readable policy language with deny-overrides semantics.
- You're already in Rust and don't want to pull a separate policy service.
- You value the analysis/verification story (proven decision algebra; z3
  equivalence, see [policy analysis](policy-analysis.md)).

## The model

A request is `(principal, action, resource, context)`; entities live in an
`EntityStore` that supports attributes and transitive `in` (the hierarchy). This
is exactly Cedar's shape. Aria's rules above use string/attribute context;
ReBAC uses the store's hierarchy:

```rust
use chai_dsl::{parse_chai, eval_with_store, EntityStore};
use chai_dsl::entity::Entity;
use chai_dsl::ast::{Effect, Value};
use std::collections::HashMap;

// Build the entity store (who is in what group, what folder contains what).
let mut store = EntityStore::new();
store.insert(Entity::new("Group::eng"));
store.insert(Entity::new("User::alice").parent("Group::eng"));   // alice ∈ eng
store.insert(Entity::new("Folder::shared"));
store.insert(Entity::new("Doc::readme").parent("Folder::shared"));

let program = parse_chai(
    "@id(\"eng-can-read\") permit when principal in Group::\"eng\" \
        and action == Action::\"read\" and resource in Folder::\"shared\"\n",
).unwrap();

// The request bindings.
let mut ctx = HashMap::new();
ctx.insert("principal".into(), Value::EntityUid("User::alice".into()));
ctx.insert("action".into(),    Value::EntityUid("Action::read".into()));
ctx.insert("resource".into(),  Value::EntityUid("Doc::readme".into()));

let d = eval_with_store(&program, ctx, &store).unwrap();
assert!(matches!(d.effect, Effect::Allow));   // via transitive `in`
```

## Loading entities from Cedar JSON

If you already have Cedar-format entity data:

```rust
use chai_dsl::EntityStore;
let json: serde_json::Value = serde_json::from_str(cedar_entities_json).unwrap();
let store = EntityStore::from_cedar_entities_json(&json).unwrap();
```

> Note: our string-literal grammar can't contain `"`, so UIDs are stored
> quote-free (`User::"alice"` → `User::alice`). `normalize_uid` handles the
> request side; `from_cedar_entities_json` handles the store side, so they line up.

## Pluggable entity backends

The store above is `EntityStore`, but it is one implementation of a trait. Every
eval entry point takes `&dyn EntityResolver`, so the entity/relationship backend
is the plug point. Four options, all interchangeable:

- `EntityStore` (in-memory, the default; load from Cedar entity JSON, as above).
- `PgStore` (feature `postgres`): backed by two tables,
  `entity_attr(uid, name, value JSONB)` and `entity_parent(child, parent)`;
  transitive `in` resolves via a recursive CTE. Verified live against Postgres 16
  (`tests/postgres.rs`, 2/2).
- `RedisStore` (feature `redis`): attributes as `HSET chai:attr:<uid> <name> <json>`
  and edges as `SADD chai:parents:<uid> <parent>`; transitive `in` resolves by
  client-side BFS. Verified live against Redis 8.8 (`tests/redis.rs`, 2/2).
- Any custom type implementing `EntityResolver { attr, has_attr, is_in }`.

Use Postgres or Redis when the entity/relationship graph outgrows in-memory. The
policy, the rules, and the eval call are identical across all four backends.

## RBAC / ABAC / ReBAC examples

```
# RBAC
@id("admin")  permit when principal in Role::"admin"

# ABAC (Aria's untrusted-agent and refund-cap rules are of this form)
@id("owner")  permit when resource.owner == principal
@id("public") permit when resource.is_public and action == Action::"read"

# ReBAC (relationships)
@id("member") permit when principal in resource.team
@id("nested") permit when resource in principal.viewable      # transitive

# forbid overrides everything (deny-overrides default)
@id("locked") forbid when resource.classification == "secret" and not (principal in Group::"cleared")

# Extension types
@id("net")    permit when principal.addr.isInRange(ip("10.0.0.0/8"))
@id("cap")    forbid when resource.cost.greaterThan(decimal("500.00"))

# Policy templates (link a principal/resource at instantiation)
@id("share")  permit when principal == ?principal and resource == ?resource
```

## How faithful is it to Cedar?

- **Conformance:** runs Cedar's own `tiny_sandboxes` corpus, **21/21** for cases
  expressible in our language; cases needing Cedar features we don't have are
  listed out-of-scope, not faked (`examples/cedar_conformance.rs`).
- **gdrive ReBAC model:** **7/7** (`examples/gdrive.rs`).
- **Differential:** generative testing against the *real* Cedar crate over 4000
  scenarios: RBAC/ReBAC + bool attributes + principal groups + multi-level
  hierarchy + `ip()` (`cargo test --features cedar-diff`). This found **4 real
  bugs** in our engine (plus a 5th, a `redact` fail-open, found and fixed this
  session); the value of the differential is precisely that it surfaces them.
- **Proven:** the decision algebra reduces *exactly* to Cedar deny-overrides for
  permit/forbid policies, mechanically proven
  (`formal/ChaiProofs/Decision.lean::cedar_reduction`). This is why Aria's
  `forbid` rules override her `permit` rules the same way Cedar's would.

## Performance

~1.2 µs/authorization at 10k entities, on the same machine where Cedar's
`is_authorized` benches at 1.76 µs, same order of magnitude (Cedar does strictly
more per decision). Full methodology and caveats in
[`BENCHMARKS.md`](../../BENCHMARKS.md).

```sh
cargo bench --bench authorization
```

## What Cedar has that this doesn't

Honest gaps: Cedar's **schema validator** (typed policy validation) and its
formally-verified analyzer go further than our z3 fragment. We have a schema
validator (`src/schema.rs`) that type-checks typed context records **including
nested records**, plus z3 equivalence/reachability, but still not Cedar's full
typed policy validation. See [`BACKLOG.md`](../../BACKLOG.md).
