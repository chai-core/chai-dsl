# Use case: Policy analysis

**Goal:** catch policy bugs *before* they ship, answering questions like "can this
rule ever fire?", "did my refactor change any decision?", and "is this branch
dead?", for policy authors and CI.

We use Aria's policy ([`samples/aria.chai`](../../samples/aria.chai)) as the
worked example throughout, since it mixes numeric bands (`pii_confidence`,
`harm`, `args.amount`) with entity/string equality.

The toolset:

- **Pure-Rust analysis** (always available): dead-rule / unreachable-condition
  detection **and contradiction detection** via interval reasoning
  (`src/analysis.rs`).
- **z3-backed SMT analysis** (feature `smt`): sound **and complete** reachability
  and equivalence over the encoded fragment (`src/smt.rs`).
- **Schema validation** (`src/schema.rs`): type-checks typed context records,
  **including nested records**, so a policy that reads a mistyped or misshaped
  context field is caught before it ships.

## Setup (for the SMT layer)

```sh
brew install z3
export LIBRARY_PATH=/opt/homebrew/lib:$LIBRARY_PATH
export CPATH=/opt/homebrew/include:$CPATH
export Z3_SYS_Z3_HEADER=/opt/homebrew/include/z3.h
export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib
cargo test --features smt
```

## Reachability: can this condition ever be true?

Suppose someone tightens Aria's `refund-cap` rule into a single band and gets the
bounds backwards, or tries to fold her two PII bands into one rule:

```rust
use chai_dsl::smt::condition_reachable;
// (parse a condition expression `expr` first)
match condition_reachable(&expr) {
    Some(true)  => {}                 // satisfiable: the rule can fire
    Some(false) => panic!("dead rule: this condition is unsatisfiable"),
    None        => {}                 // outside the encoded fragment -> unknown
}
```

`dlp_facts.pii_confidence > 0.5 and dlp_facts.pii_confidence < 0.3` → `Some(false)`
(dead: no confidence is both above 0.5 and below 0.3). `principal == User::"a" and
principal == User::"b"` → `Some(false)` (a principal can't be two entities). These
are exactly the mistakes that produce a rule that never fires.

## Equivalence: did my refactor change any decision?

The headline analysis: prove two conditions decide identically for **all** inputs.
Say you rewrite a combined safety-and-PII guard using De Morgan and want to be
sure the rewrite is behavior-preserving:

```rust
use chai_dsl::smt::conditions_equivalent;
let before = /* parse */;  // not (safety_facts.harm > 0.6 or dlp_facts.pii_confidence < 0.4)
let after  = /* parse */;  // safety_facts.harm <= 0.6 and dlp_facts.pii_confidence >= 0.4
assert_eq!(conditions_equivalent(&before, &after), Some(true));   // safe refactor
```

`Some(true)` = equivalent, `Some(false)` = a difference exists, `None` = outside
the fragment (never a wrong answer: it fails to "unknown", not to a false claim).

## What the SMT layer can reason about

Boolean combinations (`and`/`or`/`not`) of:

- numeric comparisons (`< <= > >= == !=`) over **linear/polynomial real
  arithmetic** (`+ - *`, path-vs-path): `dlp_facts.pii_confidence + safety_facts.harm > 1.0`,
  `args.amount > threshold`;
- boolean atoms (`flag`, `tooltrace.tainted_sink == true`);
- entity/string **equality** (`principal == User::"x"`, `action == "issue_refund"`).

Anything else (methods, list/`in` terms, ordering of entities) makes it return
`None`: unknown, never wrong.

### How much do you trust it?

The z3 encoding is differential-tested against an **independent, complete oracle**
(a separate exact-integer reference brute-forced over a grid), asserting z3 agrees
**exactly, both directions, across 6000 random conditions**. A perf/scale
study confirms encode+solve stays in single-digit milliseconds up to N=800 terms.
So the *integration* is rigorously validated: see
[`BACKLOG.md`](../../BACKLOG.md) for the honest scope (it's testing of a fragment,
not a whole-language proof).

## Pure-Rust dead-rule detection (no z3)

```rust
use chai_dsl::analysis::unreachable_rules;
let dead = unreachable_rules(&program);   // indices of rules that can never fire
```

Run over Aria's policy this returns empty: every one of her rules is reachable.
Add the backwards `pii_confidence > 0.5 and pii_confidence < 0.3` band and its
index shows up. This is a sound *under-approximation* over conjunctions of
intervals: it won't flag everything z3 can, but needs no external solver and is
always on. The same interval reasoning also flags **contradictions** (rules whose
conditions can never be jointly satisfiable).

## Schema validation

`src/schema.rs` type-checks the typed context Aria's rules read. If a rule
referenced `dlp_facts.pii_confidence` as a string, or `args.amount` under the
wrong nesting, the mismatch is caught before the policy ships, including nested
records.

## In CI

A practical gate: fail the build if a refactor changes any decision, or if a rule
is provably dead.

```sh
cargo test --features smt analysis     # your equivalence/reachability assertions
```

Wrap your before/after policies in a test that asserts
`conditions_equivalent(old, new) == Some(true)` for the rules you intend to keep
identical, for example when refactoring Aria's `pii`/`clean` boundary.
