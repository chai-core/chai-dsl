/*
 * Chai native C ABI: call the engine IN-PROCESS (no sidecar) from any language
 * that speaks C. Link against the cdylib built with the `capi` feature:
 *
 *   cargo build --release --features capi   # -> target/release/libchai_dsl.{dylib,so}
 *
 * Same engine as the Rust library and the WASM build, so the proofs and
 * differential tests apply. Every call is total and fail-closed.
 */
#ifndef CHAI_H
#define CHAI_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Evaluate `policy` against `context_json` (both NUL-terminated UTF-8). Returns a
 * newly-allocated NUL-terminated JSON string, e.g.
 *   {"effect":"Allow","reason":"...","rule_trace":["ok"],"errors":[]}
 * or {"parse_error":"..."} on bad input. Free it with chai_free_string.
 * Never panics across the boundary; null/invalid input yields an error object.
 */
char *chai_decide(const char *policy, const char *context_json);

/*
 * Evaluate a PAM guard against `context_json`. `guard_json` is a JSON array of
 * tagged checks, e.g.
 *   [{"flag":"required","when":"subject.trust_tier >= 2"},
 *    {"flag":"sufficient","when":"args.amount <= 100"}]
 * Returns {"pass":true} or {"pass":false}. Free it with chai_free_string.
 * Fail-closed: any error yields {"pass":false,...}.
 */
char *chai_pam_decide(const char *guard_json, const char *context_json);

/* Free a string returned by chai_decide or chai_pam_decide. */
void chai_free_string(char *s);

/* Engine version as a static NUL-terminated string. Do not free. */
const char *chai_version(void);

#ifdef __cplusplus
}
#endif

#endif /* CHAI_H */
