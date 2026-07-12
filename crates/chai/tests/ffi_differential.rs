//! §0.2 FFI equivalence: the native C ABI (`chai_decide`) must return verdicts
//! byte-identical to the in-process engine (`embed::evaluate_json`). This extends
//! the byte-identical claim across the FFI boundary, argument marshalling, string
//! ownership, and the `catch_unwind` panic guard, for at least one binding path.
//!
//! Run with: `cargo test --features capi --test ffi_differential`.
#![cfg(feature = "capi")]

use chai_dsl::embed::evaluate_json;
use chai_dsl::ffi::{chai_decide, chai_free_string};
use std::ffi::{CStr, CString};

/// Drive one request through the C ABI exactly as a ctypes/cgo caller would:
/// marshal to C strings, call, copy the result out, and free it.
fn ffi_decide(policy: &str, context_json: &str) -> String {
    let p = CString::new(policy).expect("policy has no interior NUL");
    let c = CString::new(context_json).expect("context has no interior NUL");
    let out = chai_decide(p.as_ptr(), c.as_ptr());
    assert!(!out.is_null(), "chai_decide returned null");
    let s = unsafe { CStr::from_ptr(out) }.to_string_lossy().into_owned();
    chai_free_string(out);
    s
}

/// Request corpus: exercises permit/forbid, the streaming effects, entity-free
/// conditions, effect-tagged errors (§1.1), and malformed policies.
const CORPUS: &[(&str, &str)] = &[
    ("permit when true\n", "{}"),
    ("forbid when true\n", "{}"),
    ("permit when 1 < 2\nforbid when 3 > 4\n", "{}"),
    ("redact when dlp_facts.pii > 0.4\n", "{\"dlp_facts\":{\"pii\":0.9}}"),
    ("defer when review.stage == \"hold\"\n", "{\"review\":{\"stage\":\"hold\"}}"),
    ("require_human when safety.harm > 0.5\n", "{\"safety\":{\"harm\":0.9}}"),
    ("downgrade when label.secret == true\n", "{\"label\":{\"secret\":true}}"),
    // §1.1 effect-tagged error: a strict forbid whose guard errors must deny.
    ("permit when true\nforbid when \"abc\" < 5\n", "{}"),
    // §1.1 lenient annotation keeps the error inert, so the permit wins.
    ("permit when true\ndeny lenient when \"abc\" < 5\n", "{}"),
    // malformed policy: both paths must produce the same parse_error object.
    ("permit whenn nonsense\n", "{}"),
];

#[test]
fn ffi_matches_in_process_on_corpus() {
    for (policy, ctx) in CORPUS {
        let in_process = evaluate_json(policy, ctx);
        let via_ffi = ffi_decide(policy, ctx);
        assert_eq!(
            via_ffi, in_process,
            "FFI verdict diverged from in-process engine for policy:\n{policy}\ncontext: {ctx}"
        );
    }
}

#[test]
fn ffi_null_inputs_are_fail_closed_and_identical() {
    // A null pointer marshals to an empty string on both sides; the ABI must not
    // crash and must agree with evaluating the empty policy.
    let out = chai_decide(std::ptr::null(), std::ptr::null());
    assert!(!out.is_null());
    let via_ffi = unsafe { CStr::from_ptr(out) }.to_string_lossy().into_owned();
    chai_free_string(out);
    assert_eq!(via_ffi, evaluate_json("", "{}"));
}
