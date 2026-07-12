//! Native C ABI (feature = `capi`). Link the cdylib and call the engine
//! in-process from C, C++, Go (cgo), Python (ctypes), and anything else that
//! speaks the C ABI. No sidecar, no HTTP hop. Same engine as the Rust library and
//! the WASM build, so the proofs and differential tests apply unchanged.
//!
//! Build the shared library:
//!   cargo build --release --features capi        # -> target/release/libchai_dsl.{dylib,so}
//!
//! See `integrations/embed/` for the header and per-language samples.

use crate::embed::{evaluate_json, pam_decide_json};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Evaluate `policy` against `context_json` (both NUL-terminated UTF-8). Returns a
/// newly-allocated NUL-terminated JSON string with the decision, or a
/// `{"parse_error": "..."}` object. The caller must free it with
/// [`chai_free_string`]. Total and fail-closed: it never panics across the
/// boundary, and a null or non-UTF-8 input yields a fail-closed error object.
///
/// # Safety
/// `policy` and `context_json` must be valid NUL-terminated C strings or null.
#[no_mangle]
pub extern "C" fn chai_decide(policy: *const c_char, context_json: *const c_char) -> *mut c_char {
    let json = std::panic::catch_unwind(|| {
        let p = to_str(policy);
        let c = to_str(context_json);
        evaluate_json(&p, if c.is_empty() { "{}" } else { &c })
    })
    .unwrap_or_else(|_| r#"{"parse_error":"internal error"}"#.to_string());

    CString::new(json)
        .unwrap_or_else(|_| CString::new(r#"{"parse_error":"nul in output"}"#).unwrap())
        .into_raw()
}

/// Evaluate a PAM guard (`guard_json`, a JSON array of tagged checks) against
/// `context_json`. Returns a newly-allocated `{"pass": true|false}` string; free
/// it with [`chai_free_string`]. Fail-closed: any error yields `{"pass": false,
/// ...}`.
///
/// # Safety
/// `guard_json` and `context_json` must be valid NUL-terminated C strings or null.
#[no_mangle]
pub extern "C" fn chai_pam_decide(guard_json: *const c_char, context_json: *const c_char) -> *mut c_char {
    let json = std::panic::catch_unwind(|| {
        let g = to_str(guard_json);
        let c = to_str(context_json);
        pam_decide_json(if g.is_empty() { "[]" } else { &g }, if c.is_empty() { "{}" } else { &c })
    })
    .unwrap_or_else(|_| r#"{"pass":false,"parse_error":"internal error"}"#.to_string());

    CString::new(json)
        .unwrap_or_else(|_| CString::new(r#"{"pass":false}"#).unwrap())
        .into_raw()
}

/// Free a string returned by [`chai_decide`] or [`chai_pam_decide`].
///
/// # Safety
/// `s` must be a pointer returned by `chai_decide`/`chai_pam_decide`, or null.
#[no_mangle]
pub extern "C" fn chai_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}

/// The engine version, as a static NUL-terminated string. Do not free it.
#[no_mangle]
pub extern "C" fn chai_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

fn to_str(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}
