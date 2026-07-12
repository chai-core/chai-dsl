//! Browser-callable WASM export (feature = `wasm`), no wasm-bindgen.
//!
//! Compiles the real engine to a raw C-ABI WASM module so the playground runs the
//! exact production decision logic. It is the same code, so the proofs and
//! differential tests still apply. Hand-written JS glue in `integrations/playground`
//! passes strings across the boundary. Skipping wasm-bindgen avoids the toolchain
//! version dance. Build:
//!   cargo build --release --target wasm32-unknown-unknown --features wasm

use crate::embed::evaluate_json;
use std::alloc::{alloc as rust_alloc, dealloc, Layout};

/// Allocate `len` bytes in the WASM heap for the JS side to write strings into.
#[no_mangle]
pub extern "C" fn chai_alloc(len: usize) -> *mut u8 {
    unsafe { rust_alloc(Layout::from_size_align(len.max(1), 1).unwrap()) }
}

/// Free a buffer previously returned by `chai_alloc` / `chai_evaluate`.
#[no_mangle]
pub extern "C" fn chai_free(ptr: *mut u8, len: usize) {
    unsafe { dealloc(ptr, Layout::from_size_align(len.max(1), 1).unwrap()) }
}

/// Evaluate `policy` against `context`, both UTF-8. Returns a pointer to a
/// `[u32-LE length][utf8 json]` buffer. The caller reads the length, then the
/// bytes, then frees it. Total and fail-closed, no panic crosses the boundary.
#[no_mangle]
pub extern "C" fn chai_evaluate(p_ptr: *const u8, p_len: usize, c_ptr: *const u8, c_len: usize) -> *mut u8 {
    let policy = std::str::from_utf8(unsafe { std::slice::from_raw_parts(p_ptr, p_len) }).unwrap_or("");
    let context = std::str::from_utf8(unsafe { std::slice::from_raw_parts(c_ptr, c_len) }).unwrap_or("{}");
    let bytes = evaluate_json(policy, context).into_bytes();
    let len = bytes.len() as u32;
    let out = chai_alloc(4 + bytes.len());
    unsafe {
        std::ptr::copy_nonoverlapping(len.to_le_bytes().as_ptr(), out, 4);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(4), bytes.len());
    }
    out
}
