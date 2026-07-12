# Embed Chai in-process (no sidecar)

Call the engine directly, in your own process, through a stable C ABI. This is the
same engine as the Rust library, the HTTP sidecar, and the WASM playground, so the
proofs and differential tests apply. No HTTP hop.

## Build the shared library

```sh
cargo build --release --features capi     # -> target/release/libchai_dsl.{dylib,so}
```

The ABI is four C functions ([`chai.h`](chai.h)):

```c
char *chai_decide(const char *policy, const char *context_json);       /* run a policy */
char *chai_pam_decide(const char *guard_json, const char *context_json); /* run a PAM guard */
void  chai_free_string(char *s);
const char *chai_version(void);
```

`chai_decide` honors the `mode` directive, so it covers both the default Cedar
deny-override and the ACL `first_match` mode. Everything takes and returns JSON
strings, so a binding is tiny. Every call is total and fail-closed.

## All three paradigms, in every language

Each sample runs regular (deny-override), ACL (`first_match`), and PAM in-process:

| Language | Run |
|---|---|
| Rust | it *is* the library (`use chai_dsl::...`; see `samples/aria.chai`, `samples/egress_acl.chai`, `examples/pam_gate.rs`) |
| C | [`c/`](c/): `cd c && make run` |
| C++ | [`cpp/`](cpp/): `cd cpp && make run` |
| Python (ctypes) | [`python/inproc.py`](python/inproc.py): `python python/inproc.py` |
| Go (cgo) | [`go/`](go/): `cd go && go run .` |

Every one prints the same three-paradigm result:

```
deny-override:      trust 4 -> Allow, trust 1 -> Deny
ACL (first_match):  read    -> Allow, write -> Deny
PAM guard:          junior $50 -> pass, junior $9999 -> fail
```

## Which embedding do I want?

| Embedding | Use |
|---|---|
| **Rust crate** (`chai_dsl`) | in-process, native, lowest latency |
| **C ABI** (this directory) | in-process from C / C++ / Go / Python / anything with an FFI |
| **WASM** (`integrations/playground`) | in the browser or Node |
| **HTTP sidecar** (`integrations/clients`) | any language, out of process, one local hop |

The shared library's install name is an absolute path under `target/release`, so
the samples run without setting `DYLD_LIBRARY_PATH` / `LD_LIBRARY_PATH`. For
distribution, install the library on the loader path and adjust the install name.
