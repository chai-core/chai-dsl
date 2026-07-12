"""In-process Python: all three policy paradigms via ctypes over the native C ABI.

Build the shared library first (from the repo root):
    cargo build --release --features capi
Then:
    python inproc.py
"""
import ctypes
import json
import os
import platform

_ext = "dylib" if platform.system() == "Darwin" else "so"
_lib_path = os.environ.get("CHAI_LIB") or os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "target", "release", f"libchai_dsl.{_ext}"
)
_lib = ctypes.CDLL(_lib_path)
# Return c_void_p (not c_char_p) so we keep the exact pointer to free.
for fn in (_lib.chai_decide, _lib.chai_pam_decide):
    fn.restype = ctypes.c_void_p
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_lib.chai_free_string.argtypes = [ctypes.c_void_p]
_lib.chai_version.restype = ctypes.c_char_p


def _call(fn, a: str, b: str) -> dict:
    ptr = fn(a.encode(), b.encode())
    out = ctypes.cast(ptr, ctypes.c_char_p).value.decode()
    _lib.chai_free_string(ptr)
    return json.loads(out)


def decide(policy: str, ctx: dict) -> dict:
    return _call(_lib.chai_decide, policy, json.dumps(ctx))


def pam(guard: list, ctx: dict) -> bool:
    return _call(_lib.chai_pam_decide, json.dumps(guard), json.dumps(ctx))["pass"]


print("chai", _lib.chai_version().decode(), "in-process\n")

reg = ('@id("untrusted") forbid when subject.trust_tier < 3\n'
       '@id("ok")        permit when subject.trust_tier >= 3\n')
print("deny-override:")
print("  trust 4:", decide(reg, {"subject": {"trust_tier": 4}})["effect"])
print("  trust 1:", decide(reg, {"subject": {"trust_tier": 1}})["effect"])

acl = ('mode first_match\n'
       '@id("allow-read") permit when action == "read"\n'
       '@id("deny-all")   deny   when true\n')
print("ACL (first_match):")
print("  read: ", decide(acl, {"action": "read"})["effect"])
print("  write:", decide(acl, {"action": "write"})["effect"])

guard = [
    {"flag": "required", "when": "subject.trust_tier >= 2"},
    {"flag": "sufficient", "when": 'subject.role == "senior"'},
    {"flag": "sufficient", "when": "args.amount <= 100"},
]
print("PAM guard:")
print("  junior $50:  ", pam(guard, {"subject": {"trust_tier": 3, "role": "support"}, "args": {"amount": 50}}))
print("  junior $9999:", pam(guard, {"subject": {"trust_tier": 3, "role": "support"}, "args": {"amount": 9999}}))
