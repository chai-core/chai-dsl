"""Smoke test for the Python ChaiClient against a running sidecar (DEMO policy).
   PYTHONPATH=. python test_client.py [base_url]"""
import sys
from chai_client import ChaiClient

base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8731"
c = ChaiClient(base)
res = []


def check(name, ok):
    res.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")


check("trust>=3 allowed", c.allowed(subject_uid="Agent::a1", subject_attrs={"trust_tier": 4}, tool="db.write"))
check("trust<3 denied", not c.allowed(subject_uid="Agent::a1", subject_attrs={"trust_tier": 1}, tool="db.write"))
check("secret result dropped",
      c.govern_result(subject_uid="Agent::a1", subject_attrs={"trust_tier": 5}, tool="vault.read",
                      result="password: hunter2")["action"] == "drop")
check("clean result emitted",
      c.govern_result(subject_uid="Agent::a1", subject_attrs={"trust_tier": 5}, tool="db.read",
                      result="row count 12")["action"] == "emit")
check("fail-closed on dead PDP",
      not ChaiClient("http://127.0.0.1:9999").allowed(subject_uid="x", subject_attrs={"trust_tier": 9}, tool="t"))

p = sum(res)
print(f"\n{p}/{len(res)}")
sys.exit(0 if p == len(res) else 1)
