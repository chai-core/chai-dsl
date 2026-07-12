// Smoke test for the TS ChaiClient against a running sidecar (DEMO policy).
//   node test.ts [base_url]      (Node >= 23 runs .ts directly)
import { ChaiClient } from "./chai-client.ts";

const base = process.argv[2] ?? "http://127.0.0.1:8731";
const c = new ChaiClient(base);
let pass = 0,
  total = 0;
function check(name: string, ok: boolean) {
  total++;
  if (ok) pass++;
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${name}`);
}

check("trust>=3 allowed", await c.allowed({ subjectUid: "Agent::a1", subjectAttrs: { trust_tier: 4 }, tool: "db.write" }));
check("trust<3 denied", !(await c.allowed({ subjectUid: "Agent::a1", subjectAttrs: { trust_tier: 1 }, tool: "db.write" })));
check(
  "secret result dropped",
  (await c.governResult({ subjectUid: "Agent::a1", subjectAttrs: { trust_tier: 5 }, tool: "vault.read", result: "password: hunter2" })).action === "drop",
);
const dead = new ChaiClient("http://127.0.0.1:9999");
check("fail-closed on dead PDP", !(await dead.allowed({ subjectUid: "x", subjectAttrs: { trust_tier: 9 }, tool: "t" })));

console.log(`\n${pass}/${total}`);
process.exit(pass === total ? 0 : 1);
