// Sample: gate a tool call and govern a tool result through the Chai sidecar.
//
// Start the sidecar first (demo policy):
//
//	cargo run --features server --example sidecar
//
// Then:
//
//	cd integrations/clients/go && go run ./example
package main

import (
	"fmt"

	"chai"
)

func main() {
	c := chai.New("http://127.0.0.1:8731", "", 0)

	// 1. Authorize tool calls (demo policy: trust_tier >= 3 may act).
	fmt.Printf("trust 4, db.write -> %s\n", verdict(c.Allowed("Agent::a1", map[string]any{"trust_tier": 4}, "db.write", nil)))
	fmt.Printf("trust 1, db.write -> %s\n", verdict(c.Allowed("Agent::a1", map[string]any{"trust_tier": 1}, "db.write", nil)))

	// 2. Govern tool results (fail-closed drop on error).
	action, _ := c.Govern("Agent::a1", map[string]any{"trust_tier": 5}, "vault.read", "password: hunter2")
	fmt.Printf("secret result -> %s\n", action)

	action, content := c.Govern("Agent::a1", map[string]any{"trust_tier": 5}, "db.read", "row count 12")
	fmt.Printf("clean result  -> %s, content=%q\n", action, deref(content))

	// 3. Fail-closed when the PDP is unreachable.
	dead := chai.New("http://127.0.0.1:9999", "", 0)
	fmt.Printf("dead PDP       -> %s\n", verdict(dead.Allowed("Agent::a1", map[string]any{"trust_tier": 9}, "db.write", nil)))
}

func verdict(ok bool) string {
	if ok {
		return "ALLOW"
	}
	return "DENY"
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
