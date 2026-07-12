// In-process Go: all three policy paradigms via cgo over the native C ABI.
//
// Build the shared library first (from the repo root):
//
//	cargo build --release --features capi
//
// Then:
//
//	cd integrations/embed/go && go run .
package main

/*
#cgo CFLAGS: -I${SRCDIR}/..
#cgo LDFLAGS: -L${SRCDIR}/../../../target/release -lchai_dsl -Wl,-rpath,${SRCDIR}/../../../target/release
#include <stdlib.h>
#include "chai.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func call(fn func(*C.char, *C.char) *C.char, a, b string) string {
	ca, cb := C.CString(a), C.CString(b)
	defer C.free(unsafe.Pointer(ca))
	defer C.free(unsafe.Pointer(cb))
	out := fn(ca, cb)
	defer C.chai_free_string(out)
	return C.GoString(out)
}

func decide(policy, ctx string) string {
	return call(func(a, b *C.char) *C.char { return C.chai_decide(a, b) }, policy, ctx)
}

func pam(guard, ctx string) string {
	return call(func(a, b *C.char) *C.char { return C.chai_pam_decide(a, b) }, guard, ctx)
}

func main() {
	fmt.Println("chai", C.GoString(C.chai_version()), "in-process")

	reg := "@id(\"untrusted\") forbid when subject.trust_tier < 3\n" +
		"@id(\"ok\")        permit when subject.trust_tier >= 3\n"
	fmt.Println("\ndeny-override:")
	fmt.Println("  trust 4:", decide(reg, `{"subject":{"trust_tier":4}}`))
	fmt.Println("  trust 1:", decide(reg, `{"subject":{"trust_tier":1}}`))

	acl := "mode first_match\n" +
		"@id(\"allow-read\") permit when action == \"read\"\n" +
		"@id(\"deny-all\")   deny   when true\n"
	fmt.Println("\nACL (first_match):")
	fmt.Println("  read: ", decide(acl, `{"action":"read"}`))
	fmt.Println("  write:", decide(acl, `{"action":"write"}`))

	guard := `[{"flag":"required","when":"subject.trust_tier >= 2"},` +
		`{"flag":"sufficient","when":"subject.role == \"senior\""},` +
		`{"flag":"sufficient","when":"args.amount <= 100"}]`
	fmt.Println("\nPAM guard:")
	fmt.Println("  junior $50:  ", pam(guard, `{"subject":{"trust_tier":3,"role":"support"},"args":{"amount":50}}`))
	fmt.Println("  junior $9999:", pam(guard, `{"subject":{"trust_tier":3,"role":"support"},"args":{"amount":9999}}`))
}
