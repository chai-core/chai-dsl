/*
 * In-process C: all three policy paradigms via the native C ABI, no sidecar.
 *
 * Build the shared library first:
 *   cargo build --release --features capi
 * Then:
 *   make run
 */
#include "chai.h"

#include <stdio.h>

static void show(const char *label, char *json) {
    printf("  %-14s %s\n", label, json);
    chai_free_string(json);
}

int main(void) {
    printf("chai %s, in-process\n\n", chai_version());

    /* 1. Regular: Cedar deny-override (the default). */
    const char *reg =
        "@id(\"untrusted\") forbid when subject.trust_tier < 3\n"
        "@id(\"ok\")        permit when subject.trust_tier >= 3\n";
    puts("deny-override:");
    show("trust 4:", chai_decide(reg, "{\"subject\":{\"trust_tier\":4}}"));
    show("trust 1:", chai_decide(reg, "{\"subject\":{\"trust_tier\":1}}"));

    /* 2. ACL: first-match, order is the control. */
    const char *acl =
        "mode first_match\n"
        "@id(\"allow-read\") permit when action == \"read\"\n"
        "@id(\"deny-all\")   deny   when true\n";
    puts("\nACL (first_match):");
    show("read:", chai_decide(acl, "{\"action\":\"read\"}"));
    show("write:", chai_decide(acl, "{\"action\":\"write\"}"));

    /* 3. PAM: a guard stack of tagged checks. */
    const char *guard =
        "[{\"flag\":\"required\",\"when\":\"subject.trust_tier >= 2\"},"
        " {\"flag\":\"sufficient\",\"when\":\"subject.role == \\\"senior\\\"\"},"
        " {\"flag\":\"sufficient\",\"when\":\"args.amount <= 100\"}]";
    puts("\nPAM guard:");
    show("junior $50:", chai_pam_decide(guard, "{\"subject\":{\"trust_tier\":3,\"role\":\"support\"},\"args\":{\"amount\":50}}"));
    show("junior $9999:", chai_pam_decide(guard, "{\"subject\":{\"trust_tier\":3,\"role\":\"support\"},\"args\":{\"amount\":9999}}"));
    return 0;
}
