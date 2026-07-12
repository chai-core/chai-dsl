// In-process C++: all three policy paradigms via the native C ABI, no sidecar.
//
// Build the shared library first (from the repo root):
//   cargo build --release --features capi
// Then:
//   make run
#include "chai.h"

#include <iostream>
#include <string>

// RAII wrapper so returned strings are always freed.
struct Owned {
    char* p;
    explicit Owned(char* q) : p(q) {}
    ~Owned() { chai_free_string(p); }
    std::string str() const { return p ? std::string(p) : std::string(); }
};

static std::string decide(const char* policy, const char* ctx) { return Owned(chai_decide(policy, ctx)).str(); }
static std::string pam(const char* guard, const char* ctx) { return Owned(chai_pam_decide(guard, ctx)).str(); }

int main() {
    std::cout << "chai " << chai_version() << ", in-process\n\n";

    const char* reg =
        "@id(\"untrusted\") forbid when subject.trust_tier < 3\n"
        "@id(\"ok\")        permit when subject.trust_tier >= 3\n";
    std::cout << "deny-override:\n";
    std::cout << "  trust 4: " << decide(reg, "{\"subject\":{\"trust_tier\":4}}") << "\n";
    std::cout << "  trust 1: " << decide(reg, "{\"subject\":{\"trust_tier\":1}}") << "\n";

    const char* acl =
        "mode first_match\n"
        "@id(\"allow-read\") permit when action == \"read\"\n"
        "@id(\"deny-all\")   deny   when true\n";
    std::cout << "\nACL (first_match):\n";
    std::cout << "  read:  " << decide(acl, "{\"action\":\"read\"}") << "\n";
    std::cout << "  write: " << decide(acl, "{\"action\":\"write\"}") << "\n";

    const char* guard =
        "[{\"flag\":\"required\",\"when\":\"subject.trust_tier >= 2\"},"
        " {\"flag\":\"sufficient\",\"when\":\"subject.role == \\\"senior\\\"\"},"
        " {\"flag\":\"sufficient\",\"when\":\"args.amount <= 100\"}]";
    std::cout << "\nPAM guard:\n";
    std::cout << "  junior $50:   " << pam(guard, "{\"subject\":{\"trust_tier\":3,\"role\":\"support\"},\"args\":{\"amount\":50}}") << "\n";
    std::cout << "  junior $9999: " << pam(guard, "{\"subject\":{\"trust_tier\":3,\"role\":\"support\"},\"args\":{\"amount\":9999}}") << "\n";
    return 0;
}
