// Sample: gate a tool call and govern a tool result through the Chai sidecar.
//
// Start the sidecar first (demo policy):
//   cargo run --features server --example sidecar
// Then:
//   make run
#include "chai_client.hpp"

#include <curl/curl.h>

#include <iostream>
#include <string>

static const char* name(chai::Action a) {
    switch (a) {
        case chai::Action::Emit: return "emit";
        case chai::Action::Redact: return "redact";
        case chai::Action::Buffer: return "buffer";
        case chai::Action::RequireHuman: return "require_human";
        default: return "drop";
    }
}

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    chai::Client chai("http://127.0.0.1:8731");

    // 1. Authorize tool calls (demo policy: trust_tier >= 3 may act).
    std::cout << "trust 4, db.write -> "
              << (chai.allowed("Agent::a1", "{\"trust_tier\":4}", "db.write") ? "ALLOW" : "DENY") << "\n";
    std::cout << "trust 1, db.write -> "
              << (chai.allowed("Agent::a1", "{\"trust_tier\":1}", "db.write") ? "ALLOW" : "DENY") << "\n";

    // 2. Govern tool results (fail-closed drop on error).
    auto secret = chai.govern_result("Agent::a1", "{\"trust_tier\":5}", "vault.read", "password: hunter2");
    std::cout << "secret result -> " << name(secret.action) << "\n";

    auto clean = chai.govern_result("Agent::a1", "{\"trust_tier\":5}", "db.read", "row count 12");
    std::cout << "clean result  -> " << name(clean.action) << ", content=\"" << clean.released << "\"\n";

    // 3. Fail-closed when the PDP is unreachable.
    chai::Client dead("http://127.0.0.1:9999", "", 1000);
    std::cout << "dead PDP       -> "
              << (dead.allowed("Agent::a1", "{\"trust_tier\":9}", "db.write") ? "ALLOW" : "DENY") << "\n";

    curl_global_cleanup();
    return 0;
}
