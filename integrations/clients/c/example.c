/*
 * Sample: gate a tool call and govern a tool result through the Chai sidecar.
 *
 * Start the sidecar first (demo policy):
 *   cargo run --features server --example sidecar
 * Then:
 *   make run
 */
#include "chai_client.h"

#include <curl/curl.h>
#include <stdio.h>

static const char *action_name(chai_action a) {
    switch (a) {
        case CHAI_EMIT: return "emit";
        case CHAI_REDACT: return "redact";
        case CHAI_BUFFER: return "buffer";
        case CHAI_REQUIRE_HUMAN: return "require_human";
        default: return "drop";
    }
}

int main(void) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    chai_client chai = {"http://127.0.0.1:8731", NULL /* token */, 5000 /* ms */};

    /* 1. Authorize tool calls (demo policy: trust_tier >= 3 may act). */
    printf("trust 4, db.write -> %s\n",
           chai_allowed(&chai, "Agent::a1", "{\"trust_tier\":4}", "db.write", "{}") ? "ALLOW" : "DENY");
    printf("trust 1, db.write -> %s\n",
           chai_allowed(&chai, "Agent::a1", "{\"trust_tier\":1}", "db.write", "{}") ? "ALLOW" : "DENY");

    /* 2. Govern tool results (fail-closed drop on error). */
    char released[1024];
    chai_action a = chai_govern_result(&chai, "Agent::a1", "{\"trust_tier\":5}",
                                       "vault.read", "password: hunter2", released, sizeof released);
    printf("secret result -> %s\n", action_name(a));

    a = chai_govern_result(&chai, "Agent::a1", "{\"trust_tier\":5}",
                           "db.read", "row count 12", released, sizeof released);
    printf("clean result  -> %s, content=\"%s\"\n", action_name(a), released);

    /* 3. Fail-closed when the PDP is unreachable. */
    chai_client dead = {"http://127.0.0.1:9999", NULL, 1000};
    printf("dead PDP       -> %s\n",
           chai_allowed(&dead, "Agent::a1", "{\"trust_tier\":9}", "db.write", "{}") ? "ALLOW" : "DENY");

    curl_global_cleanup();
    return 0;
}
