/*
 * Chai PDP client for C: call the sidecar from any C service.
 *
 * Every call is FAIL-CLOSED: any error (PDP down, timeout, non-2xx, unparseable
 * response) returns a deny / drop, never an allow.
 *
 * Depends on libcurl. See the Makefile.
 */
#ifndef CHAI_CLIENT_H
#define CHAI_CLIENT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *base_url; /* e.g. "http://127.0.0.1:8731" */
    const char *token;    /* optional bearer token, or NULL */
    long timeout_ms;      /* request timeout, e.g. 5000 */
} chai_client;

typedef enum {
    CHAI_DROP = 0, /* the fail-closed default; also buffer/require_human map here for "withheld" */
    CHAI_EMIT,
    CHAI_REDACT,
    CHAI_BUFFER,
    CHAI_REQUIRE_HUMAN
} chai_action;

/*
 * Authorize a tool call. `subject_attrs_json` and `args_json` are raw JSON
 * objects (pass NULL for "{}"). Returns 1 if the decision is Allow, else 0.
 * Fail-closed: returns 0 on any error.
 */
int chai_allowed(const chai_client *c,
                 const char *subject_uid,
                 const char *subject_attrs_json,
                 const char *tool,
                 const char *args_json);

/*
 * Govern a tool result. Returns the action. For CHAI_EMIT / CHAI_REDACT the
 * content to forward is copied into `released_out` (NUL-terminated, truncated to
 * `released_cap`); for withheld actions `released_out` is set to "".
 * Fail-closed: returns CHAI_DROP on any error.
 */
chai_action chai_govern_result(const chai_client *c,
                               const char *subject_uid,
                               const char *subject_attrs_json,
                               const char *tool,
                               const char *result,
                               char *released_out,
                               size_t released_cap);

#ifdef __cplusplus
}
#endif

#endif /* CHAI_CLIENT_H */
