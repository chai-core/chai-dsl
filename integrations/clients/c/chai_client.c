#include "chai_client.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct membuf {
    char *data;
    size_t len;
};

static size_t write_cb(char *ptr, size_t sz, size_t nm, void *ud) {
    struct membuf *b = (struct membuf *)ud;
    size_t n = sz * nm;
    char *p = (char *)realloc(b->data, b->len + n + 1);
    if (!p) return 0;
    b->data = p;
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

/* Append a JSON-escaped copy of `s` into buf[*pos..cap-1]. Returns 0 (caller
 * fails closed) if the buffer is too small to hold the whole escaped string. */
static int json_escape(char *buf, size_t cap, size_t *pos, const char *s) {
    for (; s && *s; s++) {
        if (*pos + 2 >= cap) return 0; /* no room for an escape pair plus NUL */
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\') { buf[(*pos)++] = '\\'; buf[(*pos)++] = (char)ch; }
        else if (ch == '\n') { buf[(*pos)++] = '\\'; buf[(*pos)++] = 'n'; }
        else if (ch == '\t') { buf[(*pos)++] = '\\'; buf[(*pos)++] = 't'; }
        else if (ch == '\r') { buf[(*pos)++] = '\\'; buf[(*pos)++] = 'r'; }
        else if (ch >= 0x20) { buf[(*pos)++] = (char)ch; }
        /* other control chars are dropped */
    }
    buf[*pos] = '\0';
    return 1;
}

/* Extract the JSON string value for `key` into out, unescaping \" \\ \n \t \r. */
static int extract_str(const char *json, const char *key, char *out, size_t cap) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = json ? strstr(json, pat) : NULL;
    if (cap) out[0] = '\0';
    if (!p) return 0;
    p += strlen(pat);
    size_t i = 0;
    while (*p && i + 1 < cap) {
        if (*p == '\\' && p[1]) {
            char e = p[1];
            out[i++] = e == 'n' ? '\n' : e == 't' ? '\t' : e == 'r' ? '\r' : e;
            p += 2;
        } else if (*p == '"') {
            break;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = '\0';
    return 1;
}

/* POST `body` to base+path. On a 2xx with a body, fills `resp` (caller frees)
 * and returns 1. Otherwise returns 0, which every caller treats as fail-closed. */
static int post(const chai_client *c, const char *path, const char *body, struct membuf *resp) {
    resp->data = NULL;
    resp->len = 0;
    if (!c || !c->base_url) return 0;
    CURL *h = curl_easy_init();
    if (!h) return 0;

    char url[512];
    snprintf(url, sizeof url, "%s%s", c->base_url, path);

    struct curl_slist *hdr = curl_slist_append(NULL, "Content-Type: application/json");
    char auth[512];
    if (c->token && c->token[0]) {
        snprintf(auth, sizeof auth, "Authorization: Bearer %s", c->token);
        hdr = curl_slist_append(hdr, auth);
    }

    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, c->timeout_ms > 0 ? c->timeout_ms : 5000);

    CURLcode rc = curl_easy_perform(h);
    long code = 0;
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(h);

    if (rc != CURLE_OK || code < 200 || code >= 300 || !resp->data) {
        free(resp->data);
        resp->data = NULL;
        return 0;
    }
    return 1;
}

/* Truncation-guarded appends into the fixed `body` buffer. On overflow the caller
 * returns its fail-closed value (FAIL) rather than overrunning the buffer. Both
 * expect `body` and `pos` in scope. */
#define CHAI_FMT(FAIL, ...)                                                    \
    do {                                                                      \
        int n_ = snprintf(body + pos, sizeof body - pos, __VA_ARGS__);        \
        if (n_ < 0 || (size_t)n_ >= sizeof body - pos) return (FAIL);         \
        pos += (size_t)n_;                                                    \
    } while (0)
#define CHAI_ESC(FAIL, S)                                                      \
    do {                                                                      \
        if (!json_escape(body, sizeof body, &pos, (S))) return (FAIL);        \
    } while (0)

int chai_allowed(const chai_client *c, const char *subject_uid, const char *subject_attrs_json,
                 const char *tool, const char *args_json) {
    char body[4096];
    size_t pos = 0;
    // Every append is truncation-guarded: an over-long input fails closed (deny)
    // rather than overrunning the fixed buffer.
    CHAI_FMT(0, "{\"subject_uid\":\"");
    CHAI_ESC(0, subject_uid);
    CHAI_FMT(0, "\",\"subject_attrs\":%s,\"tool\":\"", subject_attrs_json ? subject_attrs_json : "{}");
    CHAI_ESC(0, tool);
    CHAI_FMT(0, "\",\"args\":%s}", args_json ? args_json : "{}");

    struct membuf resp;
    if (!post(c, "/authorize_tool_call", body, &resp)) return 0; /* fail-closed */
    char effect[32];
    int ok = extract_str(resp.data, "effect", effect, sizeof effect) && strcmp(effect, "Allow") == 0;
    free(resp.data);
    return ok;
}

chai_action chai_govern_result(const chai_client *c, const char *subject_uid, const char *subject_attrs_json,
                               const char *tool, const char *result, char *released_out, size_t released_cap) {
    if (released_out && released_cap) released_out[0] = '\0';
    char body[8192];
    size_t pos = 0;
    // Truncation-guarded appends: an over-long result fails closed (drop).
    CHAI_FMT(CHAI_DROP, "{\"subject_uid\":\"");
    CHAI_ESC(CHAI_DROP, subject_uid);
    CHAI_FMT(CHAI_DROP, "\",\"subject_attrs\":%s,\"tool\":\"", subject_attrs_json ? subject_attrs_json : "{}");
    CHAI_ESC(CHAI_DROP, tool);
    CHAI_FMT(CHAI_DROP, "\",\"result\":\"");
    CHAI_ESC(CHAI_DROP, result);
    CHAI_FMT(CHAI_DROP, "\"}");

    struct membuf resp;
    if (!post(c, "/filter_tool_result", body, &resp)) return CHAI_DROP; /* fail-closed */

    char action[32];
    extract_str(resp.data, "action", action, sizeof action);
    chai_action a = CHAI_DROP;
    if (strcmp(action, "emit") == 0) a = CHAI_EMIT;
    else if (strcmp(action, "redact") == 0) a = CHAI_REDACT;
    else if (strcmp(action, "buffer") == 0) a = CHAI_BUFFER;
    else if (strcmp(action, "require_human") == 0) a = CHAI_REQUIRE_HUMAN;

    if ((a == CHAI_EMIT || a == CHAI_REDACT) && released_out) {
        extract_str(resp.data, "released", released_out, released_cap);
    }
    free(resp.data);
    return a;
}
