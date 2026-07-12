// Chai PDP client for C++ (header-only): call the sidecar from any C++ service.
//
// Every call is FAIL-CLOSED: any error (PDP down, timeout, non-2xx, unparseable
// response) returns a deny / drop, never an allow.
//
// Depends on libcurl. Compile with `curl-config --cflags --libs`.
#pragma once

#include <curl/curl.h>

#include <cstddef>
#include <string>
#include <utility>

namespace chai {

enum class Action { Drop, Emit, Redact, Buffer, RequireHuman };

struct ResultDecision {
    Action action = Action::Drop;  // fail-closed default
    std::string released;          // content to forward for emit/redact, else empty
};

class Client {
public:
    explicit Client(std::string base = "http://127.0.0.1:8731",
                    std::string token = "", long timeout_ms = 5000)
        : base_(std::move(base)), token_(std::move(token)), timeout_(timeout_ms) {}

    // Authorize a tool call. `subject_attrs_json` / `args_json` are raw JSON
    // objects. Fail-closed: returns false on any error.
    bool allowed(const std::string& subject_uid, const std::string& subject_attrs_json,
                 const std::string& tool, const std::string& args_json = "{}") const {
        std::string body = "{\"subject_uid\":\"" + esc(subject_uid) +
            "\",\"subject_attrs\":" + orEmpty(subject_attrs_json) +
            ",\"tool\":\"" + esc(tool) + "\",\"args\":" + orEmpty(args_json) + "}";
        std::string resp;
        if (!post("/authorize_tool_call", body, resp)) return false;
        return field(resp, "effect") == "Allow";
    }

    // Govern a tool result. Fail-closed: Action::Drop on any error.
    ResultDecision govern_result(const std::string& subject_uid, const std::string& subject_attrs_json,
                                 const std::string& tool, const std::string& result) const {
        std::string body = "{\"subject_uid\":\"" + esc(subject_uid) +
            "\",\"subject_attrs\":" + orEmpty(subject_attrs_json) +
            ",\"tool\":\"" + esc(tool) + "\",\"result\":\"" + esc(result) + "\"}";
        std::string resp;
        ResultDecision d;
        if (!post("/filter_tool_result", body, resp)) return d;  // drop
        const std::string a = field(resp, "action");
        if (a == "emit") d.action = Action::Emit;
        else if (a == "redact") d.action = Action::Redact;
        else if (a == "buffer") d.action = Action::Buffer;
        else if (a == "require_human") d.action = Action::RequireHuman;
        if (d.action == Action::Emit || d.action == Action::Redact)
            d.released = field(resp, "released");
        return d;
    }

private:
    std::string base_, token_;
    long timeout_;

    static size_t write_cb(char* p, size_t s, size_t n, void* ud) {
        static_cast<std::string*>(ud)->append(p, s * n);
        return s * n;
    }

    bool post(const char* path, const std::string& body, std::string& out) const {
        CURL* h = curl_easy_init();
        if (!h) return false;
        const std::string url = base_ + path;
        curl_slist* hdr = curl_slist_append(nullptr, "Content-Type: application/json");
        std::string auth;
        if (!token_.empty()) {
            auth = "Authorization: Bearer " + token_;
            hdr = curl_slist_append(hdr, auth.c_str());
        }
        curl_easy_setopt(h, CURLOPT_URL, url.c_str());
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdr);
        curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(h, CURLOPT_WRITEDATA, &out);
        curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, timeout_ > 0 ? timeout_ : 5000);
        const CURLcode rc = curl_easy_perform(h);
        long code = 0;
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code);
        curl_slist_free_all(hdr);
        curl_easy_cleanup(h);
        return rc == CURLE_OK && code >= 200 && code < 300 && !out.empty();
    }

    static std::string orEmpty(const std::string& j) { return j.empty() ? "{}" : j; }

    static std::string esc(const std::string& s) {
        std::string o;
        o.reserve(s.size() + 8);
        for (char c : s) {
            switch (c) {
                case '"': o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\t': o += "\\t"; break;
                case '\r': o += "\\r"; break;
                default:
                    if (static_cast<unsigned char>(c) >= 0x20) o += c;
                    break;
            }
        }
        return o;
    }

    static std::string field(const std::string& json, const std::string& key) {
        const std::string pat = "\"" + key + "\":\"";
        auto p = json.find(pat);
        if (p == std::string::npos) return "";
        p += pat.size();
        std::string out;
        for (; p < json.size(); ++p) {
            const char c = json[p];
            if (c == '\\' && p + 1 < json.size()) {
                const char e = json[++p];
                out += e == 'n' ? '\n' : e == 't' ? '\t' : e == 'r' ? '\r' : e;
            } else if (c == '"') {
                break;
            } else {
                out += c;
            }
        }
        return out;
    }
};

}  // namespace chai
