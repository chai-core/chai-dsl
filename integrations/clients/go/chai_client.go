// Package chai is a fail-closed client for the Chai sidecar (the Policy Decision
// Point): call it from any Go service.
//
// Every call is FAIL-CLOSED: any error (PDP down, timeout, non-2xx, unparseable
// response) returns a deny / drop, never an allow.
//
//	c := chai.New("http://127.0.0.1:8731", "", 0)
//	if !c.Allowed("Agent::a1", map[string]any{"trust_tier": 4}, "db.write", nil) {
//		return errors.New("policy denied")
//	}
package chai

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Client talks to a running Chai sidecar.
type Client struct {
	base  string
	token string
	hc    *http.Client
}

// New builds a client. token may be "" (no auth); timeout <= 0 means 5s.
func New(baseURL, token string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		hc:    &http.Client{Timeout: timeout},
	}
}

// Decision is the verdict for a tool call.
type Decision struct {
	Effect    string   `json:"effect"`
	Reason    string   `json:"reason"`
	RuleTrace []string `json:"rule_trace"`
	Errors    []string `json:"errors"`
}

// ResultDecision is the verdict for a tool result. Action is one of
// emit | redact | drop | buffer | require_human. Released carries the (possibly
// redacted) content for emit/redact, else nil.
type ResultDecision struct {
	Action   string  `json:"action"`
	Released *string `json:"released"`
	Effect   string  `json:"effect"`
	Reason   string  `json:"reason"`
}

// Authorize a tool call. Fail-closed: a Deny decision on any error.
func (c *Client) Authorize(subjectUID string, subjectAttrs map[string]any, tool string, args map[string]any) Decision {
	if subjectAttrs == nil {
		subjectAttrs = map[string]any{}
	}
	if args == nil {
		args = map[string]any{}
	}
	body := map[string]any{"subject_uid": subjectUID, "subject_attrs": subjectAttrs, "tool": tool, "args": args}
	var d Decision
	if !c.post("/authorize_tool_call", body, &d) {
		return Decision{Effect: "Deny", Reason: "PDP error (fail-closed)"}
	}
	return d
}

// Allowed reports whether the tool call is authorized.
func (c *Client) Allowed(subjectUID string, subjectAttrs map[string]any, tool string, args map[string]any) bool {
	return c.Authorize(subjectUID, subjectAttrs, tool, args).Effect == "Allow"
}

// GovernResult runs a tool result through the engine. Fail-closed: drop on error.
func (c *Client) GovernResult(subjectUID string, subjectAttrs map[string]any, tool, result string) ResultDecision {
	if subjectAttrs == nil {
		subjectAttrs = map[string]any{}
	}
	body := map[string]any{"subject_uid": subjectUID, "subject_attrs": subjectAttrs, "tool": tool, "result": result}
	var d ResultDecision
	if !c.post("/filter_tool_result", body, &d) {
		return ResultDecision{Action: "drop", Effect: "Deny", Reason: "PDP error (fail-closed)"}
	}
	return d
}

// Govern is a convenience over GovernResult: it returns the (possibly redacted)
// content to forward for emit/redact, or nil when the result is withheld.
func (c *Client) Govern(subjectUID string, subjectAttrs map[string]any, tool, result string) (action string, content *string) {
	d := c.GovernResult(subjectUID, subjectAttrs, tool, result)
	if d.Action == "emit" || d.Action == "redact" {
		return d.Action, d.Released
	}
	return d.Action, nil
}

func (c *Client) post(path string, body, out any) bool {
	buf, err := json.Marshal(body)
	if err != nil {
		return false
	}
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(buf))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	return json.NewDecoder(resp.Body).Decode(out) == nil
}
