/**
 * Chai PDP client for TypeScript/JavaScript: call the sidecar from any Node service.
 *
 *   import { ChaiClient } from "./chai-client.ts";
 *   const chai = new ChaiClient("http://127.0.0.1:8731");
 *   if (!(await chai.allowed({ subjectUid: "Agent::a1", subjectAttrs: { trust_tier: 4 }, tool: "db.write" })))
 *     throw new Error("policy denied");
 *
 * Every call is FAIL-CLOSED: any error returns Deny / drop, never an allow.
 */
export interface Decision {
  effect: string;
  reason: string;
  rule_trace?: string[];
  errors?: string[];
}

export interface ResultDecision {
  action: string; // emit | redact | drop | buffer | require_human
  released: string | null;
  effect: string;
  reason: string;
}

export interface AuthorizeArgs {
  subjectUid: string;
  tool: string;
  subjectAttrs?: Record<string, unknown>;
  args?: Record<string, unknown>;
  resource?: string;
}

export class ChaiClient {
  // Plain fields (not parameter-properties) so Node's type-stripping can run
  // this .ts directly without a compile step.
  private base: string;
  private token?: string;
  private timeoutMs: number;

  constructor(base: string = "http://127.0.0.1:8731", token?: string, timeoutMs: number = 5000) {
    this.base = base.replace(/\/$/, "");
    this.token = token;
    this.timeoutMs = timeoutMs;
  }

  async authorize(o: AuthorizeArgs): Promise<Decision> {
    return this.post(
      "/authorize_tool_call",
      { subject_uid: o.subjectUid, subject_attrs: o.subjectAttrs ?? {}, tool: o.tool, args: o.args ?? {}, resource: o.resource },
      { effect: "Deny", reason: "PDP error (fail-closed)", rule_trace: [], errors: [] },
    );
  }

  async governResult(o: { subjectUid: string; tool: string; result: string; subjectAttrs?: Record<string, unknown> }): Promise<ResultDecision> {
    return this.post(
      "/filter_tool_result",
      { subject_uid: o.subjectUid, subject_attrs: o.subjectAttrs ?? {}, tool: o.tool, result: o.result },
      { action: "drop", released: null, effect: "Deny", reason: "PDP error (fail-closed)" },
    );
  }

  async allowed(o: AuthorizeArgs): Promise<boolean> {
    return (await this.authorize(o)).effect === "Allow";
  }

  /** Convenience over governResult: returns the (possibly ADAPTED/redacted)
   * content to forward for emit/redact, or null when withheld. */
  async govern(o: { subjectUid: string; tool: string; result: string; subjectAttrs?: Record<string, unknown> }): Promise<{ action: string; content: string | null }> {
    const r = await this.governResult(o);
    const content = r.action === "emit" || r.action === "redact" ? r.released : null;
    return { action: r.action, content };
  }

  private async post<T>(path: string, body: unknown, deny: T): Promise<T> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.token) headers["authorization"] = `Bearer ${this.token}`;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const r = await fetch(this.base + path, { method: "POST", headers, body: JSON.stringify(body), signal: ctrl.signal });
      if (!r.ok) return deny; // non-2xx -> fail-closed
      return (await r.json()) as T;
    } catch {
      return deny; // PDP down / timeout -> fail-closed
    } finally {
      clearTimeout(t);
    }
  }
}
