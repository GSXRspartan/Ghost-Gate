import { json } from "./contracts.js";

/**
 * One Durable Object per tenant/gate/nonce. SQLite-backed Durable Object storage serializes each
 * object instance, so reserve/authorize transitions are atomic for that replay identity. It is
 * not called directly by browsers: the Worker supplies a secret coordinator token.
 */
export class ReplayCoordinator {
  constructor(state, env) { this.state = state; this.env = env; }

  authorized(request) {
    return Boolean(this.env.GG_COORDINATOR_TOKEN)
      && request.headers.get("authorization") === `Bearer ${this.env.GG_COORDINATOR_TOKEN}`;
  }

  async fetch(request) {
    if (!this.authorized(request)) return json(403, { error: "GG: coordinator caller is not authorized" });
    let body;
    try { body = await request.json(); } catch { return json(400, { error: "GG: invalid coordinator body" }); }
    const existing = await this.state.storage.get("record");
    if (request.method === "POST" && request.url.endsWith("/issue")) {
      if (existing) return json(409, { error: "GG: replay identity already exists" });
      if (!body?.nonce || !body?.tenant || !body?.gate || !body?.visitorSession || !Number.isInteger(body?.network)) {
        return json(400, { error: "GG: incomplete server-created replay binding" });
      }
      const record = { ...body, state: "issued", proofJobId: null, authorizationId: null, sessionToken: null };
      await this.state.storage.put("record", record);
      return json(201, { state: record.state });
    }
    if (!existing) return json(404, { error: "GG: replay identity is unknown" });
    if (existing.expiresUnix < Math.floor(Date.now() / 1000)) return json(409, { error: "GG: challenge has expired" });
    if (request.method === "POST" && request.url.endsWith("/reserve")) {
      if (existing.visitorSession !== body.visitorSession || existing.tenant !== body.tenant
        || existing.gate !== body.gate || existing.relyingSite !== body.relyingSite || existing.network !== body.network) {
        return json(409, { error: "GG: challenge binding mismatch" });
      }
      if (existing.state === "issued") {
        existing.state = "submitted"; existing.proofJobId = body.proofJobId;
        await this.state.storage.put("record", existing);
        return json(200, { state: "reserved", proofJobId: existing.proofJobId });
      }
      if (existing.state === "submitted") return json(202, { state: "pending", proofJobId: existing.proofJobId });
      return json(409, { error: "GG: challenge authorization is final" });
    }
    if (request.method === "POST" && request.url.endsWith("/authorize")) {
      // This route is only reachable after the worker receives an authenticated verifier verdict.
      // It never trusts a browser's claimed balance, account, transaction, or proof metadata.
      if (existing.state === "submitted") {
        existing.state = "authorized"; existing.authorizationId = body.authorizationId; existing.sessionToken = body.sessionToken;
        await this.state.storage.put("record", existing);
        return json(200, { state: "authorized", authorizationId: existing.authorizationId });
      }
      if (existing.state === "authorized" && existing.authorizationId === body.authorizationId) {
        return json(200, { state: "authorized", authorizationId: existing.authorizationId });
      }
      return json(409, { error: "GG: challenge authorization is final" });
    }
    return json(404, { error: "GG: coordinator route not found" });
  }
}
