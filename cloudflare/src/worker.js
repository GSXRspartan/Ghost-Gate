import { failClosed, gateFor, json, originMatches, parseGateCatalog } from "./contracts.js";
export { ReplayCoordinator } from "./replay-coordinator.js";

const text = new TextEncoder();
const CHALLENGE_TTL_SECS = 180;
const MAX_PROOF_BYTES = 8 * 1024;
// Bound the wire body as well as the canonical proof. `Request.json()` otherwise buffers an
// attacker-controlled chunked body before the proof-size check below can run.
const MAX_PROOF_REQUEST_BYTES = MAX_PROOF_BYTES + 8 * 1024;
const MAX_PROXY_BODY_BYTES = 64 * 1024;

// Web Tari Universe deliberately runs its dApp container under
// Cross-Origin-Embedder-Policy: require-corp. A cross-origin nested document
// must both permit cross-origin embedding and carry a compatible COEP policy.
// Keep that opt-in limited to the public Privacy Lab documents; it must never
// spill over to authenticated bridge, claim, Telegram, or administrator routes.
function embeddableLabDocument(response) {
  const headers = new Headers(response.headers);
  headers.set("cross-origin-resource-policy", "cross-origin");
  headers.set("cross-origin-embedder-policy", "require-corp");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function catalog(env) {
  try { return parseGateCatalog(env.GG_GATE_CATALOG, { allowLocalHttp: env.GG_LOCAL_DEVELOPMENT === "1" }); }
  catch (error) { return error; }
}

function route(pathname) {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length === 4 && parts[0] === "api" && parts[1] === "tenants" && parts[3] === "gates") return { kind: "gates", tenant: parts[2] };
  if (parts.length === 6 && parts[0] === "api" && parts[1] === "tenants" && parts[3] === "gates") return { kind: parts[5], tenant: parts[2], gateId: parts[4] };
  if (parts.length === 7 && parts[0] === "api" && parts[1] === "tenants" && parts[3] === "gates" && parts[5] === "proof") return { kind: "status", tenant: parts[2], gateId: parts[4], nonce: parts[6] };
  return { kind: "none" };
}

function randomId(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return [...data].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function cookies(request) {
  return Object.fromEntries((request.headers.get("cookie") || "").split(";").map((part) => {
    const [key, ...value] = part.trim().split("="); return [key, value.join("=")];
  }).filter(([key]) => key));
}

function localDevelopment(request, env) {
  if (env.GG_LOCAL_DEVELOPMENT !== "1") return false;
  const { hostname } = new URL(request.url);
  return ["localhost", "127.0.0.1", "[::1]"].includes(hostname);
}

function cookie(name, value, maxAge = null, secure = true) {
  return `${name}=${value}; Path=/; HttpOnly; ${secure ? "Secure; " : ""}SameSite=Strict${maxAge === null ? "" : `; Max-Age=${maxAge}`}`;
}

function cookieNames(request, env) {
  // `__Host-` cookies intentionally cannot work over local HTTP. The only exception is an explicit
  // localhost-only development process; deployments retain the stronger names and Secure flag.
  return localDevelopment(request, env)
    ? { visitor: "gg_visitor", access: "gg_access", nonce: "gg_nonce", secure: false }
    : { visitor: "__Host_gg_visitor", access: "__Host_gg_access", nonce: "__Host_gg_nonce", secure: true };
}

function coordinator(env, gate, nonce) {
  if (!env.REPLAY_COORDINATOR || !env.GG_COORDINATOR_TOKEN) return null;
  // Nonce is random and server-created. The tenant/gate prefix prevents accidental identity
  // overlap even if a random source ever failed catastrophically.
  return env.REPLAY_COORDINATOR.get(env.REPLAY_COORDINATOR.idFromName(`v1:${gate.tenant}:${gate.gateId}:${nonce}`));
}

async function coordinatorCall(env, gate, nonce, action, body) {
  const stub = coordinator(env, gate, nonce);
  if (!stub) return failClosed("durable replay coordination is not configured");
  return stub.fetch(`https://coordinator.internal/${action}`, {
    method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${env.GG_COORDINATOR_TOKEN}` },
    body: JSON.stringify(body),
  });
}

function binding(gate, nonce, visitorSession) {
  return {
    nonce, tenant: gate.tenant, gateId: gate.gateId, relyingSite: gate.relyingSite,
    network: gate.network, resourceAddress: gate.resourceAddress, thresholdRaw: gate.thresholdRaw,
    policyVersion: gate.policyVersion, policyHash: gate.policyHash, visitorSession,
  };
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

async function sha256(value) {
  const bytes = await crypto.subtle.digest("SHA-256", text.encode(value));
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexBytes(value) {
  if (typeof value !== "string" || value.length % 2 || !/^[0-9a-f]+$/i.test(value)) return null;
  return Uint8Array.from(value.match(/../g).map((part) => Number.parseInt(part, 16)));
}

/** Verify the Rust service's HMAC over the complete, canonical verifier response. */
export async function verifyVerifierSignature(response, signature, secret) {
  const bytes = hexBytes(signature);
  if (!bytes || !secret) return false;
  const key = await crypto.subtle.importKey("raw", text.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return crypto.subtle.verify("HMAC", key, bytes, text.encode(canonical(response)));
}

/** Sign the complete server-created verification request before it leaves the Worker.
 *
 * The bearer capability stops an accidental public endpoint; this signature makes a request
 * replayed or fabricated by another network peer useless to the verifier. `proof` is included in
 * the canonical value so no intermediary can substitute browser evidence after reservation.
 */
async function signVerifierRequest(request, secret) {
  if (!secret) return null;
  const key = await crypto.subtle.importKey("raw", text.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const bytes = new Uint8Array(await crypto.subtle.sign("HMAC", key, text.encode(canonical(request))));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function trustedVerify(env, verificationRequest) {
  if (!env.GG_VERIFIER_ORIGIN || !env.GG_VERIFIER_TOKEN || !env.GG_VERIFIER_REQUEST_KEY || !env.GG_VERIFIER_RESPONSE_KEY) return null;
  const requestSignature = await signVerifierRequest(verificationRequest, env.GG_VERIFIER_REQUEST_KEY);
  let response;
  try {
    response = await fetch(`${env.GG_VERIFIER_ORIGIN.replace(/\/$/, "")}/v1/hosted/verify`, {
      method: "POST", redirect: "manual", headers: {
        "content-type": "application/json", authorization: `Bearer ${env.GG_VERIFIER_TOKEN}`,
        "x-gg-verifier-request-signature": requestSignature,
      },
      body: JSON.stringify(verificationRequest),
    });
  } catch { return { verdict: "UNKNOWN" }; }
  let body;
  try { body = await response.json(); } catch { return { verdict: "UNKNOWN" }; }
  const signature = response.headers.get("x-gg-verifier-signature");
  if (!response.ok || !await verifyVerifierSignature(body, signature, env.GG_VERIFIER_RESPONSE_KEY)) return { verdict: "UNKNOWN" };
  return body;
}

function verifierMatches(result, input, proofDigest) {
  return result && ["VERIFIED", "REJECTED", "PENDING", "UNKNOWN"].includes(result.verdict)
    && result.nonce === input.nonce && result.tenant === input.tenant && result.gateId === input.gateId
    && result.relyingSite === input.relyingSite && result.network === input.network
    && result.resourceAddress === input.resourceAddress && result.thresholdRaw === input.thresholdRaw
    && result.policyVersion === input.policyVersion && result.proofDigest === proofDigest
    && typeof result.verificationId === "string" && result.verificationId.length >= 16;
}

function gateAndOrigin(request, gates, match) {
  const gate = gateFor(gates, match.tenant, match.gateId);
  if (!gate) return { error: json(404, { error: "GG: gate is unknown" }) };
  if (!originMatches(request, gate)) return { error: json(403, { error: "GG: relying-site origin mismatch" }) };
  return { gate };
}

function bridgeRoute(method, pathname) {
  if (method === "POST" && /^\/gate\/[^/]+\/(challenge|credential|prove)$/.test(pathname)) return true;
  if (method === "GET" && /^\/gate\/[^/]+$/.test(pathname)) return true;
  if (method === "GET" && /^\/proof\/[^/]+\/status$/.test(pathname)) return true;
  // The Privacy Lab inspector's trace is read-only and scoped to the unguessable attempt id
  // supplied both in its query and header.  It must take the same restricted bridge proxy path as
  // the challenge/proof requests; serving it as a static-asset fallback leaves Technical blank.
  if (method === "GET" && pathname === "/lab/trace") return true;
  return false;
}

function telegramBotUrl(env) {
  if (!env.GG_TELEGRAM_BOT_URL) return null;
  try {
    const url = new URL(env.GG_TELEGRAM_BOT_URL);
    // The bot destination is deployment configuration, never a browser parameter.  Accept only
    // Telegram's canonical HTTPS public link shape; a query, fragment, port, or redirector is
    // not an official bot destination.
    if (url.protocol !== "https:" || url.hostname !== "t.me" || url.port || url.username || url.password
      || !/^\/[A-Za-z0-9_]{5,}$/.test(url.pathname) || url.search || url.hash) return null;
    return url.toString();
  } catch { return null; }
}

async function labGates(env) {
  const gates = catalog(env);
  if (gates instanceof Error) return json(200, { gates: [] });
  const enriched = [];
  for (const g of gates) {
    let symbol = "";
    try {
      const r = await fetch(`${env.GG_VERIFIER_ORIGIN.replace(/\/$/, "")}/gate/${encodeURIComponent(g.gateId)}`, {
        headers: { accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(5000),
      });
      if (r.ok) { const meta = await r.json(); symbol = meta.symbol || ""; }
    } catch { /* bridge unreachable — symbol stays empty */ }
    enriched.push({
      gateId: g.gateId, symbol, resourceAddress: g.resourceAddress, thresholdRaw: g.thresholdRaw,
      divisibility: g.divisibility, network: g.network, proofMode: g.proofMode || "credential",
      policyVersion: g.policyVersion, policyHash: g.policyHash, relyingSite: g.relyingSite,
      activatable: (g.proofMode || "credential") !== "xtm",
      sessionsAvailable: Boolean(env.REPLAY_COORDINATOR && env.GG_COORDINATOR_TOKEN),
      useMode: "both",
    });
  }
  return json(200, { gates: enriched });
}

async function labHealth(env) {
  let bridgeReachable = false;
  const gates = catalog(env);
  const gateIds = gates instanceof Error ? [] : gates.map((g) => g.gateId);
  if (env.GG_VERIFIER_ORIGIN && gateIds.length) {
    try {
      const r = await fetch(`${env.GG_VERIFIER_ORIGIN.replace(/\/$/, "")}/gate/${encodeURIComponent(gateIds[0])}`, {
        headers: { accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(5000),
      });
      bridgeReachable = r.ok;
    } catch { /* unreachable */ }
  }
  return json(200, {
    service: "ghost-gate-bridge", version: "edge-proxy",
    gates: gateIds, live_challenges: 0,
    registry_backed: Boolean(env.REPLAY_COORDINATOR), credential_configured: bridgeReachable,
    xtm_configured: false,
  });
}

async function bridgeProxy(env, request) {
  if (!env.GG_VERIFIER_ORIGIN) return json(503, { error: "GG: bridge origin is not configured" });
  const parsed = new URL(request.url);
  const url = `${env.GG_VERIFIER_ORIGIN.replace(/\/$/, "")}${parsed.pathname}${parsed.search}`;
  const headers = { accept: "application/json" };
  if (request.method !== "GET" && request.method !== "HEAD") {
    headers["content-type"] = "application/json";
  }
  const attempt = request.headers.get("x-gg-attempt");
  if (attempt) headers["x-gg-attempt"] = attempt;
  const init = { method: request.method, headers, redirect: "manual", signal: AbortSignal.timeout(10000) };
  if (request.method !== "GET" && request.method !== "HEAD") {
    const announced = Number(request.headers.get("content-length"));
    if (Number.isFinite(announced) && announced > MAX_PROXY_BODY_BYTES) return json(413, { error: "GG: proxy request is too large" });
    const body = await request.text();
    if (text.encode(body).byteLength > MAX_PROXY_BODY_BYTES) return json(413, { error: "GG: proxy request is too large" });
    init.body = body;
  }
  try {
    const response = await fetch(url, init);
    return new Response(response.body, {
      status: response.status,
      headers: { "content-type": response.headers.get("content-type") || "application/json", "cache-control": "no-store" },
    });
  } catch {
    return json(503, { error: "GG: bridge is unreachable" });
  }
}

export default {
  async fetch(request, env) {
    const parsed = new URL(request.url);
    if (request.method === "GET" && parsed.pathname === "/_edge/health") return json(200, {
      service: "ghost-gate-edge", coordinator: Boolean(env.REPLAY_COORDINATOR && env.GG_COORDINATOR_TOKEN),
      verifier: Boolean(env.GG_VERIFIER_ORIGIN && env.GG_VERIFIER_TOKEN && env.GG_VERIFIER_REQUEST_KEY && env.GG_VERIFIER_RESPONSE_KEY),
    });
    if (request.method === "GET" && parsed.pathname === "/health") return labHealth(env);
    if (request.method === "GET" && parsed.pathname === "/lab/gates") return labGates(env);
    if (request.method === "GET" && parsed.pathname === "/wallet/status") return json(200, { configured: false, reachable: false, note: "wallet daemon is bridge-local; use a browser wallet for credential proofs" });
    // The administrator stays loopback-only until a separately reviewed WebAuthn enrollment and
    // Cloudflare Access design exists.  Do not let an asset fallback or future bridge route make
    // it accidentally public at the Privacy Lab origin.
    if (parsed.pathname === "/admin" || parsed.pathname.startsWith("/admin/")) return json(404, { error: "GG: administrator is not served from this origin" });
    if (bridgeRoute(request.method, parsed.pathname)) return bridgeProxy(env, request);
    if (request.method === "GET" && (parsed.pathname === "/bot" || parsed.pathname === "/bot/")) {
      const bot = telegramBotUrl(env);
      if (bot) return Response.redirect(bot, 302);
      if (!env.ASSETS) return json(503, { error: "GG: Telegram bot destination is not configured" });
      // Cloudflare Assets canonicalizes an HTML file to its directory URL. Fetch the
      // canonical directory directly so /bot and /bot/ return the page instead of a
      // redirect loop through this worker.
      return env.ASSETS.fetch(new Request(new URL("/bot/", request.url), request));
    }
    if (request.method === "GET" && !parsed.pathname.startsWith("/api/") && env.ASSETS) {
      // Cloudflare Assets canonicalizes a directory's `index.html` as a redirect to the
      // directory URL. Fetch that canonical asset path internally so the outer root request
      // remains a 200 at `/` instead of inheriting an unwanted `/lab/` redirect.
      if (parsed.pathname === "/") {
        return embeddableLabDocument(await env.ASSETS.fetch(new Request(new URL("/lab/", request.url), request)));
      }
      if (parsed.pathname === "/lab" || parsed.pathname === "/lab/") {
        return embeddableLabDocument(await env.ASSETS.fetch(request));
      }
      // Telegram's bot historically minted /telegram/join links.  /claim is the concise public
      // alias.  Both serve the same static page and still require a bot-minted single-use token.
      if (parsed.pathname === "/claim" || parsed.pathname === "/claim/" || parsed.pathname === "/telegram/join") {
        // The join page has a canonical directory asset for the same reason as /bot/;
        // direct file fetches are normalized to a redirect by Cloudflare Assets.
        return env.ASSETS.fetch(new Request(new URL("/telegram/join/", request.url), request));
      }
      return env.ASSETS.fetch(request);
    }
    const gates = catalog(env);
    if (gates instanceof Error) return failClosed("hosted gate configuration is invalid");
    const match = route(parsed.pathname);
    if (request.method === "GET" && parsed.pathname === "/api/gates") return json(200, { gates });
    if (match.kind === "gates" && request.method === "GET") return json(200, { gates: gates.filter((gate) => gate.tenant === match.tenant) });
    if (match.kind === "none") return json(404, { error: "GG: route not found" });
    const checked = gateAndOrigin(request, gates, match);
    if (checked.error) return checked.error;
    const gate = checked.gate;
    const allCookies = cookies(request);
    const names = cookieNames(request, env);
    const visitorSession = allCookies[names.visitor] || randomId();

    if (match.kind === "challenge" && request.method === "POST") {
      const nonce = randomId();
      const expiresUnix = Math.floor(Date.now() / 1000) + CHALLENGE_TTL_SECS;
      const response = await coordinatorCall(env, gate, nonce, "issue", { ...binding(gate, nonce, visitorSession), expiresUnix });
      if (!response.ok) return response;
      return json(201, { state: "issued", challenge: {
        nonce, tenant: gate.tenant, gateId: gate.gateId, network: gate.network,
        resourceAddress: gate.resourceAddress, thresholdRaw: gate.thresholdRaw, policyVersion: gate.policyVersion, expiresUnix,
      } }, { "set-cookie": cookie(names.visitor, visitorSession, gate.sessionTtlSecs + CHALLENGE_TTL_SECS, names.secure) });
    }

    if (match.kind === "proof" && request.method === "POST") {
      // Refuse at the service boundary before examining browser evidence when no independently
      // authenticated verifier exists. This keeps an unconfigured deployment unmistakably closed.
      if (!env.GG_VERIFIER_ORIGIN || !env.GG_VERIFIER_TOKEN || !env.GG_VERIFIER_REQUEST_KEY || !env.GG_VERIFIER_RESPONSE_KEY) return failClosed("an authenticated trusted Rust verifier has not been configured");
      const announcedLength = Number(request.headers.get("content-length"));
      if (Number.isFinite(announcedLength) && announcedLength > MAX_PROOF_REQUEST_BYTES) {
        return json(413, { error: "GG: proof request is too large", authorized: false });
      }
      let payload;
      try {
        const raw = await request.text();
        if (text.encode(raw).byteLength > MAX_PROOF_REQUEST_BYTES) return json(413, { error: "GG: proof request is too large", authorized: false });
        payload = JSON.parse(raw);
      } catch { return json(400, { error: "GG: malformed proof request" }); }
      const nonce = typeof payload?.nonce === "string" ? payload.nonce : "";
      if (!/^[0-9a-f]{64}$/i.test(nonce) || canonical(payload?.proof || null).length > MAX_PROOF_BYTES) return json(400, { error: "GG: proof request is invalid" });
      const proofDigest = await sha256(canonical(payload.proof || null));
      const proofJobId = randomId(16);
      const reservation = await coordinatorCall(env, gate, nonce, "reserve", {
        ...binding(gate, nonce, visitorSession), proofJobId, proofDigest,
      });
      let reserved;
      try { reserved = await reservation.clone().json(); } catch { return failClosed("durable replay coordination returned an invalid response"); }
      if (!reservation.ok) return reservation;
      // A same-visitor retry with the exact same evidence returns the original durable job and
      // may safely recontact the verifier. A changed proof is refused by the DO; it cannot turn an
      // ambiguous outcome into another authorization attempt.
      const c = reserved.challenge;
      const verifierInput = {
        nonce: c.nonce, tenant: c.tenant, gateId: c.gateId, relyingSite: c.relyingSite,
        network: c.network, resourceAddress: c.resourceAddress, thresholdRaw: c.thresholdRaw,
        policyVersion: c.policyVersion, proofDigest, proof: { backendState: c.backendState, credential: payload.proof || null },
      };
      const result = await trustedVerify(env, verifierInput);
      if (!verifierMatches(result, verifierInput, proofDigest)) return json(202, { state: "pending", proofId: proofJobId, reason: "verification outcome is unavailable" });
      if (result.verdict === "PENDING" || result.verdict === "UNKNOWN") return json(202, { state: "pending", proofId: proofJobId });
      if (result.verdict === "REJECTED") {
        // A definite rejection is safe to retry against this still-live challenge. Unknown and
        // timeout results never take this release path.
        await coordinatorCall(env, gate, nonce, "release", { ...binding(gate, nonce, visitorSession), proofJobId: reserved.proofJobId });
        return json(403, { state: "rejected", authorized: false, reason: "proof was not eligible" });
      }
      const sessionToken = randomId();
      const sessionExpiresUnix = Math.floor(Date.now() / 1000) + Math.min(gate.sessionTtlSecs, c.backendState.sessionTtlSecs);
      const authorizationId = `gg-auth-${nonce}`;
      const authorized = await coordinatorCall(env, gate, nonce, "authorize", {
        ...binding(gate, nonce, visitorSession), proofJobId: reserved.proofJobId, verificationId: result.verificationId,
        proofDigest, authorizationId, sessionToken, sessionExpiresUnix,
      });
      if (!authorized.ok) return authorized;
      return json(200, { state: "authorized", authorized: true, expiresUnix: sessionExpiresUnix }, {
        cookies: [cookie(names.access, sessionToken, gate.sessionTtlSecs, names.secure), cookie(names.nonce, nonce, gate.sessionTtlSecs, names.secure)],
      });
    }

    if (match.kind === "status" && request.method === "GET") {
      if (!/^[0-9a-f]{64}$/i.test(match.nonce)) return json(404, { error: "GG: proof is unknown" });
      return coordinatorCall(env, gate, match.nonce, "status", binding(gate, match.nonce, visitorSession));
    }

    const nonce = allCookies[names.nonce];
    const sessionToken = allCookies[names.access];
    if (!nonce || !/^[0-9a-f]{64}$/i.test(nonce)) return json(401, { authorized: false, error: "GG: no active session" });
    if (match.kind === "session" && request.method === "GET") return coordinatorCall(env, gate, nonce, "access", { ...binding(gate, nonce, visitorSession), sessionToken });
    if (match.kind === "protected" && request.method === "GET") {
      const decision = await coordinatorCall(env, gate, nonce, "access", { ...binding(gate, nonce, visitorSession), sessionToken });
      if (!decision.ok) return json(401, { authorized: false, error: "GG: protected resource requires an active authorization" });
      return json(200, { protected: true, content: "Ghost Gate protected demonstration resource" });
    }
    if (match.kind === "revoke" && request.method === "POST") {
      const response = await coordinatorCall(env, gate, nonce, "revoke", { ...binding(gate, nonce, visitorSession), sessionToken });
      if (!response.ok) return response;
      return json(200, { revoked: true }, { "set-cookie": cookie(names.access, "", 0, names.secure) });
    }
    if (match.kind === "logout" && request.method === "POST") return json(200, { loggedOut: true }, { "set-cookie": cookie(names.access, "", 0, names.secure) });
    return json(404, { error: "GG: route not found" });
  },
};
