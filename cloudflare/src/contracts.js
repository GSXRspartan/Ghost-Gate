/** Shared, wire-safe contract checks for the hosted edge. */

export function json(status, body, extra = {}) {
  const { cookies, ...headers } = extra;
  const responseHeaders = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
  for (const value of cookies || []) responseHeaders.append("set-cookie", value);
  return new Response(JSON.stringify(body), {
    status,
    headers: responseHeaders,
  });
}

export function failClosed(message = "trusted proof verification is unavailable") {
  return json(503, { error: `GG: ${message}`, authorized: false });
}

export function parseGateCatalog(raw, { allowLocalHttp = false } = {}) {
  if (!raw) return [];
  let catalog;
  try { catalog = JSON.parse(raw); } catch { throw new Error("GG_GATE_CATALOG is not valid JSON"); }
  if (!Array.isArray(catalog)) throw new Error("GG_GATE_CATALOG must be an array");
  return catalog.map((gate) => {
    if (!gate || typeof gate !== "object" || typeof gate.tenant !== "string" || typeof gate.gateId !== "string"
      || typeof gate.relyingSite !== "string" || !Number.isInteger(gate.network)
      || gate.network < 0 || gate.network > 255 || typeof gate.resourceAddress !== "string"
      || !gate.resourceAddress || !/^[0-9]+$/.test(String(gate.thresholdRaw || ""))) {
      throw new Error("GG_GATE_CATALOG contains an invalid gate");
    }
    let relyingOrigin;
    try { relyingOrigin = new URL(gate.relyingSite).origin; } catch { throw new Error("GG_GATE_CATALOG contains an invalid relying site"); }
    const localHttp = relyingOrigin.startsWith("http://")
      && ["localhost", "127.0.0.1", "[::1]"].includes(new URL(gate.relyingSite).hostname);
    if (relyingOrigin !== gate.relyingSite || (!relyingOrigin.startsWith("https://") && !(allowLocalHttp && localHttp))) {
      throw new Error("GG_GATE_CATALOG relying sites must be HTTPS origins (except explicit localhost development)");
    }
    // The worker publishes only public policy metadata. It never stores a wallet API token, seed,
    // visitor account name, or server-side wallet selection.
    return {
      tenant: gate.tenant, gateId: gate.gateId, relyingSite: gate.relyingSite,
      network: gate.network, resourceAddress: String(gate.resourceAddress || ""),
      thresholdRaw: String(gate.thresholdRaw || ""), divisibility: Number(gate.divisibility || 0),
      proofMode: String(gate.proofMode || "credential"),
      // Version and TTL are server configuration, never request fields. A changed version means
      // an old challenge cannot be interpreted as evidence for its replacement policy.
      policyVersion: String(gate.policyVersion || "v1"),
      // The hash is public integrity metadata from bindings.json, not browser input.  Older
      // staging catalogs did not carry it; once present it must agree with the Rust bridge's
      // freshly authenticated state before a hosted challenge or session is usable.
      policyHash: gate.policyHash == null ? null
        : (/^[0-9a-f]{64}$/i.test(String(gate.policyHash)) ? String(gate.policyHash).toLowerCase()
          : (() => { throw new Error("GG_GATE_CATALOG contains an invalid policy hash"); })()),
      sessionTtlSecs: Number.isSafeInteger(gate.sessionTtlSecs) && gate.sessionTtlSecs > 0
        ? gate.sessionTtlSecs : 3600,
    };
  });
}

export function gateFor(catalog, tenant, gateId) {
  return catalog.find((gate) => gate.tenant === tenant && gate.gateId === gateId) || null;
}

export function originMatches(request, gate) {
  const origin = request.headers.get("origin");
  if (origin !== null) return origin === gate.relyingSite;
  // Browsers normally omit Origin on same-origin GET requests. Never infer it for writes.
  return request.method === "GET" && new URL(request.url).origin === gate.relyingSite;
}
