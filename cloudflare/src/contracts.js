/** Shared, wire-safe contract checks for the hosted edge. */

export function json(status, body, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra },
  });
}

export function failClosed(message = "trusted proof verification is unavailable") {
  return json(503, { error: `GG: ${message}`, authorized: false });
}

export function parseGateCatalog(raw) {
  if (!raw) return [];
  let catalog;
  try { catalog = JSON.parse(raw); } catch { throw new Error("GG_GATE_CATALOG is not valid JSON"); }
  if (!Array.isArray(catalog)) throw new Error("GG_GATE_CATALOG must be an array");
  return catalog.map((gate) => {
    if (!gate || typeof gate !== "object" || typeof gate.tenant !== "string" || typeof gate.gateId !== "string"
      || typeof gate.relyingSite !== "string" || !Number.isInteger(gate.network)) {
      throw new Error("GG_GATE_CATALOG contains an invalid gate");
    }
    // The worker publishes only public policy metadata. It never stores a wallet API token, seed,
    // visitor account name, or server-side wallet selection.
    return {
      tenant: gate.tenant, gateId: gate.gateId, relyingSite: gate.relyingSite,
      network: gate.network, resourceAddress: String(gate.resourceAddress || ""),
      thresholdRaw: String(gate.thresholdRaw || ""), divisibility: Number(gate.divisibility || 0),
      proofMode: String(gate.proofMode || "credential"),
    };
  });
}

export function gateFor(catalog, tenant, gateId) {
  return catalog.find((gate) => gate.tenant === tenant && gate.gateId === gateId) || null;
}

export function originMatches(request, gate) {
  return request.headers.get("origin") === gate.relyingSite;
}
