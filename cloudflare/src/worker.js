import { failClosed, gateFor, json, originMatches, parseGateCatalog } from "./contracts.js";
export { ReplayCoordinator } from "./replay-coordinator.js";

function catalog(env) {
  try { return parseGateCatalog(env.GG_GATE_CATALOG); }
  catch (error) { return error; }
}

function route(pathname) {
  const parts = pathname.split("/").filter(Boolean);
  return parts.length === 4 && parts[0] === "api" && parts[1] === "tenants" && parts[3] === "gates"
    ? { kind: "gates", tenant: parts[2] }
    : parts.length === 6 && parts[0] === "api" && parts[1] === "tenants" && parts[3] === "gates"
      ? { kind: parts[5], tenant: parts[2], gateId: parts[4] } : { kind: "none" };
}

export default {
  async fetch(request, env) {
    const parsed = new URL(request.url);
    if (request.method === "GET" && parsed.pathname === "/health") return json(200, { service: "ghost-gate-edge", verifier: Boolean(env.GG_VERIFIER_ORIGIN) });
    const gates = catalog(env);
    if (gates instanceof Error) return failClosed("hosted gate configuration is invalid");
    const match = route(parsed.pathname);
    if (match.kind === "gates" && request.method === "GET") {
      return json(200, { gates: gates.filter((gate) => gate.tenant === match.tenant) });
    }
    if (match.kind === "challenge" || match.kind === "proof" || match.kind === "session") {
      const gate = gateFor(gates, match.tenant, match.gateId);
      if (!gate) return json(404, { error: "GG: gate is unknown" });
      if (!originMatches(request, gate)) return json(403, { error: "GG: relying-site origin mismatch" });
      // The Rust verifier currently has no authenticated hosted deployment contract. Do not proxy
      // browser evidence to it or create a session until one exists; this is intentionally a hard
      // production boundary, not a mock-success path.
      return failClosed("an authenticated trusted Rust verifier has not been configured");
    }
    return json(404, { error: "GG: route not found" });
  },
};
