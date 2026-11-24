/**
 * Isolated, non-authorizing staging edge for the two privacy Labs.
 *
 * Boundaries enforced here, independently of the static pages:
 *  - no Durable Object, no replay authority and no session creation;
 *  - no verifier, bot, claim, admin or fixture route exists;
 *  - /lab/gates is PUBLIC STATIC CONFIGURATION ONLY and describes draft gates;
 *  - every proof/admission route returns 404, so no caller can obtain a grant.
 */
const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-gg-mode": "non-authorizing-staging",
};

const GATES = {
  gates: [
    {
      gateId: "Crypt",
      label: "Mainnet L2 TARI Privacy Lab (draft)",
      network: 0,
      networkHex: "00",
      resourceAddress: "resource_0101010101010101010101010101010101010101010101010101010101010101",
      symbol: "TARI",
      thresholdRaw: "100000000",
      divisibility: 6,
      proofMode: "credential",
      enabled: false,
      testLane: true,
      chainGeneration: 0,
      admissions: false,
      consensusVerifierIntegrated: false,
    },
    {
      gateId: "ggbp1xtm",
      label: "Esmeralda L1 tXTM GGBP-1 Privacy Lab (experimental)",
      network: 38,
      networkHex: "26",
      symbol: "tXTM",
      thresholdRaw: "1000000",
      divisibility: 6,
      proofMode: "ggbp1-v3",
      enabled: false,
      testLane: true,
      chainAuthorizedGrants: false,
      authenticatedChainCheckerIntegrated: false,
    },
  ],
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function denied() {
  return new Response("not found", {
    status: 404,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/_edge/health") {
      return json({
        service: "ghost-gate-labs-staging",
        mode: "non-authorizing",
        admissions: false,
        sessions: false,
        durableObject: false,
        verifier: false,
      });
    }

    // Static, published-only gate metadata. Browser code may display it; it can
    // never turn it into an authorization.
    if (path === "/lab/gates" && request.method === "GET") return json(GATES);

    // No route below can issue an admission, mint a session, redeem a Telegram
    // approval, reach the bot/admin plane, or submit a proof.
    if (
      /^\/(v1|proof|claim|admin|gate|bot|telegram\/claim|fixture)(\/|$)/.test(path) ||
      /^\/lab\/(challenge|proof|session|credential|verify|grant)/.test(path) ||
      request.method !== "GET" && request.method !== "HEAD"
    ) {
      return denied();
    }

    return env.ASSETS.fetch(request);
  },
};
