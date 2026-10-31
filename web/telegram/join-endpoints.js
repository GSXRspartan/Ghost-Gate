import { trustedBase } from "./trusted-url.js";

function isPublishedCredentialGate(gate) {
  if (!gate || typeof gate !== "object"
    || typeof gate.gateId !== "string" || !gate.gateId
    || typeof gate.resourceAddress !== "string" || !gate.resourceAddress
    || typeof gate.thresholdRaw !== "string" || !/^[1-9][0-9]*$/.test(gate.thresholdRaw)
    || !Number.isInteger(gate.divisibility) || gate.divisibility < 0
    || !Number.isInteger(gate.network) || gate.network < 0
    || gate.proofMode !== "credential"
    || (typeof gate.policyVersion !== "string" && typeof gate.policyVersion !== "number")
    || typeof gate.policyHash !== "string" || !/^[0-9a-f]{64}$/i.test(gate.policyHash)
    || typeof gate.relyingSite !== "string") return false;
  try {
    const relyingSite = new URL(gate.relyingSite);
    return relyingSite.protocol === "https:" && relyingSite.origin === gate.relyingSite;
  } catch {
    return false;
  }
}

// The Telegram link's gate parameter is an exact-case selector only. Policy
// values always come from the same published catalog as Privacy Lab.
export function publishedGateFromCatalog(gates, requestedGateId) {
  if (typeof requestedGateId !== "string" || !requestedGateId) return null;
  return (Array.isArray(gates) ? gates : []).find((gate) =>
    isPublishedCredentialGate(gate) && gate.gateId === requestedGateId,
  ) || null;
}

export async function resolvePublishedGate(requestedGateId, fetchImpl = fetch) {
  let response;
  try {
    response = await fetchImpl("/lab/gates", {
      redirect: "error",
      credentials: "omit",
      headers: { accept: "application/json" },
    });
  } catch {
    return null;
  }
  if (!response.ok) return null;
  try {
    return publishedGateFromCatalog((await response.json()).gates, requestedGateId);
  } catch {
    return null;
  }
}

// The bot link is deliberately not an endpoint-discovery mechanism. These two destinations are
// deployment-controlled HTML configuration, validated again before a wallet is contacted.
export function configuredJoinEndpoints({ bridgeOrigin, claimOrigin, pageOrigin }) {
  const bridgeBase = trustedBase(bridgeOrigin, bridgeOrigin, pageOrigin);
  const claimUrl = trustedBase(`${claimOrigin}/claim`, claimOrigin, pageOrigin, { allowPath: true });
  return {
    bridgeBase,
    claimUrl: claimUrl && new URL(claimUrl).pathname === "/claim" ? claimUrl : null,
  };
}
