// Resolve a Telegram join link against the same published catalog that powers
// Privacy Lab.  The bot-provided gate id is only an exact-case selector; it
// never supplies policy values or a fallback gate.

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
