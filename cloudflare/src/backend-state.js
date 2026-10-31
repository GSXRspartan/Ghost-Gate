const encoder = new TextEncoder();
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}
export async function backendState(env, gate) {
  if (!env.GG_VERIFIER_ORIGIN || !env.GG_VERIFIER_TOKEN || !env.GG_VERIFIER_REQUEST_KEY || !env.GG_VERIFIER_RESPONSE_KEY) throw Error("backend not configured");
  const nonce = [...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, "0")).join("");
  const request = { nonce, tenant: gate.tenant, gateId: gate.gateId, relyingSite: gate.relyingSite,
    network: gate.network, resourceAddress: gate.resourceAddress, thresholdRaw: gate.thresholdRaw,
    policyVersion: gate.policyVersion, proofDigest: nonce, proof: { hostedState: true } };
  const key = async secret => crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const bytes = new Uint8Array(await crypto.subtle.sign("HMAC", await key(env.GG_VERIFIER_REQUEST_KEY), encoder.encode(canonical(request))));
  const started = Date.now();
  const response = await fetch(`${env.GG_VERIFIER_ORIGIN.replace(/\/$/, "")}/v1/hosted/verify`, { method: "POST", redirect: "error", signal: AbortSignal.timeout(5000),
    headers: { "content-type": "application/json", authorization: `Bearer ${env.GG_VERIFIER_TOKEN}`, "x-gg-verifier-request-signature": [...bytes].map(b => b.toString(16).padStart(2, "0")).join("") }, body: JSON.stringify(request) });
  const body = await response.json();
  const signature = response.headers.get("x-gg-verifier-signature") || "";
  if (!response.ok || !/^[0-9a-f]{64}$/.test(signature) || Date.now() - started > 5000
    || canonical(body.request) !== canonical(request) || !Number.isSafeInteger(body.issuedUnix)
    || Math.abs(Date.now() / 1000 - body.issuedUnix) > 5
    || !await crypto.subtle.verify("HMAC", await key(env.GG_VERIFIER_RESPONSE_KEY), Uint8Array.from(signature.match(/../g), s => parseInt(s,16)), encoder.encode(canonical(body)))
    || !/^[1-9][0-9]*$/.test(body.state?.generation || "") || !/^[0-9a-f]{64}$/.test(body.state?.policyHash || "")
    || typeof body.state?.haltRevision !== "string" || !Number.isSafeInteger(body.state?.sessionTtlSecs) || body.state.sessionTtlSecs < 1) throw Error("backend state unavailable or invalid");
  // A deployment catalog rendered from bindings.json may pin the published policy hash.  The
  // bridge signs this state after resolving the same tenant/gate/version, so a stale or manually
  // mistyped Worker catalog fails closed instead of accepting a different published policy.
  if (gate.policyHash && body.state.policyHash !== gate.policyHash) throw Error("backend policy hash does not match the published catalog");
  return body.state;
}
