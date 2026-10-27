import { sapientProvider, universeProvider } from "./js/ghost/provider.js";
import { describeProviderError, formatAmount, networkVerdict } from "./js/ghost/capabilities.js";

const $ = (id) => document.getElementById(id);
const state = { gates: [], gate: null, providerId: "sapient", provider: null, connected: false, networkOk: false, challenge: null };
const providers = { sapient: sapientProvider, universe: universeProvider };

function api(path, options = {}) {
  return fetch(path, { credentials: "same-origin", ...options }).then(async (response) => {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `${response.status} ${response.statusText}`);
    return body;
  });
}

function setWalletStatus(message, bad = false) {
  $("wallet-status").textContent = message;
  $("wallet-status").classList.toggle("warning", bad);
}

function gatePath(suffix) {
  const gate = state.gate;
  return `/api/tenants/${encodeURIComponent(gate.tenant)}/gates/${encodeURIComponent(gate.gateId)}/${suffix}`;
}

function selectedGate() {
  state.gate = state.gates.find((gate) => `${gate.tenant}/${gate.gateId}` === $("gate").value) || null;
  if (!state.gate) return;
  const threshold = formatAmount(state.gate.thresholdRaw, state.gate.divisibility) ?? state.gate.thresholdRaw;
  $("gate-summary").textContent = `Requires at least ${threshold} tTARI on Esmeralda.`;
  $("gate-detail").replaceChildren(...Object.entries({
    tenant: state.gate.tenant, gate: state.gate.gateId, networkByte: state.gate.network,
    resource: state.gate.resourceAddress, thresholdRaw: state.gate.thresholdRaw,
    policyVersion: state.gate.policyVersion, proofMode: state.gate.proofMode,
  }).flatMap(([key, value]) => [Object.assign(document.createElement("dt"), { textContent: key }), Object.assign(document.createElement("dd"), { textContent: String(value) })]));
  refreshChallengeAvailability();
}

function refreshChallengeAvailability() {
  $("challenge").disabled = !(state.gate && state.connected && state.networkOk);
  $("disconnect").disabled = !state.connected;
  if (!state.connected) $("challenge-status").textContent = "Connect a compatible wallet first.";
}

function disconnect(message = "Wallet connection forgotten in this page. No access was granted.") {
  // Browser extensions own their own connection permissions. This deliberately clears only this
  // page's volatile state, so a switched account can never reuse an old challenge or UI state.
  state.provider = null; state.connected = false; state.networkOk = false; state.challenge = null;
  $("wallet-detail").replaceChildren();
  setWalletStatus(message);
  $("verification-status").textContent = "No authorization has been issued.";
  refreshChallengeAvailability();
}

async function connect() {
  const factory = providers[state.providerId];
  state.provider = factory();
  $("connect").disabled = true;
  setWalletStatus("Waiting for your wallet approval…");
  try {
    // This is the first extension RPC because real Sapient requires user authorization before
    // capability reads. Returned account names/addresses remain in the wallet and this page's RAM.
    const accounts = await state.provider.request("tari_requestAccounts");
    if (!Array.isArray(accounts) || accounts.length === 0) throw new Error("the wallet returned no account");
    const [capabilities, reportedNetwork] = await Promise.all([
      state.provider.request("tari_getCapabilities"), state.provider.request("tari_getNetwork"),
    ]);
    const verdict = networkVerdict(reportedNetwork, state.gate?.network);
    state.connected = true;
    state.networkOk = Boolean(verdict.ok);
    const supported = Object.entries(capabilities || {}).filter(([, value]) => value === true).map(([key]) => key).join(", ") || "none";
    $("wallet-detail").replaceChildren(...Object.entries({ provider: state.provider.label, accounts: accounts.length, reportedNetwork, networkByte: verdict.byte ?? "unknown", capabilities: supported }).flatMap(([key, value]) => [Object.assign(document.createElement("dt"), { textContent: key }), Object.assign(document.createElement("dd"), { textContent: String(value) })]));
    setWalletStatus(verdict.verdict, !verdict.ok);
    refreshChallengeAvailability();
  } catch (error) {
    const detail = describeProviderError(error);
    state.connected = false; state.networkOk = false;
    setWalletStatus(detail.text, true);
    refreshChallengeAvailability();
  } finally { $("connect").disabled = false; }
}

async function checkProtected() {
  if (!state.gate) return;
  $("verification-status").textContent = "Checking the server-side session…";
  try {
    const result = await api(gatePath("protected"));
    $("verification-status").textContent = result.protected
      ? "ACCESS GRANTED: the server validated an active authorization session."
      : "No active authorization session.";
  } catch (error) {
    // A protected route returning 401 is the expected state before a VERIFIED proof. Never make
    // this look like a wallet or challenge failure, and never render it as access.
    $("verification-status").textContent = `Protected area remains unavailable: ${error.message}`;
  }
}

async function logout() {
  if (!state.gate) return;
  try { await api(gatePath("logout"), { method: "POST" }); }
  catch (error) { $("verification-status").textContent = `Logout could not be confirmed: ${error.message}`; return; }
  disconnect("Logged out of this browser. Wallet permissions remain controlled by your wallet.");
}

async function requestChallenge() {
  $("challenge").disabled = true;
  $("challenge-status").textContent = "Issuing a one-time server-bound challenge…";
  try {
    const issued = await api(gatePath("challenge"), { method: "POST" });
    state.challenge = issued.challenge;
    const expires = new Date(issued.challenge.expiresUnix * 1000).toLocaleTimeString();
    $("challenge-status").textContent = `Challenge issued; it expires at ${expires}. No wallet proof or fee was requested.`;
    $("verification-status").textContent = "Challenge is live, but no eligible proof has been submitted.";
    $("submit-proof").disabled = false;
    $("proof-status").textContent = "Challenge ready. Click Submit proof to build and verify your holdings.";
  } catch (error) { $("challenge-status").textContent = error.message; }
  finally { refreshChallengeAvailability(); }
}

async function submitProof() {
  if (!state.challenge || !state.provider || !state.gate) return;
  $("submit-proof").disabled = true;
  $("proof-status").textContent = "Approve the proof output in your wallet — it is public and permanent.";
  try {
    const gate = state.gate;
    const built = await state.provider.approveAndBuildProof("credential", {
      resourceAddress: gate.resourceAddress,
      amount: String(BigInt(gate.thresholdRaw)),
      minimumValuePromise: String(BigInt(gate.thresholdRaw)),
      maxFee: "50000",
    });
    $("proof-status").textContent = "Now sign the gate's challenge in your wallet.";
    const ownership = await state.provider.signChallenge(built.substateId, state.challenge.nonce);
    $("proof-status").textContent = "The bridge is verifying your proof against chain state…";
    const result = await api(gatePath("proof"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        nonce: state.challenge.nonce,
        proof: {
          gate_id: gate.gateId,
          challenge_nonce: state.challenge.nonce,
          substate_id: built.substateId,
          public_key: ownership.publicKey,
          public_nonce: ownership.publicNonce,
          signature: ownership.signature,
          session_commitment: "",
        },
      }),
    });
    if (result.authorized === true && result.state === "authorized") {
      $("proof-status").textContent = "Proof verified — access granted.";
      $("verification-status").textContent = "ACCESS GRANTED: the bridge verified your on-chain proof.";
    } else if (result.state === "pending") {
      $("proof-status").textContent = "Proof submitted and pending. Check back shortly.";
    } else {
      $("proof-status").textContent = `Proof rejected: ${result.verdict || result.refused || "unknown reason"}.`;
    }
    state.challenge = null;
  } catch (error) {
    const msg = error && error.message ? error.message : String(error);
    if (error && error.code === 4001) {
      $("proof-status").textContent = "You declined the request in your wallet. Nothing was submitted.";
    } else {
      $("proof-status").textContent = `Proof failed: ${msg}`;
    }
  }
}

async function init() {
  try {
    const response = await api("/api/gates");
    state.gates = response.gates || [];
    const select = $("gate"); select.replaceChildren();
    for (const gate of state.gates) select.append(Object.assign(document.createElement("option"), { value: `${gate.tenant}/${gate.gateId}`, textContent: `${gate.gateId} — ${gate.thresholdRaw} raw (${gate.proofMode})` }));
    select.disabled = state.gates.length === 0;
    if (state.gates.length) selectedGate(); else $("gate-summary").textContent = "No hosted gates are configured.";
  } catch (error) { $("gate-summary").textContent = `Gate discovery failed: ${error.message}`; }
}

$("gate").addEventListener("change", selectedGate);
$("connect").addEventListener("click", connect);
$("challenge").addEventListener("click", requestChallenge);
$("submit-proof").addEventListener("click", submitProof);
$("disconnect").addEventListener("click", () => disconnect());
$("protected").addEventListener("click", checkProtected);
$("logout").addEventListener("click", logout);
document.querySelectorAll("[data-wallet]").forEach((button) => button.addEventListener("click", () => {
  state.providerId = button.dataset.wallet; disconnect("Wallet provider changed. Previous wallet state and challenge were discarded.");
  document.querySelectorAll("[data-wallet]").forEach((candidate) => candidate.classList.toggle("selected", candidate === button));
  setWalletStatus("Provider selected. Connect to inspect this account's capabilities."); refreshChallengeAvailability();
}));
$("simple-mode").addEventListener("click", () => document.body.className = "simple");
$("technical-mode").addEventListener("click", () => document.body.className = "technical");
init();
