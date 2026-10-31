/**
 * Ghost Gate multi-wallet front end.
 *
 * Written once, driven by capabilities. The user picks a wallet; the page asks *that adapter* what
 * it can do; the strongest mode the account actually supports is offered, labelled by name, with
 * the disclosure the user must be able to read before anything prompts. A wallet that supports no
 * mode is shown as unsupported, with the reason — never silently skipped and never degraded.
 *
 * What this page never does, by construction and by review:
 * - asks for a seed phrase, a private key, or a walletd credential from a browser-provider user
 *   (requirement: avoid asking browser users for daemon credentials — those belong to the local
 *   backend's own configuration, not to this page);
 * - displays a balance (the API surface has no field that could carry one);
 * - shows or requests a UTXO inventory (view access is never requested: the credential flow needs
 *   a spend approval, which is its own prompt, and a view grant would expose the whole private
 *   position for no proof benefit);
 * - requests an operation the adapter did not already report as supported.
 */

import { PROOF_MODES, browserProviderGateCompatibility, formatAmount, parseAmount } from "./capabilities.js";
import { sapientProvider, universeProvider, walletdProvider } from "./provider.js";

const BRIDGE_BASE = window.location.origin;

/** The three wallets, in the order the picker shows them. */
const WALLETS = [
  { pick: () => sapientProvider(), blurb: "Browser extension (testnets). Proofs happen in your own wallet." },
  {
    pick: () => universeProvider(),
    blurb: "Runs inside Tari Universe's app catalogue. In a plain tab, its provider is unreachable by design.",
  },
  {
    pick: () => walletdProvider(BRIDGE_BASE),
    blurb: "The developer backend: this bridge drives your local wallet daemon. The consensus-proof path.",
  },
];

const el = (id) => document.getElementById(id);

/* ------------------------------------------------------------------ */
/* Wallet picker                                                       */
/* ------------------------------------------------------------------ */

/**
 * Probes every wallet in parallel and renders the picker with each wallet's own state.
 *
 * The probe is allowed to be slow on first paint (an extension answers fast; an embedded frame
 * may not be there at all), so each card updates as its own probe resolves rather than blocking
 * the whole list behind the slowest answer.
 */
export async function renderWalletPicker() {
  const host = el("wallet-cards");
  host.replaceChildren();
  for (const w of WALLETS) {
    const card = document.createElement("div");
    card.className = "wallet-card";
    card.dataset.wallet = "";
    card.innerHTML =
      `<h3>${""}</h3>` +
      `<p class="hint wallet-blurb"></p>` +
      `<p class="wallet-state hint"></p>` +
      `<ul class="mode-list"></ul>` +
      `<button class="primary wallet-select" hidden>Use this wallet</button>`;
    card.querySelector("h3").textContent = w.pick().label;
    card.querySelector(".wallet-blurb").textContent = w.blurb;
    host.append(card);

    const provider = w.pick();
    // Fire the probe now; fill the card in when it answers.
    probeAndFill(provider, card);
  }
}

async function probeAndFill(provider, card) {
  const gateCompatibility = browserProviderGateCompatibility(currentGate);
  if (!gateCompatibility.ok) {
    card.dataset.wallet = provider.id;
    card.querySelector(".wallet-state").textContent = gateCompatibility.reason;
    card.classList.add("unsupported");
    return;
  }

  let probe;
  try {
    probe = await provider.probe();
  } catch (e) {
    probe = { available: false, unavailableReason: String(e), modes: [], capabilities: null, unusableReason: null };
  }
  card.dataset.wallet = provider.id;

  const state = card.querySelector(".wallet-state");
  const modes = card.querySelector(".mode-list");
  const button = card.querySelector(".wallet-select");
  modes.replaceChildren();

  if (!probe.available) {
    state.textContent = probe.unavailableReason || "Not available here.";
    card.classList.add("unsupported");
    return;
  }
  if (probe.modes.length === 0) {
    state.textContent = probe.unusableReason || "This account supports none of Ghost Gate's proof modes.";
    card.classList.add("unsupported");
    return;
  }

  state.textContent = probe.modes.length === 1 ? "Supported proof mode:" : "Supported proof modes:";
  for (const m of probe.modes) {
    const li = document.createElement("li");
    li.className = "mode-item";
    const name = document.createElement("strong");
    name.textContent = m.label;
    const why = document.createElement("span");
    why.className = "hint";
    why.textContent = m.disclosure;
    li.append(name, why);
    modes.append(li);
  }
  button.hidden = false;
  button.addEventListener("click", () => selectWallet(provider, probe));
}

/* ------------------------------------------------------------------ */
/* Selection + the two flows                                           */
/* ------------------------------------------------------------------ */

/** The gate the page is currently pointed at, and the adapter the user picked. */
let selected = null;

export async function selectWallet(provider, probe) {
  const gateCompatibility = browserProviderGateCompatibility(currentGate);
  if (!gateCompatibility.ok) {
    setOutcome("error", gateCompatibility.reason);
    return;
  }
  selected = { provider, probe };
  el("wallet-line").textContent =
    `${provider.label} — ${probe.modes.map((m) => m.label).join(" or ")}. ` +
    probe.modes.map((m) => m.disclosure).join(" ");
  el("connect").hidden = true;
  el("prove-area").hidden = false;

  // The threshold display already comes from the gate; the proof amount defaults to exactly the
  // threshold. Anything above is the user's call, disclosed on the wallet's own approval screen.
  const gate = currentGate;
  if (provider.id === "walletd") {
    // Mode A is driven entirely by the bridge; the page only reports.
    el("proof-mode-line").textContent = PROOF_MODES.consensus.label + " — " + PROOF_MODES.consensus.disclosure;
    el("credential-fields").hidden = true;
  } else {
    const mode = probe.modes.find((m) => m.mode === "credential");
    el("proof-mode-line").textContent = mode.label + " — " + mode.disclosure;
    el("credential-fields").hidden = false;
    el("proof-amount").value = gate ? String(gate.threshold) : "";
    el("proof-maxfee").value = "5000";
  }
  el("wallet-status-line").textContent = `${provider.label} connected.`;
}

/** Runs the flow for the selected wallet. This is the only place that submits anything. */
export async function runProof() {
  if (!selected) return;
  const gate = currentGate;
  const gateCompatibility = browserProviderGateCompatibility(gate);
  if (!gateCompatibility.ok) {
    setOutcome("error", gateCompatibility.reason);
    return;
  }
  const { provider } = selected;
  const mode = provider.id === "walletd" ? "consensus" : "credential";
  const isConsensus = mode === "consensus";

  setOutcome("working", isConsensus ? "Building the consensus proof…" : "Creating the proof output…");

  try {
    if (isConsensus) {
      const { result } = await provider.approveAndBuildProof(mode, { gateId: gate.id });
      showConsensusOutcome(result);
      return;
    }

    // ---- Mode B: create -> sign -> submit to the bridge for verification ----
    const amount = parseAmount(el("proof-amount").value);
    if (amount === null || amount < BigInt(gate.threshold)) {
      setOutcome("error", `The proof output must carry at least the threshold. This gate needs ${gate.threshold} raw units.`);
      return;
    }
    const built = await provider.approveAndBuildProof(mode, {
      resourceAddress: gate.resource_address,
      amount: amount.toString(),
      minimumValuePromise: String(gate.threshold),
      maxFee: el("proof-maxfee").value || undefined,
    });

    setOutcome("working", "Signing the site's challenge in your wallet…");
    const challenge = await issueChallenge(gate.id);
    const ownership = await provider.signChallenge(built.substateId, challenge.challenge_nonce);

    setOutcome("working", "The bridge is verifying against chain state…");
    const verdict = await submitCredential(gate.id, {
      gate_id: gate.id,
      challenge_nonce: challenge.challenge_nonce,
      session_commitment: challenge.session_commitment,
      substate_id: built.substateId,
      public_key: ownership.publicKey,
      public_nonce: ownership.publicNonce,
      signature: ownership.signature,
    });
    showCredentialOutcome(verdict, built);
  } catch (e) {
    if (e && e.code === 4001) {
      setOutcome("declined", "You declined the request in your wallet. Nothing was submitted.");
      return;
    }
    setOutcome("error", `${e && e.message ? e.message : e}`);
  }
}

function showConsensusOutcome(result) {
  if (result.state === "accepted") {
    setOutcome("granted", "ACCESS GRANTED — the network attested your proof.");
  } else if (result.state === "refused") {
    setOutcome("denied", `ACCESS DENIED — ${result.reason || "the gate refused this proof"}.`);
  } else {
    setOutcome("error", result.reason || "The proof did not complete.");
  }
}

function showCredentialOutcome(verdict, built) {
  if (verdict.state === "accepted") {
    setOutcome(
      "granted",
      "ACCESS GRANTED — verified against the output on chain. " +
        `Attested floor: ${verdict.receipt?.attested_minimum ?? "?"} raw units. ` +
        "This proof names that output; re-using it for another session links them.",
    );
  } else if (verdict && verdict.refused) {
    setOutcome("denied", `ACCESS DENIED — ${verdict.refused}`);
  } else {
    setOutcome("error", `The bridge refused to verify: ${verdict && verdict.refused ? verdict.refused : "unknown"}`);
  }
  if (built.transactionId) {
    provider_lookup_hint(built.transactionId);
  }
}

function provider_lookup_hint(transactionId) {
  const line = el("lookup-line");
  if (!line) return;
  line.textContent = `Proof transaction: ${transactionId} — a committed-result lookup can confirm what the network accepted.`;
}

/* ------------------------------------------------------------------ */
/* Bridge API (same routes the local backend already serves)           */
/* ------------------------------------------------------------------ */

let currentGate = null;

export async function loadGate(id) {
  const res = await fetch(`${BRIDGE_BASE}/gate/${encodeURIComponent(id)}`);
  const gate = await res.json();
  if (!res.ok) throw new Error(gate.error || `gate ${id}: ${res.status}`);
  currentGate = gate;
  selected = null;
  el("asset-symbol").textContent = gate.symbol || "—";
  el("asset-address").textContent = gate.resource_address;
  el("threshold").textContent =
    `${gate.threshold} raw units` +
    (gate.divisibility != null && formatAmount(gate.threshold, gate.divisibility)
      ? ` (${formatAmount(gate.threshold, gate.divisibility)} display)`
      : "");
  el("divisibility").textContent = gate.divisibility ?? "—";
  // Re-render after policy load: wallet availability is a property of the selected gate as well
  // as the wallet. In particular, an L2 provider must never be prompted for a Minotari L1 gate.
  renderWalletPicker();
  return gate;
}

async function issueChallenge(gateId) {
  const res = await fetch(`${BRIDGE_BASE}/gate/${encodeURIComponent(gateId)}/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || `challenge: ${res.status}`);
  return json;
}

async function submitCredential(gateId, body) {
  const res = await fetch(`${BRIDGE_BASE}/gate/${encodeURIComponent(gateId)}/credential`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

/* ------------------------------------------------------------------ */
/* Outcome rendering                                                   */
/* ------------------------------------------------------------------ */

function setOutcome(kind, text) {
  const section = el("outcome");
  section.hidden = false;
  el("outcome-title").textContent =
    kind === "granted" ? "ACCESS GRANTED" :
    kind === "denied" ? "ACCESS DENIED" :
    kind === "declined" ? "REQUEST DECLINED" :
    kind === "error" ? "SOMETHING WENT WRONG" :
    "WORKING…";
  el("outcome-body").textContent = text;
}

/* ------------------------------------------------------------------ */
/* Wire-up                                                             */
/* ------------------------------------------------------------------ */

export function init() {
  const params = new URLSearchParams(window.location.search);
  loadGate(params.get("gate") || "g1").catch((e) => {
    const line = el("wallet-line");
    if (line) line.textContent = `No gate loaded: ${e.message}`;
  });
  el("prove").addEventListener("click", runProof);
  el("again").addEventListener("click", () => {
    el("outcome").hidden = true;
    el("prove-area").hidden = false;
  });
}

// Auto-init only in a browser; the node tests import the functions but never this DOM wiring.
if (typeof window !== "undefined" && document.getElementById("wallet-cards")) {
  window.addEventListener("DOMContentLoaded", init);
}
