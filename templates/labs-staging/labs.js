"use strict";
/**
 * Capability discovery only. This script never constructs a proof, submits a
 * challenge, asks a wallet to sign, or requests a session. Missing providers
 * are reported explicitly rather than hidden behind a fake success state.
 */
(function () {
  var state = document.getElementById("wallet-state");
  var output = document.getElementById("output");
  var lab = document.querySelector('meta[name="gg-lab"]')?.content || "";

  function log(message) {
    output.textContent += (output.textContent ? "\n" : "") + message;
  }

  function describe(provider) {
    if (!provider) return "absent — no wallet provider injected into this frame";
    var parts = [];
    if (provider.isTariWallet) parts.push("Tari wallet bridge");
    if (provider.isEmbedded) parts.push("embedded dApp frame");
    if (typeof provider.request === "function") parts.push("request() available");
    if (typeof provider.tari === "object" && provider.tari) parts.push("window.tari bridge");
    return parts.length ? parts.join(", ") : "object present but no recognized capability";
  }

  async function discover() {
    output.textContent = "";
    state.textContent = "Checking wallet provider…";
    var provider = window.tari || null;
    var result = describe(provider);
    state.textContent = "Wallet provider: " + result;

    if (!provider) {
      log("DIAGNOSTIC: no actual wallet provider was found.");
      log(lab === "ggbp1-l1"
        ? "Expected provider: Tari Universe embedded dApp (tari-dapp-bridge/1) with GGBP-1 v3 capability on Esmeralda."
        : "Expected provider: Sapient Ootle wallet on mainnet (network 0x00).");
      log("No proof, challenge or session was requested.");
      return;
    }

    log("Provider detected: " + result + ".");
    log("Capability discovery only: proof and session routes are intentionally unavailable on this staging edge.");
    if (lab === "ggbp1-l1") {
      log("Required methods: tari_getBalanceProofSubject, tari_requestBalanceProof.");
      log("Origin binding, Esmeralda genesis and 223-byte challenge must be validated by the wallet before any proof.");
    } else {
      log("Mainnet Crypt draft: enabled=false, test_lane=true, chain_generation=0.");
      log("Authenticated consensus verifier is not integrated into this Lab's verdict.");
    }

    try {
      var response = await fetch("/lab/gates", { headers: { accept: "application/json" } });
      var gates = await response.json();
      log("Published static gates: " + (gates.gates || []).map(function (g) { return g.gateId; }).join(", "));
    } catch (error) {
      log("Static gate metadata unavailable: " + error.message);
    }
  }

  document.getElementById("discover").addEventListener("click", discover);
  discover();
})();
