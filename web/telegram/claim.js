/**
 * Telegram join-page logic — M6+ bot-session Sapient flow.
 *
 * The bot creates a session on the bridge (HMAC-authenticated) and sends a
 * ?bot_session={id}&gate={gate} URL to this page. The flow:
 *   1. Build the credential output in the browser wallet (yields substateId);
 *   2. Obtain a signing challenge from the bridge, bound to that substateId;
 *   3. Sign the challenge in the wallet;
 *   4. Submit the proof to the bridge for on-chain verification;
 *   5. The bot polls the bridge and auto-redeems the Verified session.
 *
 * Query params (all set by the bot):
 *   bot_session — the bridge-issued session id (HMAC-minted, server-side)
 *   gate        — which gate to prove (selects the published resource + threshold)
 *
 * The bridge origin is never read from the query string. The deployed page carries
 * the exact trusted bridge origin in a gg-trusted-bridges meta tag, so a forwarded
 * or edited URL cannot redirect proof material to another service.
 */

import { sapientProvider, universeProvider } from "/js/ghost/provider.js";
import { formatAmount } from "/js/ghost/capabilities.js";
import { configuredJoinEndpoints, resolvePublishedGate } from "/telegram/join-endpoints.js";

const $ = (id) => document.getElementById(id);
const step = (name, state) => {
  const li = document.querySelector(`#tg-steps li[data-step="${name}"]`);
  if (li) li.dataset.state = state;
};

const params = new URLSearchParams(window.location.search);
const botSession = params.get("bot_session") || "";
const gate = params.get("gate") || "";
const configured = name => document.querySelector(`meta[name="${name}"]`)?.content || "";
const { bridgeBase: trustedBridgeOrigin, claimUrl } = configuredJoinEndpoints({
  bridgeOrigin: configured("gg-trusted-bridges"),
  claimOrigin: configured("gg-trusted-claims"),
  pageOrigin: location.origin,
});

function fail(message, technical = "") {
  const err = $("tg-error");
  err.hidden = false;
  $("tg-error-heading").textContent = "Verification unavailable";
  $("tg-error-message").textContent = message;
  const detail = $("tg-error-detail");
  detail.hidden = !technical;
  $("tg-error-technical").textContent = technical;
  const a = $("tg-error-action");
  if (a) {
    a.hidden = true;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
  }
  $("tg-line").textContent = "The verification did not complete.";
}

function showRejection(heading, explanation) {
  fail(explanation, heading);
  $("tg-error-heading").textContent = heading;
}

async function post(url, body) {
  const res = await fetch(url, {
    method: "POST", redirect: "error", credentials: "omit",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || `${res.status}`);
  return json;
}

async function main() {
  if (!trustedBridgeOrigin) {
    return fail(
      "This verification page is not configured for the approved Ghost Gate bridge. " +
      "Request a new /join link from the bot.",
      "Configured bridge origin (gg-trusted-bridges) is missing or invalid.",
    );
  }
  if (!botSession) {
    return fail("This page needs a bot session link. Send /join to the bot first.");
  }
  if (!gate) {
    return fail("This join link does not name a gate. Send /join again.");
  }

  // Wait briefly for the wallet extension to inject before probing.
  if (!window.tari) {
    await new Promise((resolve) => {
      let settled = false;
      const done = () => { if (!settled) { settled = true; window.removeEventListener("tari#initialized", done); resolve(); } };
      window.addEventListener("tari#initialized", done);
      setTimeout(done, 1500);
    });
  }
  const candidates = [sapientProvider(), universeProvider()];
  let provider = null;
  let detectedButDisconnected = false;
  for (const p of candidates) {
    try {
      const probe = await p.probe();
      if (probe.available && probe.modes.some((m) => m.mode === "credential")) {
        provider = p;
        break;
      }
      // Extension present but not authorized for this site (error 4100).
      if (probe.available && !probe.capabilities) detectedButDisconnected = true;
    } catch { /* try the next */ }
  }
  if (!provider && detectedButDisconnected) {
    return fail(
      "A Tari wallet (Sapient or Universe) is installed but this page is not connected to it " +
      "yet. Open the Privacy Lab, press Connect wallet to authorize this site, then retry the " +
      "join link.",
    );
  }
  if (!provider) {
    return fail(
      "No Tari browser wallet answered (Sapient extension, or this page opened inside Tari " +
      "Universe). Install/open a wallet on this device and try the join link again.",
    );
  }

  $("tg-line").textContent = `${provider.label} found. Fetching the gate's terms…`;

  // A previously-shielded qualifying output STAYS qualifying: resuming signs over it and
  // never moves funds. The id comes from the wallet's own shield response (persisted as
  // "gg-last-output" when this browser last shielded) — never from a balance display,
  // which proves nothing about any single output's existence. A malformed id is treated
  // as absent: the fresh path below is the honest fallback.
  const remembered = (() => {
    try { return (localStorage.getItem("gg-last-output") || "").trim(); } catch { return ""; }
  })();
  const resumeSubstate = /^utxo_[0-9a-f]{64}_[0-9a-f]{64}$/i.test(remembered) ? remembered : "";

  let substateId;
  if (resumeSubstate) {
    // RESUME path: no shield, no spend. The bridge binds the challenge to the EXISTING
    // output and re-checks existence, unspent status, floor and ownership against chain
    // state — so a stale or spent id fails here exactly as a fresh one would.
    step("output", "done");
    $("tg-line").textContent =
      "Using your existing verified output — nothing new is spent. Approve only the signature when the wallet asks.";
    substateId = resumeSubstate;
  } else {
    // The bot's gate parameter selects one exact published gate. Policy (resource, threshold)
    // comes from the same catalog the Privacy Lab uses — never from the query string.
    let meta;
    try {
      meta = await resolvePublishedGate(gate);
      if (!meta) throw new Error("not registered");
    } catch (e) {
      return fail("The requested gate is not available. Send /join again.", "Gate lookup did not return a published gate.");
    }
    const div = Number(meta.divisibility ?? 0);
    $("tg-line").textContent =
      `Gate ${meta.gateId}: needs at least ${meta.thresholdRaw} raw units` +
      (formatAmount(meta.thresholdRaw, div) ? ` (${formatAmount(meta.thresholdRaw, div)})` : "") +
      `. Approve the proof output in your wallet…`;

    try {
      // Step 1: build the credential output. The substateId is needed to bind the challenge.
      step("output", "active");
      $("tg-line").textContent = "Approve the proof output in your wallet — it is public and permanent.";
      const built = await provider.approveAndBuildProof("credential", {
        resourceAddress: meta.resourceAddress,
        amount: String(BigInt(meta.thresholdRaw)),
        minimumValuePromise: String(BigInt(meta.thresholdRaw)),
        maxFee: "50000",
      });
      if (!built || !built.substateId) {
        throw new Error("the wallet produced no proof artifact to verify");
      }
      substateId = built.substateId;
      // Remember the output so the NEXT join can resume from it instead of shielding again:
      // re-shielding spends funds for nothing.
      try { localStorage.setItem("gg-last-output", substateId); } catch { /* private mode */ }
      step("output", "done");
    } catch (e) {
      if (e && e.code === 4100) return fail("Wallet authorization ended. Send /join to start again.");
      const lc = String(e && e.message ? e.message : e).toLowerCase();
      if (lc.includes("insufficient")) {
        const humanThreshold = meta && formatAmount(meta.thresholdRaw, Number(meta.divisibility ?? 0))
          ? `${formatAmount(meta.thresholdRaw, Number(meta.divisibility ?? 0))} ${meta.symbol || "tokens"}`.trim()
          : "the required threshold";
        return showRejection(
          "Not enough funds.",
          "Your wallet does not hold enough of the required token to pass this gate. " +
          `Reveal at least ${humanThreshold} in a qualifying output and try again with /join.`,
        );
      }
      throw e;
    }
  }

  // Steps 2-5 are one transaction of progress: a failure in any of them is named by the
  // catch below, and the page never reports a success that did not happen.
  try {
  // Step 2: request a signing challenge bound to the specific output.
  step("challenge", "active");
  $("tg-line").textContent = "Requesting a challenge from the bridge…";
  const ch = await post(
    `${trustedBridgeOrigin}/v1/bot/sessions/${encodeURIComponent(botSession)}/challenge`,
    { substate_id: substateId },
  );
  step("challenge", "done");

  // Step 3: sign the bridge's challenge string in the wallet.
  step("sign", "active");
  $("tg-line").textContent = "Sign the gate's challenge in your wallet.";
  // ch.challenge is the full domain-separated challenge string from the bridge. Pass it
  // unchanged — the bridge re-derives the same string when verifying the signature. The
  // resource override names the gate's resource explicitly: the resume path never ran a
  // shield, so this page session was never told the resource any other way.
  const ownership = await provider.signChallenge(substateId, ch.challenge, ch.resource);
  step("sign", "done");

  // Step 4: submit the proof to the bridge for chain verification.
  step("verify", "active");
  $("tg-line").textContent = "The bridge is verifying ownership against chain state…";
  const proofResult = await post(
    `${trustedBridgeOrigin}/v1/bot/sessions/${encodeURIComponent(botSession)}/proof`,
    {
      gate_id: ch.gate_id,
      challenge_nonce: ch.challenge_nonce,
      // session_commitment is a required wire field but is not validated in the bot-session
      // path: the session identity is carried by the session id, not by a per-challenge
      // commitment. Any 64-char hex value satisfies the wire schema.
      session_commitment: "00".repeat(32),
      substate_id: substateId,
      public_key: ownership.publicKey,
      public_nonce: ownership.publicNonce,
      signature: ownership.signature,
    },
  );
  if (!proofResult.verified) {
    throw new Error("the bridge did not verify this proof");
  }
  step("verify", "done");

  // Step 5: THE CLAIM. The bot redeems a Verified session only when the page tells it to:
  // redemption is the operation that returns the Telegram identity, so it is gated on the
  // bot's own endpoint, not on the bridge's. Without this POST the session would sit
  // Verified forever and nobody would be admitted — which is exactly the gap this step closes.
  step("claim", "active");
  $("tg-line").textContent = "Verified against chain state. Asking the bot to complete your admission…";
  if (!claimUrl) {
    return fail(
      "Your proof was verified, but this page does not know the bot's admission endpoint, " +
      "so the join could not be completed. Send /join again.",
      "Configured claim origin (gg-trusted-claims) is missing or invalid.",
    );
  }
  const claimResult = await post(claimUrl, { bot_session_id: botSession });
  if (claimResult.state !== "granted") {
    throw new Error(claimResult.error || "the bot could not complete this admission");
  }
  step("claim", "done");
  $("tg-line").textContent =
    "Verified and admitted — the bot has approved your join request. Check Telegram.";

  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    const lc = msg.toLowerCase();
    if (e && e.code === 4001) {
      return fail("You declined the request in your wallet. Nothing was submitted.");
    }
    if (lc.includes("the bridge did not verify") || lc.includes("refused the proof") || lc.includes("the bridge refused")) {
      return showRejection(
        "Proof rejected.",
        "The bridge could not verify your proof against the chain. " +
        "Make sure your wallet holds the required balance and try again with /join.",
      );
    }
    if (lc.includes("join link expired") || lc.includes("session expired") || lc.includes("unknown or already-consumed")) {
      return showRejection(
        "Verification link expired",
        "This single-use verification link has expired. Return to the Ghost Gate bot and send /join again.",
      );
    }
    fail(
      "The wallet or verification service could not complete this request. Nothing was authorized.",
      msg,
    );
  }
}

window.addEventListener("DOMContentLoaded", main);
