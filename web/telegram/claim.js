/**
 * Telegram join-page logic.
 *
 * Runs the credential flow for the gate the bot's link named, then claims the join token at the
 * bot's endpoint. The bot re-verifies the receipt against the bridge itself, so this page cannot
 * grant anything by lying — and it doesn't try.
 *
 * Query params (all minted by the bot):
 *   token  — the single-use join token
 *   gate   — which registered gate to prove (e.g. "Crypt")
 *
 * Claim and bridge destinations are never read from the link. The deployed page carries exact,
 * operator-configured HTTPS origins instead, so a forwarded or edited URL cannot redirect proof
 * material or a claim token to another service.
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
const token = params.get("token") || "";
const gate = params.get("gate") || "";
const configured = name => document.querySelector(`meta[name="${name}"]`)?.content || "";
const { claimUrl, bridgeBase: trustedBridgeOrigin } = configuredJoinEndpoints({
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
  const action = $("tg-error-action");
  if (action) action.hidden = true;
  $("tg-line").textContent = "The verification did not complete.";
}

function showRejection(heading, explanation) {
  fail(explanation, heading);
  $("tg-error-heading").textContent = heading;
}

function showExpiredJoinLink() {
  fail(
    "This single-use verification link has expired. Return to the Ghost Gate bot and send /join again to create a new one.",
    "The bot refused the final claim because this join token is past its server-side expiry.",
  );
  $("tg-error-heading").textContent = "Verification link expired";
  const action = $("tg-error-action");
  if (action) action.hidden = false;
}

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST", redirect: "error", credentials: "omit",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || `${res.status}`);
  return json;
}

async function main() {
  if (!trustedBridgeOrigin || !claimUrl) {
    return fail(
      "This verification page is not configured for the approved Ghost Gate services. Request a new /join link from the bot.",
      "Configured bridge or claim endpoint is missing or invalid.",
    );
  }
  if (!token) return fail("This page needs a join link from the bot. Send /join there first.");
  if (!gate) return fail("This join link does not name a gate. Send /join again.");

  // Which wallet? A browser wallet — this flow is the credential mode. The bridge's own walletd
  // path is not reachable from a Telegram user's browser unless they also run the bridge; if no
  // browser wallet answers, say exactly that.
  // window.tari may not exist at parse time: the extension injects at document_start, the
  // connector on script load. Wait briefly for it (or the tari#initialized event) before probing,
  // so a slow-injecting wallet isn't mistaken for "no wallet installed".
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
      // The extension is present but this site is not authorized yet (4100): a real wallet is
      // sitting right there, so "no wallet answered" would be a lie. Name the actual state.
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

  // The bot's query parameter selects one exact published gate.  The policy itself
  // comes from the same Worker catalog as Privacy Lab, not from the query string or
  // a separately maintained Telegram list.  Browser proof requests stay same-origin
  // through that Worker; the bridge deliberately does not grant arbitrary browser CORS.
  let meta;
  try {
    meta = await resolvePublishedGate(gate);
    if (!meta) throw new Error("not registered");
  } catch (e) {
    return fail("The requested gate is not available. Send /join again.", "Gate lookup did not return a published gate.");
  }
  const gateId = meta.gateId;
  const gatePath = `/gate/${encodeURIComponent(gateId)}`;
  const div = Number(meta.divisibility ?? 0);
  $("tg-line").textContent =
    `Gate ${gateId}: needs at least ${meta.thresholdRaw} raw units` +
    (formatAmount(meta.thresholdRaw, div) ? ` (${formatAmount(meta.thresholdRaw, div)})` : "") +
    `. A fresh challenge is being issued…`;

  try {
    step("challenge", "active");
    const ch = await post(`${gatePath}/challenge`, {});
    step("challenge", "done");

    step("output", "active");
    $("tg-line").textContent = "Approve the proof output in your wallet — it is public and permanent.";
    const built = await provider.approveAndBuildProof("credential", {
      resourceAddress: meta.resourceAddress,
      amount: String(BigInt(meta.thresholdRaw)),
      minimumValuePromise: String(BigInt(meta.thresholdRaw)),
      maxFee: "50000",
    });

    step("output", "done");
    step("sign", "active");
    $("tg-line").textContent = "Now sign the gate's challenge in your wallet.";
    const ownership = await provider.signChallenge(built.substateId, ch.challenge_nonce);
    step("sign", "done");

    step("verify", "active");
    $("tg-line").textContent = "The bridge is verifying against chain state…";
    const verdict = await post(`${gatePath}/credential`, {
      gate_id: gateId,
      challenge_nonce: ch.challenge_nonce,
      session_commitment: ch.session_commitment,
      substate_id: built.substateId,
      public_key: ownership.publicKey,
      public_nonce: ownership.publicNonce,
      signature: ownership.signature,
    });
    if (verdict.state !== "accepted") {
      throw new Error(verdict.refused || "the bridge refused the proof");
    }
    step("verify", "done");

    step("claim", "active");
    $("tg-line").textContent = "Claiming your seat with the bot…";
    const claimRes = await fetch(claimUrl, {
      method: "POST", redirect: "error", credentials: "omit",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, proof_id: verdict.proof_id }),
    });
    const claim = await claimRes.json();
    if (claim.state !== "granted") {
      if (String(claim.error || "").toLowerCase().includes("join link expired")) {
        return showExpiredJoinLink();
      }
      throw new Error(claim.error || "the bot refused the claim");
    }
    step("claim", "done");
    if (claim.admission === "test_only") {
      $("tg-line").textContent =
        "TEST AUTHORIZATION ONLY — the local fixture accepted this proof. No Telegram membership " +
        "and no production access were granted.";
      return;
    }
    const inviteLink = claim.invite_link;
    if (inviteLink) {
      $("tg-line").textContent = "Access authorized — your proof was verified on-chain.";
      const banner = document.createElement("div");
      banner.style.cssText =
        "margin:1.5rem auto;padding:1.5rem;text-align:center;border:2px solid #0f0;" +
        "border-radius:12px;background:rgba(0,255,0,0.08);max-width:400px;";
      const heading = document.createElement("div");
      heading.textContent = "You're in.";
      heading.style.cssText = "font-size:1.4rem;font-weight:700;color:#0f0;margin-bottom:0.75rem;";
      const a = document.createElement("a");
      a.href = inviteLink;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = "Join the group on Telegram";
      a.style.cssText =
        "display:inline-block;padding:0.75rem 2rem;background:#0f0;color:#000;font-weight:700;" +
        "font-size:1.1rem;border-radius:8px;text-decoration:none;";
      const hint = document.createElement("div");
      hint.textContent = "This invite is single-use and bound to your Telegram account.";
      hint.style.cssText = "margin-top:0.75rem;font-size:0.85rem;opacity:0.7;";
      banner.appendChild(heading);
      banner.appendChild(a);
      banner.appendChild(hint);
      $("tg-line").parentNode.insertBefore(banner, $("tg-line").nextSibling);
    } else {
      $("tg-line").textContent =
        "Access authorized. Check Telegram — the bot approves only the Telegram account bound to this proof.";
    }
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    if (e && e.code === 4001) {
      return fail("You declined the request in your wallet. Nothing was submitted.");
    }
    const lc = msg.toLowerCase();
    if (lc.includes("insufficientfunds") || lc.includes("insufficient") || lc.includes("insufficient balance")) {
      const humanThreshold = meta && formatAmount(meta.thresholdRaw, div)
        ? `${formatAmount(meta.thresholdRaw, div)} ${meta.symbol || "tokens"}`.trim()
        : "the required threshold";
      return showRejection(
        "Not enough funds.",
        "Your wallet does not hold enough of the required token to pass this gate. " +
        `Reveal at least ${humanThreshold} in a qualifying output and try again with /join.`,
      );
    }
    if (lc.includes("the bridge refused") || lc.includes("refused the proof")) {
      return showRejection(
        "Proof rejected.",
        "The bridge could not verify your proof against the chain. " +
        "Make sure your wallet holds the required balance and try again with /join.",
      );
    }
    fail("The wallet or verification service could not complete this request. Nothing was authorized.", "The verification flow stopped before a Telegram claim was granted.");
  }
}

window.addEventListener("DOMContentLoaded", main);
