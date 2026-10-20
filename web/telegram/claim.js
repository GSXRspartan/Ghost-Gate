/**
 * Telegram join-page logic.
 *
 * Runs the credential flow for the gate the bot's link named, then claims the join token at the
 * bot's endpoint. The bot re-verifies the receipt against the bridge itself, so this page cannot
 * grant anything by lying — and it doesn't try.
 *
 * Query params (all minted by the bot):
 *   token — the single-use join token
 *   gate  — which registered gate to prove (e.g. "crypt")
 *   claim — the bot's claim endpoint base URL (its own origin; the bot's CORS names ours exactly)
 */

import { sapientProvider, universeProvider } from "/js/ghost/provider.js";
import { formatAmount } from "/js/ghost/capabilities.js";

const $ = (id) => document.getElementById(id);
const step = (name, state) => {
  const li = document.querySelector(`#tg-steps li[data-step="${name}"]`);
  if (li) li.dataset.state = state;
};

const params = new URLSearchParams(window.location.search);
const token = params.get("token") || "";
const gate = params.get("gate") || "crypt";
// The claim endpoint is the bot's origin. Validated against https and loopback http only: a join
// link that points your proof receipt at an arbitrary host is a leak vector, and the bot mints
// these links itself — a tampered one is refused here before any wallet is involved.
const claimRaw = params.get("claim") || "";
const claimUrl = (() => {
  try {
    const u = new URL(claimRaw);
    const loopback = u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]" || u.hostname === "::1";
    if (u.protocol === "https:" || (u.protocol === "http:" && loopback)) {
      return `${u.protocol}//${u.host}${u.pathname.replace(/\/$/, "")}`;
    }
  } catch { /* fall through */ }
  return null;
})();

function fail(message) {
  const err = $("tg-error");
  err.hidden = false;
  err.textContent = message;
  $("tg-line").textContent = "The verification did not complete.";
}

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || `${res.status}`);
  return json;
}

async function main() {
  if (!token) return fail("This page needs a join link from the bot. Send /join there first.");
  if (!claimUrl) {
    return fail(
      `The join link's claim endpoint is not acceptable (${claimRaw || "missing"}). ` +
      "Re-request the link with /join — links are minted by the bot and point at the local bridge.",
    );
  }

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
  for (const p of candidates) {
    try {
      const probe = await p.probe();
      if (probe.available && probe.modes.some((m) => m.mode === "credential")) {
        provider = p;
        break;
      }
    } catch { /* try the next */ }
  }
  if (!provider) {
    return fail(
      "No Tari browser wallet answered (Sapient extension, or this page opened inside Tari " +
      "Universe). Install/open a wallet on this device and try the join link again.",
    );
  }

  $("tg-line").textContent = `${provider.label} found. Fetching the gate's terms…`;

  // The gate's resource and threshold come from the bridge — the page has no opinion.
  let meta;
  try {
    meta = await fetch(`/gate/${encodeURIComponent(gate)}`).then((r) => r.json());
    if (!meta.resource_address) throw new Error(meta.error || "not registered");
  } catch (e) {
    return fail(`The gate ${gate} is not available on this bridge: ${e && e.message ? e.message : e}`);
  }
  const div = Number(meta.divisibility ?? 0);
  $("tg-line").textContent =
    `Gate ${gate}: needs at least ${meta.threshold} raw units` +
    (formatAmount(meta.threshold, div) ? ` (${formatAmount(meta.threshold, div)})` : "") +
    `. A fresh challenge is being issued…`;

  try {
    step("challenge", "active");
    const ch = await post(`/gate/${gate}/challenge`, {});
    step("challenge", "done");

    step("output", "active");
    $("tg-line").textContent = "Approve the proof output in your wallet — it is public and permanent.";
    const built = await provider.approveAndBuildProof("credential", {
      resourceAddress: meta.resource_address,
      amount: String(BigInt(meta.threshold)),
      minimumValuePromise: String(BigInt(meta.threshold)),
      maxFee: "5000",
    });

    step("output", "done");
    step("sign", "active");
    $("tg-line").textContent = "Now sign the gate's challenge in your wallet.";
    const ownership = await provider.signChallenge(built.substateId, ch.challenge_nonce);
    step("sign", "done");

    step("verify", "active");
    $("tg-line").textContent = "The bridge is verifying against chain state…";
    const verdict = await post(`/gate/${gate}/credential`, {
      gate_id: gate,
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
    const claimRes = await fetch(`${claimUrl}/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, proof_id: verdict.proof_id }),
    });
    const claim = await claimRes.json();
    if (claim.state !== "granted") {
      throw new Error(claim.error || "the bot refused the claim");
    }
    step("claim", "done");
    $("tg-line").textContent =
      "Verified and claimed. Check Telegram — the bot has sent you a one-seat invite link. " +
      "It expires after a while; the bot will ask for a fresh proof then.";
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    if (e && e.code === 4001) {
      return fail("You declined the request in your wallet. Nothing was submitted.");
    }
    fail(msg);
  }
}

window.addEventListener("DOMContentLoaded", main);
