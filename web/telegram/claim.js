/**
 * Telegram join-page logic.
 *
 * Runs the credential flow for the gate the bot's link named, then claims the join token at the
 * bot's endpoint. The bot re-verifies the receipt against the bridge itself, so this page cannot
 * grant anything by lying — and it doesn't try.
 *
 * Query params (all minted by the bot):
 *   token  — the single-use join token
 *   gate   — which registered gate to prove (e.g. "crypt")
 *   claim  — the bot's claim endpoint base URL (its own origin; the bot's CORS names ours exactly)
 *   bridge — (optional) the bridge's public URL through the tunnel; when set, gate metadata,
 *            challenges, and credential proofs are sent there instead of the page's own origin
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
const bridgeBase = (() => {
  const raw = params.get("bridge") || "";
  if (!raw) return "";
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:") return "";
    const allowed = document.querySelector('meta[name="gg-trusted-bridges"]');
    if (allowed) {
      const origins = allowed.content.split(",").map((s) => s.trim().toLowerCase());
      if (origins.includes(u.origin.toLowerCase())) return `${u.protocol}//${u.host}`;
      return "";
    }
    const pageParts = location.hostname.toLowerCase().split(".");
    const bridgeParts = u.hostname.toLowerCase().split(".");
    if (pageParts.length >= 2 && bridgeParts.length >= 2) {
      const pageDomain = pageParts.slice(-2).join(".");
      const bridgeDomain = bridgeParts.slice(-2).join(".");
      if (pageDomain === bridgeDomain) return `${u.protocol}//${u.host}`;
    }
    return "";
  } catch { /* fall through */ }
  return "";
})();

function fail(message) {
  const err = $("tg-error");
  err.hidden = false;
  err.textContent = message;
  $("tg-line").textContent = "The verification did not complete.";
}

function showRejection(heading, explanation) {
  $("tg-line").textContent = "";
  const banner = document.createElement("div");
  banner.style.cssText =
    "margin:1.5rem auto;padding:1.5rem;text-align:center;border:2px solid #f44;" +
    "border-radius:12px;background:rgba(255,50,50,0.08);max-width:440px;";
  const h = document.createElement("div");
  h.textContent = heading;
  h.style.cssText = "font-size:1.4rem;font-weight:700;color:#f44;margin-bottom:0.75rem;";
  const p = document.createElement("div");
  p.textContent = explanation;
  p.style.cssText = "font-size:1rem;line-height:1.5;opacity:0.9;";
  banner.appendChild(h);
  banner.appendChild(p);
  $("tg-line").parentNode.insertBefore(banner, $("tg-line").nextSibling);
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

  // The gate's resource and threshold come from the bridge — the page has no opinion.
  let meta;
  try {
    meta = await fetch(`${bridgeBase}/gate/${encodeURIComponent(gate)}`).then((r) => r.json());
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
    const ch = await post(`${bridgeBase}/gate/${gate}/challenge`, {});
    step("challenge", "done");

    step("output", "active");
    $("tg-line").textContent = "Approve the proof output in your wallet — it is public and permanent.";
    const built = await provider.approveAndBuildProof("credential", {
      resourceAddress: meta.resource_address,
      amount: String(BigInt(meta.threshold)),
      minimumValuePromise: String(BigInt(meta.threshold)),
      maxFee: "50000",
    });

    step("output", "done");
    step("sign", "active");
    $("tg-line").textContent = "Now sign the gate's challenge in your wallet.";
    const ownership = await provider.signChallenge(built.substateId, ch.challenge_nonce);
    step("sign", "done");

    step("verify", "active");
    $("tg-line").textContent = "The bridge is verifying against chain state…";
    const verdict = await post(`${bridgeBase}/gate/${gate}/credential`, {
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
      a.rel = "noopener";
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
      return showRejection(
        "Not enough funds.",
        "Your wallet does not hold enough of the required token to pass this gate. " +
        "Unshield more tTARI and try again with /join.",
      );
    }
    if (lc.includes("the bridge refused") || lc.includes("refused the proof")) {
      return showRejection(
        "Proof rejected.",
        "The bridge could not verify your proof against the chain. " +
        "Make sure your wallet holds the required balance and try again with /join.",
      );
    }
    fail(msg);
  }
}

window.addEventListener("DOMContentLoaded", main);
