/**
 * GHOST GATE — THE HAUNTED VAULT, sanctum logic.
 *
 * Security shape (docs/SECURITY_RELEASE_GATE.md):
 * - A chamber opens only from the bridge's verdict for a proof made in THIS session. There is no
 *   persisted "unlocked" state: reload the page and the doors are sealed again, because an unlock
 *   is a fact about a session, not a fact about this file's storage.
 * - localStorage holds puzzle progress, lore and relics — cosmetic only, labelled as such.
 * - Preview mode is labelled in three places and never calls the challenge/proof/credential
 *   routes; it renders sample states and mints nothing.
 * - The thresholds shown come from the bridge's /gate/:id responses. The page never decides what
 *   a gate requires.
 */

import { sapientProvider, universeProvider, walletdProvider } from "/js/ghost/provider.js";
import { formatAmount } from "/js/ghost/capabilities.js";

const GATES = ["crypt", "vault", "abyss"];
const $ = (id) => document.getElementById(id);

/* ------------------------------- state ------------------------------- */

/**
 * Cosmetic progress only. An `unlockedGates` entry is written in PREVIEW mode and is always
 * displayed with the preview badge; real unlocks live in `session.unlocked` (memory only).
 */
const STORE_KEY = "ghost-gate-vault-progress-v1";
const store = loadStore();

function loadStore() {
  const empty = { relics: {}, secrets: {}, previewUnlocked: [] };
  try {
    const raw = localStorage.getItem(STORE_KEY);
    return raw ? { ...empty, ...JSON.parse(raw) } : empty;
  } catch {
    return empty;
  }
}
function saveStore() {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(store));
  } catch {
    /* storage disabled: cosmetic progress degrades gracefully */
  }
}

/** In-session proof state. Never persisted; this is the only thing that opens a door for real. */
const session = {
  provider: null,
  providerProbe: null,
  unlocked: new Set(),
  inFlight: false,
};

let previewMode = false;

/* ------------------------------- boot ------------------------------- */

window.addEventListener("DOMContentLoaded", () => {
  // "Connect a wallet" lands in the Sanctum and opens the chooser straight away, so the button
  // means what it says. It still only *offers* wallets that can actually prove something.
  $("btn-enter").addEventListener("click", async () => {
    await enterSanctum();
    await chooseWallet();
  });
  $("btn-preview").addEventListener("click", () => enterSanctum(true));
  $("btn-back-title").addEventListener("click", backToTitle);
  $("btn-exit-preview").addEventListener("click", exitPreview);
  $("btn-wallet").addEventListener("click", chooseWallet);
  $("proof-cancel").addEventListener("click", cancelProof);
  $("relic-close").addEventListener("click", closeRelic);
  document.querySelectorAll(".chamber-leave").forEach((b) => b.addEventListener("click", leaveChamber));
  document.querySelectorAll(".secret-glyph").forEach((g) => g.addEventListener("click", () => findSecret(g.dataset.secret)));

  for (const gate of GATES) {
    const door = doorEl(gate);
    door.querySelector(".door-prove").addEventListener("click", () => proveFor(gate));
    door.querySelector(".door-enter").addEventListener("click", () => enterChamber(gate));
  }
  buildCryptPuzzle();
  buildVaultPuzzle();
  buildAbyssPuzzle();

  if (store.relics && Object.keys(store.relics).length || store.secrets && Object.keys(store.secrets).length) {
    renderHud();
  }
});

function doorEl(gate) {
  return document.getElementById(`door-${gate}`);
}

/* ------------------------------- navigation ------------------------------- */

async function enterSanctum(preview = false) {
  $("title-screen").hidden = true;
  $("sanctum").hidden = false;
  previewMode = preview && true;
  $("preview-banner").hidden = !previewMode;
  if (previewMode) {
    // Preview renders sample states. Nothing is verified; the doors open with the preview badge.
    for (const gate of GATES) {
      session.unlocked.delete(gate);
    }
    store.previewUnlocked = [...GATES];
    saveStore();
  }
  await loadGateMetadata();
  renderDoors();
}

function backToTitle() {
  leaveChamber(true);
  $("sanctum").hidden = true;
  $("title-screen").hidden = false;
}

function exitPreview() {
  previewMode = false;
  store.previewUnlocked = [];
  saveStore();
  $("preview-banner").hidden = true;
  for (const gate of GATES) session.unlocked.delete(gate);
  renderDoors();
  $("sanctum-status").textContent = "Preview ended. Connect a wallet to break a seal for real.";
}

function enterChamber(gate) {
  $("sanctum").hidden = true;
  const chamber = document.getElementById(`chamber-${gate}`);
  if (chamber) chamber.hidden = false;
  // The vault dial is laid out in JS from measured pixels, and a hidden element measures 0. Built
  // at page load (while the chamber was hidden) every glyph was placed on a -14px radius, so the
  // rings showed a pile of letters until the first click. Re-measure once the chamber is on screen.
  if (gate === "vault") updateVault(vaultRings, vaultOffsets);
}

function leaveChamber(silent = false) {
  for (const gate of GATES) {
    const c = document.getElementById(`chamber-${gate}`);
    if (c) c.hidden = true;
  }
  if (!silent) $("sanctum").hidden = false;
}

/* ------------------------------- gate metadata ------------------------------- */

/** Thresholds are whatever the bridge reports. The page has no opinion. */
const gateMetadata = {};

function gateMeta(gate) {
  return gateMetadata[gate];
}

async function loadGateMetadata() {
  for (const gate of GATES) {
    const el = doorEl(gate).querySelector(".door-threshold");
    el.textContent = "…";
    try {
      const res = await fetch(`/gate/${encodeURIComponent(gate)}`);
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || res.status);
      const div = Number(json.divisibility ?? 0);
      el.textContent = `${json.threshold} raw units` +
        (formatAmount(json.threshold, div) ? ` (${formatAmount(json.threshold, div)})` : "");
      doorEl(gate).dataset.threshold = json.threshold;
      gateMetadata[gate] = json;
    } catch (e) {
      el.textContent = "gate not registered";
      doorEl(gate).querySelector(".door-prove").disabled = true;
      doorEl(gate).title = String(e && e.message ? e.message : e);
    }
  }
}

function renderDoors() {
  for (const gate of GATES) {
    const door = doorEl(gate);
    const unlockedForReal = session.unlocked.has(gate);
    const unlockedInPreview = previewMode && store.previewUnlocked.includes(gate);
    const open = unlockedForReal || unlockedInPreview;
    door.classList.toggle("unlocked", unlockedForReal);
    door.classList.toggle("preview-unlocked", unlockedInPreview && !unlockedForReal);
    door.querySelector(".door-prove").hidden = open;
    door.querySelector(".door-enter").hidden = !open;
    const req = door.querySelector(".door-req");
    if (unlockedForReal) req.innerHTML = 'Open · verified <span class="hint">(bridge receipt)</span>';
    else if (unlockedInPreview) req.innerHTML = 'Open · <span class="hint">PREVIEW — not verified</span>';
  }
  renderHud();
}

function renderHud() {
  const relicCount = Object.keys(store.relics).length;
  const secretCount = Object.keys(store.secrets).length;
  $("hud-relics").textContent = String(relicCount);
  $("hud-secrets").textContent = String(secretCount);
}

/* ------------------------------- wallet selection ------------------------------- */

/**
 * Wallet selection, capability-driven, with an explicit choice when more than one works. The
 * chosen adapter decides WHICH proof path runs: the walletd adapter drives the bridge's consensus
 * flow; a browser adapter runs the credential flow the audit verified (create the floor output,
 * sign the gate's challenge, let the bridge verify against chain state).
 */
async function chooseWallet() {
  const candidates = [sapientProvider(), universeProvider(), walletdProvider(window.location.origin)];
  const found = [];
  for (const p of candidates) {
    try {
      const probe = await p.probe();
      if (probe.available && probe.modes.length > 0) found.push({ p, probe });
    } catch {
      /* a wallet that fails to probe is simply not offered */
    }
  }
  const status = $("sanctum-status");
  if (found.length === 0) {
    status.textContent =
      "No usable wallet answered. Start walletd and set GG_WALLETD_ENDPOINT on the bridge, or " +
      "install Sapient / open this page inside Tari Universe.";
    return;
  }
  if (found.length === 1) {
    selectWalletForGame(found[0]);
    return;
  }
  // More than one wallet works: an explicit choice, named by label and mode, in one line.
  const parts = found.map(
    (f, i) => `[${i + 1}] ${f.p.label} (${f.probe.modes.map((m) => m.label).join("/")})`,
  );
  const answer = window.prompt(`Which wallet?\n${parts.join("\n")}\nEnter a number:`, "1");
  const idx = Number(answer) - 1;
  if (!Number.isInteger(idx) || idx < 0 || idx >= found.length) {
    status.textContent = "Wallet choice cancelled.";
    return;
  }
  selectWalletForGame(found[idx]);
}

function selectWalletForGame(pick) {
  session.provider = pick.p;
  session.providerProbe = pick.probe;
  $("sanctum-status").textContent =
    `${pick.p.label} connected — ${pick.probe.modes.map((m) => m.label).join(" or ")}. ` +
    "Break a seal when ready.";
}

/* ------------------------------- the proof flow ------------------------------- */

function setProofStep(name, state) {
  const li = document.querySelector(`#proof-overlay .proof-steps li[data-step="${name}"]`);
  if (li) li.dataset.state = state;
}

function openProofOverlay(gate) {
  $("proof-title").textContent =
    gate === "crypt" ? "Breaking the Crypt's seal" :
    gate === "vault" ? "Breaking the Forgotten Vault's seal" :
    "Breaking the Abyss";
  $("proof-line").textContent = "The dark stirs…";
  $("proof-error").hidden = true;
  for (const li of document.querySelectorAll("#proof-overlay .proof-steps li")) li.dataset.state = "";
  $("proof-overlay").hidden = false;
}

function cancelProof() {
  $("proof-overlay").hidden = true;
  session.inFlight = false;
}

let cancelRequested = false;

/** Runs the real proof for one gate and opens the door on the bridge's verdict — nothing else. */
async function proveFor(gate) {
  if (session.inFlight || previewMode) return;
  if (!session.provider) {
    await chooseWallet();
    if (!session.provider) return;
  }
  session.inFlight = true;
  cancelRequested = false;
  openProofOverlay(gate);
  try {
    setProofStep("challenge", "active");
    const ch = await post(`/gate/${gate}/challenge`, {});
    setProofStep("challenge", "done");

    // Two verified paths, chosen by the wallet the user picked — never by what would be easiest:
    //  - walletd (consensus): the bridge drives the user's own wallet daemon; the network executes
    //    the proof and the gate attests the floor.
    //  - browser wallets (credential): the wallet first creates a REAL output publicly committing
    //    to the threshold, then signs the gate's challenge over it; the bridge verifies against
    //    chain state before the door opens.
    const isConsensus = session.provider.id === "walletd";
    let verdict;
    if (isConsensus) {
      setProofStep("statement", "active");
      $("proof-line").textContent = "Your wallet daemon is preparing the proof. Approve it there.";
      const proof = await post(`/gate/${gate}/prove`, {
        gate_id: gate,
        challenge_nonce: ch.challenge_nonce,
        session_commitment: ch.session_commitment,
      });
      setProofStep("statement", "done");
      setProofStep("submit", "done");

      setProofStep("wait", "active");
      $("proof-line").textContent = "Consensus is deciding. The floor is public; the amount is not.";
      verdict = await pollProof(proof.proof_id);
      if (verdict.state === "accepted") {
        verdict._floor = verdict.result?.attested_minimum;
      }
    } else {
      const meta = gateMeta(gate);
      setProofStep("statement", "active");
      $("proof-line").textContent =
        "Your wallet will first create the proof output — public and permanent on chain. Approve it there.";
      const built = await session.provider.approveAndBuildProof("credential", {
        resourceAddress: meta.resource_address,
        amount: String(BigInt(meta.threshold)),
        minimumValuePromise: String(BigInt(meta.threshold)),
        maxFee: "5000",
      });
      $("proof-line").textContent = "Now sign the gate's challenge in your wallet.";
      const ownership = await session.provider.signChallenge(built.substateId, ch.challenge_nonce);
      setProofStep("statement", "done");
      setProofStep("submit", "done");

      setProofStep("wait", "active");
      $("proof-line").textContent = "The bridge is verifying against chain state.";
      const v = await post(`/gate/${gate}/credential`, {
        gate_id: gate,
        challenge_nonce: ch.challenge_nonce,
        session_commitment: ch.session_commitment,
        substate_id: built.substateId,
        public_key: ownership.publicKey,
        public_nonce: ownership.publicNonce,
        signature: ownership.signature,
      });
      verdict = v.refused
        ? { state: "refused", reason: v.refused }
        : v.state === "accepted"
        ? { state: "accepted", result: { attested_minimum: v.receipt?.attested_minimum } }
        : { state: "failed", reason: "unexpected verdict" };
    }

    // Both branches above have already resolved to a terminal verdict — the consensus path by
    // polling its proof id, the credential path from the bridge's own accept/refuse response.
    // There is nothing left to poll here; an earlier revision re-polled `proof.proof_id` on both
    // paths, which crashed the credential flow (no `proof` existed there) and would have thrown
    // even on consensus. Judge the door on this single verdict.
    if (verdict.state === "accepted") {
      session.unlocked.add(gate);
      $("proof-line").textContent = "The seal breaks.";
      await sleep(900);
      $("proof-overlay").hidden = true;
      doorOpeningAnimation(gate);
      renderDoors();
    } else if (verdict.state === "refused" || verdict.state === "failed") {
      throw new Error(verdict.reason || "the gate refused the proof");
    } else {
      throw new Error("the proof did not settle");
    }
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    if (cancelRequested || msg.includes("cancelled")) {
      $("proof-overlay").hidden = true;
    } else {
      $("proof-line").textContent = "The seal holds.";
      const err = $("proof-error");
      err.hidden = false;
      err.textContent = msg;
      setProofStep("wait", "");
    }
  } finally {
    session.inFlight = false;
  }
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

async function pollProof(proofId, attempts = 40) {
  for (let i = 0; i < attempts; i++) {
    if (cancelRequested) throw new Error("cancelled");
    const res = await fetch(`/proof/${encodeURIComponent(proofId)}/status`);
    const json = await res.json();
    if (["accepted", "refused", "failed"].includes(json.state)) return json;
    await sleep(1000);
  }
  throw new Error("timed out waiting for consensus");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** The dramatic bit: rumble, cracks, light, doors swinging. Pure CSS classes; reduced-motion safe. */
function doorOpeningAnimation(gate) {
  const door = doorEl(gate);
  door.classList.add("opening");
  // The chambers behind have their own ambience; the door opens before the player clicks Enter.
  setTimeout(() => {
    door.classList.remove("opening");
    door.classList.add("unlocked");
    renderDoors();
  }, 2100);
}

/* ------------------------------- puzzles ------------------------------- */

const RELICS = {
  crypt: {
    id: "crypt",
    art: "🕯",
    title: "Relic of the Vigil",
    lore: "The candles remember being prayers. Yours, tonight, is the first light they have " +
      "trusted in a long time. The crypt exhales; somewhere below, a ledger ticks.",
  },
  vault: {
    id: "vault",
    art: "🗝",
    title: "Relic of the Ledger",
    lore: "DEBT SLEEPS. TRUST WAKES. GOLD REMEMBERS. The banker's motto was never a warning — " +
      "it was an inventory. The vault gives up its ledger, and the ledger is heavier than the gold.",
  },
  abyss: {
    id: "abyss",
    art: "🌀",
    title: "Relic of the Echo",
    lore: "You answered in fours until it stopped asking. What remains when a door no longer " +
      "needs to keep something in is not silence. Take the echo. Do not answer it back.",
  },
};

function grantRelic(gate) {
  if (store.relics[gate]) return;
  store.relics[gate] = Date.now();
  saveStore();
  renderHud();
  const relic = RELICS[gate];
  $("relic-art").textContent = relic.art;
  $("relic-title").textContent = relic.title;
  $("relic-lore").textContent = relic.lore;
  $("relic-overlay").hidden = false;
}

function closeRelic() {
  $("relic-overlay").hidden = true;
  leaveChamber();
  // The ending, once everything is held.
  if (Object.keys(store.relics).length === GATES.length) {
    $("sanctum-status").textContent =
      "Three relics. The Vault's heart beats once, slowly, and lets you go — for now.";
  }
}

function findSecret(gate) {
  const names = {
    crypt: "Whisper of the chapel floor",
    vault: "Whisper of the bricked ledger",
    abyss: "Whisper that was not yours",
  };
  if (store.secrets[gate]) return;
  store.secrets[gate] = Date.now();
  saveStore();
  renderHud();
  const relic = RELICS[gate];
  $("relic-art").textContent = "👁";
  $("relic-title").textContent = names[gate];
  $("relic-lore").textContent =
    gate === "crypt"
      ? "Scratched under the fourth candle: 'the vigil is not for the dead; it is so the dead can tell when we stop watching.'"
      : gate === "vault"
      ? "Behind the dial's face, a second dial. Nobody has ever turned it. It points at you."
      : "The whisper you repeated was not the abyss's. It was yours, from a room you have not entered yet.";
  $("relic-overlay").hidden = false;
  void relic;
}

/* ---- The Crypt: candle sequence ---- */

const CRYPT_ORDER = [2, 0, 3, 1]; // watches, weeps, keeper of names, keeper of sleeps

function buildCryptPuzzle() {
  const host = $("crypt-candles");
  const names = ["the watcher", "the weeper", "keeper of names", "keeper of sleeps"];
  for (let i = 0; i < 4; i++) {
    const c = document.createElement("div");
    c.className = "candle";
    c.dataset.i = String(i);
    c.innerHTML = '<div class="flame"></div><div class="stick"></div>';
    const label = document.createElement("div");
    label.className = "label";
    label.textContent = names[i];
    c.append(label);
    c.addEventListener("click", () => lightCandle(i));
    host.append(c);
  }
}

function lightCandle(i) {
  if (isPuzzleSolved("crypt")) return;
  const candles = [...document.querySelectorAll("#crypt-candles .candle")];
  const lit = candles.filter((c) => c.classList.contains("lit")).length;
  if (CRYPT_ORDER[lit] === i) {
    candles[i].classList.add("lit");
    if (lit + 1 === 4) {
      completePuzzle("crypt");
      $("crypt-hint").textContent = "The vigil is kept.";
    }
  } else {
    // Wrong order wakes them: all blow out, with a shake.
    candles.forEach((c) => {
      c.classList.remove("lit");
      c.classList.add("awake");
      setTimeout(() => c.classList.remove("awake"), 450);
    });
    $("crypt-hint").textContent = "They went out. Read the epitaph again.";
  }
}

/* ---- The Forgotten Vault: ring alignment ---- */

const VAULT_TARGET = { 0: "T", 1: "T", 2: "G" }; // each ring's glyph that must sit under the pointer
// Module scope, because the dial is re-measured when its chamber is shown (see enterChamber).
let vaultRings = [];
const vaultOffsets = [0, 0, 0];

function buildVaultPuzzle() {
  vaultRings = [...document.querySelectorAll("#vault-sigil .ring")];
  vaultRings.forEach((ring, ri) => {
    ring.addEventListener("click", () => {
      if (isPuzzleSolved("vault")) return;
      vaultOffsets[ri] = (vaultOffsets[ri] + 1) % ring.children.length;
      updateVault(vaultRings, vaultOffsets);
    });
  });
  updateVault(vaultRings, vaultOffsets);
}

/**
 * Positions every glyph at its angle for the ring's current offset, and marks the one under the
 * pointer. Glyphs are placed in JS because CSS cannot know how many a ring carries; the glyph at
 * angle 0 is the one under the pointer, so "aligned" is a geometric fact, not a styled opinion.
 */
function updateVault(rings, offsets) {
  let all = true;
  const names = ["Outer", "Middle", "Inner"];
  rings.forEach((ring, ri) => {
    const glyphs = [...ring.children].filter((g) => g.classList.contains("glyph"));
    const step = 360 / glyphs.length;
    const radius = ring.clientWidth / 2 - 14;
    glyphs.forEach((g, gi) => {
      // The ring's offset rotates the whole dial; this glyph's absolute angle decides where it sits.
      const angle = (gi - offsets[ri]) * step - 90;
      const rad = (angle * Math.PI) / 180;
      g.style.left = `${ring.clientWidth / 2 + radius * Math.cos(rad)}px`;
      g.style.top = `${ring.clientHeight / 2 + radius * Math.sin(rad)}px`;
      g.style.transform = "translate(-50%, -50%)";
      g.classList.remove("aligned");
    });
    // Which glyph is under the pointer (top center) after the offset?
    const pointerIndex = ((-offsets[ri] % glyphs.length) + glyphs.length) % glyphs.length;
    const ch = glyphs[pointerIndex].textContent.trim();
    const ok = ch === VAULT_TARGET[ri];
    if (ok) glyphs[pointerIndex].classList.add("aligned");
    ring.classList.toggle("solved", ok);
    if (!ok) all = false;
    names[ri] = `${names[ri]}: ${ch}${ok ? " ✓" : ""}`;
  });
  $("vault-state").textContent = names.join(" · ");
  if (all) {
    completePuzzle("vault");
    $("vault-hint").textContent = "The rings settle. The ledger slides free.";
  }
}

/* ---- The Abyss: echo memory ---- */

const ABYSS_ROUNDS = 4;
let abyssSeq = [];
let abyssInput = [];
// True from "watch" until "your turn". Presses during playback are ignored rather than counted as a
// wrong answer: the abyss is asking you to WATCH first, and a player who taps early should not be
// punished with a reset they cannot explain.
let abyssListening = false;

function buildAbyssPuzzle() {
  document.querySelectorAll("#abyss-pads .echo").forEach((b) =>
    b.addEventListener("click", () => echoPress(Number(b.dataset.i))),
  );
  startAbyssRound();
}

function startAbyssRound() {
  abyssListening = true;
  abyssSeq.push(Math.floor(Math.random() * 4));
  abyssInput = [];
  $("abyss-hint").textContent = `Round ${abyssSeq.length} of ${ABYSS_ROUNDS}. Watch.`;
  playAbyss();
}

async function playAbyss() {
  const eye = $("abyss-eye");
  eye.classList.add("listening");
  await sleep(600);
  for (const i of abyssSeq) {
    flashEcho(i);
    await sleep(640);
  }
  eye.classList.remove("listening");
  $("abyss-hint").textContent = "Your turn.";
  abyssListening = false;
}

function flashEcho(i) {
  const b = document.querySelector(`#abyss-pads .echo[data-i="${i}"]`);
  if (!b) return;
  b.classList.remove("flash");
  void b.offsetWidth; // restart the animation
  b.classList.add("flash");
}

async function echoPress(i) {
  if (isPuzzleSolved("abyss") || abyssListening) return;
  flashEcho(i);
  abyssInput.push(i);
  const idx = abyssInput.length - 1;
  if (abyssSeq[idx] !== i) {
    $("abyss-hint").textContent = "Wrong echo. It begins again.";
    abyssSeq = [];
    abyssListening = true; // hold input across the pause so a click can't split the restart
    await sleep(700);
    startAbyssRound();
    return;
  }
  if (abyssInput.length === abyssSeq.length) {
    if (abyssSeq.length >= ABYSS_ROUNDS) {
      completePuzzle("abyss");
      $("abyss-hint").textContent = "It stops asking.";
    } else {
      abyssListening = true; // same across the between-round pause
      await sleep(500);
      startAbyssRound();
    }
  }
}

/* ------------------------------- puzzle completion ------------------------------- */

function isPuzzleSolved(gate) {
  return Boolean(store.puzzles?.[gate]);
}

/** Marks a puzzle complete. This grants the RELIC (cosmetic) — never an unlock. */
function completePuzzle(gate) {
  if (store.puzzles?.[gate]) return;
  store.puzzles = store.puzzles || {};
  store.puzzles[gate] = Date.now();
  saveStore();
  grantRelic(gate);
}
