/**
 * GHOST GATE — THE LOST EPOCH, orchestrator.
 *
 * Security shape (docs/SECURITY_RELEASE_GATE.md), unchanged by the rebuild:
 * - A chamber door opens only from the bridge's verdict for a proof made in THIS session, or in
 *   labelled preview. There is no persisted "unlocked" state: reload the page and the doors are
 *   sealed again, because an unlock is a fact about a session, not about this file's storage.
 * - localStorage holds story progress — fragments, whispers, chapters — cosmetic only, labelled
 *   as such. No cosmetic value is ever a credential.
 * - Preview mode is labelled in three places and never calls the challenge/proof/credential
 *   routes; it mints nothing.
 * - The thresholds shown come from the bridge's /gate/:id responses. The page never decides what
 *   a gate requires.
 */

import { sapientProvider, universeProvider, walletdProvider } from "/js/ghost/provider.js";
import { formatAmount } from "/js/ghost/capabilities.js";
import {
  FRAGMENTS,
  CASE_FILE_LINES,
  SECRETS,
  ENDING_BEATS,
  SANCTUM_INTRO,
  PHANTOM_TAUNTS,
  PHANTOM_INTRO,
} from "./story.js";
import { buildChapter1, buildChapter2, buildChapter3 } from "./chapters.js";

const GATES = ["crypt", "vault", "abyss"];
const $ = (id) => document.getElementById(id);

/* ------------------------------- state ------------------------------- */

/**
 * Cosmetic story progress. Never a credential; labelled as such in the UI. v2 — the Lost Epoch.
 */
const STORE_KEY = "ghost-gate-vault-progress-v2";
const store = loadStore();

function loadStore() {
  const empty = { fragments: {}, puzzles: {}, secrets: {}, previewUnlocked: [], endingSeen: false };
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
  $("btn-casefile").addEventListener("click", openCaseFile);
  $("casefile-close").addEventListener("click", closeCaseFile);
  $("proof-cancel").addEventListener("click", cancelProof);
  $("whisper-close").addEventListener("click", closeWhisper);
  $("fragment-close").addEventListener("click", closeFragment);
  $("ending-continue").addEventListener("click", endingNext);
  document.querySelectorAll(".chamber-leave").forEach((b) =>
    // Explicit arrow: leaveChamber's first parameter is `silent`, and passing the event object
    // here is exactly the bug that made "Back to the Sanctum" look dead — the event is truthy, so
    // the Sanctum never reappeared. Never hand a raw handler to addEventListener when it takes
    // flag arguments.
    b.addEventListener("click", () => leaveChamber()),
  );
  document.querySelectorAll(".secret-glyph").forEach((g) =>
    g.addEventListener("click", () => findSecret(g.dataset.secret)),
  );

  for (const gate of GATES) {
    const door = doorEl(gate);
    door.querySelector(".door-prove").addEventListener("click", () => proveFor(gate));
    door.querySelector(".door-enter").addEventListener("click", () => enterChamber(gate));
  }

  chapters.crypt = buildChapter1(chapterApi);
  chapters.vault = buildChapter2(chapterApi);
  chapters.abyss = buildChapter3(chapterApi);
});

const chapters = {};
const chapterApi = {
  get store() {
    return store;
  },
  save: saveStore,
  isSolved: (gate) => Boolean(store.puzzles?.[gate]),
  hasFragments: (ids) => ids.every((id) => store.fragments[id]),
  grantFragment: (id) => grantFragment(id),
  whisper: (gate) => findSecret(gate),
  openEnding: () => openEnding(),
  phantomSay: (line) => {
    const chamberPhantom = document.querySelector(".chamber:not([hidden]) .phantom-say");
    if (chamberPhantom) chamberPhantom.textContent = line;
  },
};

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
    for (const gate of GATES) session.unlocked.delete(gate);
    store.previewUnlocked = [...GATES];
    saveStore();
  }
  // The Phantom greets; the intro explains the case. Both cheap, both story.
  $("phantom-presence").textContent = PHANTOM_TAUNTS[Math.floor(Math.random() * PHANTOM_TAUNTS.length)];
  const seen = store.endingSeen || Object.keys(store.fragments).length > 0;
  $("sanctum-intro").textContent = seen ? "" : SANCTUM_INTRO;
  await loadGateMetadata();
  renderDoors();
  renderHud();
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
  // First visit gets the Phantom's chapter intro; later visits get the chamber's own line.
  const chapter = chapters[gate];
  if (chapter) chapter.enter();
  const say = chamber ? chamber.querySelector(".phantom-say") : null;
  if (say && !store.puzzles[gate]) say.textContent = "THE PHANTOM: \u201c" + PHANTOM_INTRO[gate] + "\u201d";
}

/**
 * Works from every chamber, mid-puzzle, after failure, after success, after rewards — and as many
 * times as the player likes. Chambers cancel their own timers in leave().
 */
function leaveChamber(silent = false) {
  for (const gate of GATES) {
    const c = document.getElementById(`chamber-${gate}`);
    if (c && !c.hidden) {
      const chapter = chapters[gate];
      if (chapter) chapter.leave();
      c.hidden = true;
    }
  }
  if (!silent) {
    $("sanctum").hidden = false;
    renderDoors();
    renderHud();
  }
}

/* ------------------------------- gate metadata ------------------------------- */

/** Thresholds are whatever the bridge reports. The page has no opinion. */
const gateMetadata = {};

function gateMeta(gate) {
  return gateMetadata[gate];
}

async function loadGateMetadata() {
  for (const gate of GATES) {
    // Guard the environment, not the logic: a threshold element is always present on the game
    // page, but this runs after awaits and can straddle a navigation. If the page is not the game
    // page any more, skip quietly instead of throwing mid-teardown.
    const el = doorEl(gate)?.querySelector(".door-threshold");
    if (!el) continue;
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
    const frag = door.querySelector(".door-frag");
    const f = FRAGMENTS[gate];
    if (store.fragments[gate]) frag.textContent = `Fragment ${f.numeral} recovered — ${f.title}`;
    else frag.textContent = `Fragment ${f.numeral} sealed within`;
  }
  renderHud();
}

function renderHud() {
  const fragCount = Object.keys(store.fragments).length;
  const secretCount = Object.keys(store.secrets).length;
  $("hud-frags").textContent = String(fragCount);
  $("hud-secrets").textContent = String(secretCount);
}

/* ------------------------------- wallet selection ------------------------------- */

/**
 * Wallet selection, capability-driven, with an explicit choice when more than one works. The
 * chosen adapter decides WHICH proof path runs: the walletd adapter drives the bridge's consensus
 * flow; a browser adapter runs the credential flow the audit verified.
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
    gate === "vault" ? "Breaking the Vault's seal" :
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
    // There is nothing left to poll here. Judge the door on this single verdict.
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
  setTimeout(() => {
    door.classList.remove("opening");
    door.classList.add("unlocked");
    renderDoors();
  }, 2100);
}

/* ------------------------------- fragments, whispers, case file ------------------------------- */

/**
 * Grant a fragment: mark it (cosmetic), refresh the HUD/doors, and present it in the fragment's
 * OWN presentation — a dossier for the investigation, a sealing chain for the dial, and the full
 * ending for the confrontation. Never the same modal twice.
 */
function grantFragment(id) {
  const first = !store.fragments[id];
  store.fragments[id] = Date.now();
  store.puzzles[id] = store.puzzles[id] || Date.now();
  saveStore();
  renderHud();
  renderDoors();
  if (id === "abyss") {
    openEnding();
    return;
  }
  const f = FRAGMENTS[id];
  const overlay = $("fragment-overlay");
  overlay.className = f.kind === "chain" ? "chain-presentation" : "dossier-presentation";
  $("fragment-kicker").textContent = `Fragment ${f.numeral} of III — recovered`;
  $("fragment-title").textContent = f.title;
  const body = $("fragment-body");
  body.replaceChildren();
  for (const line of f.body) body.append(el("p", null, line));
  if (f.kind === "chain") body.classList.add("chain-body");
  else body.classList.remove("chain-body");
  $("fragment-close").textContent = f.cta || "Continue";
  overlay.hidden = false;
  if (first) $("phantom-presence").textContent = "The Phantom knows. The Phantom ALWAYS knows.";
}

function closeFragment() {
  $("fragment-overlay").hidden = true;
}

/** The ∴ whispers — small, optional, story-flavoured. */
function findSecret(gate) {
  if (store.secrets[gate]) return;
  store.secrets[gate] = Date.now();
  saveStore();
  renderHud();
  const s = SECRETS[gate];
  $("whisper-art").textContent = "👁";
  $("whisper-title").textContent = s.title;
  $("whisper-lore").textContent = s.text;
  $("whisper-overlay").hidden = false;
}

function closeWhisper() {
  $("whisper-overlay").hidden = true;
}

/** Review everything the case holds so far. */
function openCaseFile() {
  const list = $("casefile-list");
  list.replaceChildren();
  const held = GATES.filter((g) => store.fragments[g]);
  if (held.length === 0) {
    list.append(el("p", "hint", "The case file is empty. The Crypt holds the first fragment."));
  } else {
    for (const g of held) list.append(el("p", null, CASE_FILE_LINES[g]));
    if (held.length === GATES.length) {
      list.append(el("p", "hint", "Three fragments. One auditor with an attitude. One door left."));
    }
  }
  $("casefile-overlay").hidden = false;
}

function closeCaseFile() {
  $("casefile-overlay").hidden = true;
}

/* ------------------------------- the ending ------------------------------- */

let endingBeat = 0;

function openEnding() {
  endingBeat = 0;
  $("ending-overlay").hidden = false;
  showEndingBeat();
}

function showEndingBeat() {
  const host = $("ending-text");
  const beats = ENDING_BEATS;
  if (endingBeat >= beats.length) {
    store.endingSeen = true;
    saveStore();
    $("ending-continue").textContent = "Return to the Sanctum";
    return;
  }
  const p = el("p", "ending-beat" + (endingBeat === beats.length - 1 ? " finale" : ""), beats[endingBeat]);
  host.append(p);
  const isLastBeat = endingBeat === beats.length - 1;
  endingBeat++;
  $("ending-continue").textContent = isLastBeat ? "Return to the Sanctum" : "Continue";
}

function endingNext() {
  const host = $("ending-text");
  if (endingBeat >= ENDING_BEATS.length) {
    $("ending-overlay").hidden = true;
    host.replaceChildren();
    leaveChamber(); // back to the Sanctum, fragments gleaming
    return;
  }
  showEndingBeat();
}

/* ------------------------------- tiny helper ------------------------------- */

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
