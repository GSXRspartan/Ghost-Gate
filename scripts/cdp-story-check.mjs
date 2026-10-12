/**
 * CDP harness for THE LOST EPOCH (scripts/browser_game_check.sh).
 *
 * Speaks Chrome DevTools Protocol over Node's built-in WebSocket — no npm dependencies. It drives
 * the REAL served page on :7799 the way a person would: computed styles, real clicks, real waits.
 * Headless Edge is a real Chromium render — the operator's own visible browser is never touched.
 *
 * What it covers (mapping to the operator's playtest report):
 *   1.  title screen on load, every overlay hidden               (startup regression)
 *   2.  Enter Preview → Sanctum; preview calls no proof routes    (preview isolation)
 *   3.  navigation matrix Crypt→S→Vault→S→Abyss→S→title          (Bug 1: leaveChamber)
 *   4.  Chapter I: witnesses, wrong accusation feedback, right
 *       accusation → dossier reward                              (Bug 2 replaced)
 *   5.  Chapter II: no solution in the UI; dial solved from
 *       data read off the page; wrong alignment feedback         (Bug 4 replaced)
 *   6.  Chapter III: clicks during the demonstration ignored;
 *       wrong press retries the SAME stage with a named reason;
 *       four stages complete → the ending                        (Bug 3 rebuilt)
 *   7.  stage-4 quorum gate on a fresh file; persistence; case
 *       file; whispers; reload
 *   8.  no-wallet failure path never strands an overlay
 *   9.  console/network hygiene + mobile overflow
 */

const PORT = process.argv[2] || process.env.CDP_PORT;
if (!PORT) throw new Error("usage: node cdp-story-check.mjs <cdp-port>");
const GAME = "http://127.0.0.1:7799/game";
const STORE = "ghost-gate-vault-progress-v2";

let ws, nextId = 1;
const pending = new Map();
const consoleErrors = [];
const failedRequests = [];
const proofCalls = [];

function send(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}
const call = (m, p) => send(m, p);

async function evaluate(expression, awaitPromise = true) {
  const r = await call("Runtime.evaluate", { expression, returnByValue: true, awaitPromise });
  if (r.exceptionDetails) {
    throw new Error("page threw: " + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
  }
  return r.result.value;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let passCount = 0, failCount = 0;
function check(name, ok, evidence = "") {
  if (ok) { passCount++; console.log(`  PASS  ${name}${evidence ? "  [" + evidence + "]" : ""}`); }
  else { failCount++; console.log(`  FAIL  ${name}${evidence ? "  [" + evidence + "]" : ""}`); }
}

async function connect() {
  const targets = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
  const page = targets.find((t) => t.type === "page");
  if (!page) throw new Error("no page target in Edge");
  ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error("cdp websocket failed")); });
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      return;
    }
    if (msg.method === "Runtime.consoleAPICalled" && ["error", "assert"].includes(msg.params.type)) {
      consoleErrors.push(msg.params.args.map((a) => a.value ?? a.description ?? a.type).join(" "));
    }
    if (msg.method === "Runtime.exceptionThrown") {
      consoleErrors.push("uncaught: " + (msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text));
    }
    if (msg.method === "Network.requestWillBeSent") {
      const url = msg.params.request.url;
      if (/\/(challenge|prove|credential)\b/.test(url)) proofCalls.push(url);
    }
    if (msg.method === "Network.loadingFailed") {
      failedRequests.push(msg.params.errorText + " " + (msg.params.type || ""));
    }
  };
  await call("Page.enable");
  await call("Runtime.enable");
  await call("Network.enable");
}

async function goto(url) {
  await call("Page.navigate", { url });
  for (let i = 0; i < 80; i++) {
    const ready = await evaluate("document.readyState", false).catch(() => null);
    if (ready === "complete") return;
    await sleep(50);
  }
}

const visible = (sel) => evaluate(`(() => {
  const el = document.querySelector(${JSON.stringify(sel)});
  if (!el) return "MISSING";
  const cs = getComputedStyle(el);
  const r = el.getBoundingClientRect();
  return cs.display !== "none" && cs.visibility !== "hidden" && r.width > 0 && r.height > 0;
})()`, false);

const click = (sel) => evaluate(`(() => {
  const el = document.querySelector(${JSON.stringify(sel)});
  if (!el) return "MISSING";
  el.click();
  return "clicked";
})()`, false);

/** Click WITHOUT awaiting: async handlers would block the harness for their full duration. */
const clickNoWait = (sel) =>
  send("Runtime.evaluate", {
    expression: `(() => { const el = document.querySelector(${JSON.stringify(sel)}); if (!el) return "MISSING"; el.click(); return "clicked"; })()`,
    returnByValue: true,
    awaitPromise: false,
  }).then((r) => r.result?.value);

async function waitFor(expr, timeoutMs = 20000, label = expr) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let v = false;
    try { v = await evaluate(expr, false); } catch { /* mid-navigation */ }
    if (v) return true;
    await sleep(100);
  }
  console.log(`  (timeout waiting for: ${label})`);
  return false;
}

const hidden = (sel) =>
  evaluate(`getComputedStyle(document.querySelector("${sel}")).display === "none"`, false);

/* ------------------------------ the run ------------------------------ */

await connect();

console.log("\n== 1. startup: /game shows the title screen, overlays hidden ==");
await goto(GAME);
await evaluate(`localStorage.removeItem("${STORE}"); "cleared"`, false);
await goto(GAME);
await sleep(500);
check("title screen is visible", await visible("#title-screen"));
for (const [sel, label] of [
  ["#proof-overlay", "proof overlay"],
  ["#fragment-overlay", "fragment overlay"],
  ["#whisper-overlay", "whisper overlay"],
  ["#casefile-overlay", "case file"],
  ["#ending-overlay", "ending"],
  ["#sanctum", "sanctum"],
]) check(`${label} hidden on load`, (await hidden(sel)) === true);
check("title names both entries", await evaluate(
  `/Connect a wallet/.test(document.body.innerText) && /Enter Preview/.test(document.body.innerText)`, false));

console.log("\n== 2. Enter Preview navigates to the Sanctum ==");
await click("#btn-preview");
await waitFor(`["crypt","vault","abyss"].every(g => { const d = document.getElementById("door-"+g);
  const e = d && d.querySelector(".door-enter"); return e && !e.hidden; })`, 20000, "preview doors");
check("sanctum visible after preview", await visible("#sanctum"));
check("PREVIEW banner shown", await visible("#preview-banner"));
check("all three doors enterable in preview", await evaluate(
  `["crypt","vault","abyss"].every(g => { const e = document.getElementById("door-"+g).querySelector(".door-enter"); return e && !e.hidden; })`, false));
check("phantom greets the Sanctum", await evaluate(
  `document.getElementById("phantom-presence").textContent.length > 0`, false));
check("no proof endpoints so far", proofCalls.length === 0, proofCalls.join(",") || "none");

console.log("\n== 3. navigation matrix: Crypt→S→Vault→S→Abyss→S→title (Bug 1) ==");
for (const gate of ["crypt", "vault", "abyss"]) {
  await click(`#door-${gate} .door-enter`);
  await waitFor(`(() => { const c = document.getElementById("chamber-${gate}"); return c && !c.hidden; })()`, 10000, `chamber ${gate} open`);
  check(`enter ${gate} chamber`, await visible(`#chamber-${gate}`));
  await click(`#chamber-${gate} .chamber-leave`); // mid-puzzle: nothing completed here
  await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 10000, "sanctum after leave");
  check(`back to the Sanctum from ${gate} (mid-puzzle)`, await visible("#sanctum"));
}
await click("#btn-back-title");
await sleep(400);
check("Leave returns to the title screen", await visible("#title-screen"));
await click("#btn-preview");
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 15000, "sanctum re-entered");

console.log("\n== 4. Chapter I: witnesses, wrong accusation, right accusation ==");
await click("#door-crypt .door-enter");
await waitFor(`(() => { const c = document.getElementById("chamber-crypt"); return c && !c.hidden; })()`, 10000, "crypt open");
check("three witnesses offered", await evaluate(`document.querySelectorAll("#crypt-witnesses .witness").length === 3`, false));
check("four stones presented", await evaluate(`document.querySelectorAll("#crypt-stones .stone").length === 4`, false));
await evaluate(`document.querySelectorAll("#crypt-witnesses .witness").forEach(b => b.click())`, false);
await sleep(300);
check("three testimonies recorded", await evaluate(`document.querySelectorAll("#crypt-notes li").length >= 3`, false));
await click(`#crypt-stones .stone[data-stone="widow"]`);
await click("#crypt-accuse");
await sleep(250);
check("wrong accusation explains the acquittal", await evaluate(
  `/agrees with the registry, the bell, and the payee/.test(document.getElementById("crypt-hint").textContent)`, false));
check("no reward on a wrong accusation", (await hidden("#fragment-overlay")) === true);
await click(`#crypt-stones .stone[data-stone="stranger"]`);
await click("#crypt-examine");
await sleep(250);
check("examining the Stranger reveals fresh scraping", await evaluate(
  `/Fresh scraping/.test(document.getElementById("crypt-notes").textContent)`, false));
await click("#crypt-accuse");
await waitFor(`(() => { const r = document.getElementById("fragment-overlay"); return r && !r.hidden; })()`, 10000, "fragment I overlay");
check("Fragment I dossier appears", await visible("#fragment-overlay"));
check("it is the Altered Ledger, in the dossier presentation", await evaluate(
  `document.getElementById("fragment-title").textContent.includes("Altered Ledger") &&
   document.getElementById("fragment-overlay").className.includes("dossier")`, false));
check("the dossier teaches the 𝕶 mark (Chapter II depends on it)", await evaluate(
  `/𝕶/.test(document.getElementById("fragment-body").textContent)`, false));
await click("#fragment-close");
await sleep(400);
check("fragment dismisses", (await hidden("#fragment-overlay")) === true);
await click(`#chamber-crypt .chamber-leave`);
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 10000, "sanctum");

console.log("\n== 5. Chapter II: no solution disclosed; the dial is solvable by reasoning ==");
await click("#door-vault .door-enter");
await waitFor(`(() => { const c = document.getElementById("chamber-vault"); return c && !c.hidden; })()`, 10000, "vault open");
check("fifteen chips across three shelves", await evaluate(
  `document.querySelectorAll("#vault-ring-0 .chip, #vault-ring-1 .chip, #vault-ring-2 .chip").length === 15`, false));
const uiText = await evaluate(`document.getElementById("chamber-vault").innerText`, false);
check("no direct solution disclosure in the UI", !/♯\s*5\s*→/.test(uiText));
const plan = await evaluate(`(() => {
  const rings = [0,1,2].map(r => [...document.querySelectorAll("#vault-ring-" + r + " .chip")].map(c => ({
    id: c.dataset.id, h: Number(c.dataset.h), parent: c.dataset.parent, corrupt: c.dataset.corrupt === "true",
  })));
  const solutions = [];
  for (let a = 0; a < rings[0].length; a++)
    for (let b = 0; b < rings[1].length; b++)
      for (let c = 0; c < rings[2].length; c++) {
        const f = [rings[0][a], rings[1][b], rings[2][c]];
        if (f[0].h === 5 && f[1].h === 6 && f[2].h === 7 &&
            f[1].parent === f[0].id && f[2].parent === f[1].id &&
            !f.some(x => x.corrupt)) solutions.push([a, b, c]);
      }
  return { solutions };
})()`);
check("exactly one solution readable from the page", plan.solutions.length === 1, JSON.stringify(plan.solutions));
// A definitely-wrong alignment first: ring 1 two turns past its solution offset.
const [sa, sb, sc] = plan.solutions[0];
await evaluate(`(() => {
  const wrong = (${sb} + 2) % 5;
  const chips = [...document.querySelectorAll("#vault-ring-1 .chip")];
  chips[wrong].click();
})()`, false);
await sleep(250);
check("wrong alignment gets legible feedback, not success", await evaluate(
  `document.getElementById("vault-feedback").textContent.length > 0 &&
   !/spine holds/.test(document.getElementById("vault-feedback").textContent)`, false));
await evaluate(`(() => {
  const set = (r, target) => {
    const chips = [...document.querySelectorAll("#vault-ring-" + r + " .chip")];
    chips[target].click();
  };
  set(0, ${sa}); set(1, ${sb}); set(2, ${sc});
})()`, false);
await waitFor(`(() => { const r = document.getElementById("fragment-overlay"); return r && !r.hidden; })()`, 12000, "fragment II overlay");
check("Fragment II appears on the true spine", await visible("#fragment-overlay"));
check("it is the Missing Parent, in the chain presentation", await evaluate(
  `document.getElementById("fragment-title").textContent.includes("Missing Parent") &&
   document.getElementById("fragment-overlay").className.includes("chain")`, false));
check("it plants the Phantom's motive for the finale", await evaluate(
  `/MODESTY/.test(document.getElementById("fragment-body").textContent)`, false));
await click("#fragment-close");
await sleep(400);
await click(`#chamber-vault .chamber-leave`);
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 10000, "sanctum");

console.log("\n== 6. Chapter III: the state machine, four stages, retry-on-mistake ==");
await click("#door-abyss .door-enter");
await waitFor(`(() => { const c = document.getElementById("chamber-abyss"); return c && !c.hidden; })()`, 10000, "abyss open");

/**
 * Play one stage like a player. The observer arms BEFORE the demonstration begins — it must never
 * attach mid-playback, or it misses leading echoes, the first press goes wrong, and a retry fires
 * (exactly the degenerate loop this harness once produced). Our own presses set __echoIgnore so
 * only the Phantom's echoes are recorded. `harass` fires six rapid clicks during the Watch phase
 * and asserts they were swallowed.
 */
async function playStage(stageNo, wrongFirst = false, harass = false) {
  // Arm the observer, then click begin INSIDE the same evaluate so the demonstration cannot start
  // before the recorder exists.
  return evaluate(`(async () => {
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));
    const fb = document.getElementById("phantom-feedback");
    const begin = document.getElementById("phantom-begin");
    const pads = [...document.querySelectorAll("#phantom-pads .echo")];
    const trueSeq = []; const paleSeq = [];
    // This Edge build delivers a single class add on an animated node as TWO identical records,
    // both with a clean oldValue. A class sampler proved the GAME flashes exactly once per echo,
    // so the observer dedupes: the same pad may not count twice within 300ms. True echoes of one
    // pad are always >=660ms apart, so the window cannot merge two real echoes.
    const last = {};
    const obs = new MutationObserver((muts) => {
      for (const m of muts) {
        const el = m.target;
        const isPale = el.classList.contains("pale");
        const has = el.classList.contains("lit") || isPale;
        const had = (m.oldValue || "").includes("lit") || (m.oldValue || "").includes("pale");
        const i = Number(el.dataset.i);
        const now = performance.now();
        const key = i + (isPale ? "P" : "T");
        if (has && !had && !window.__echoIgnore && now - (last[key] || -1e9) > 300) {
          last[key] = now;
          if (isPale) paleSeq.push(i);
          else trueSeq.push(i);
        }
      }
    });
    pads.forEach(p => obs.observe(p, { attributes: true, attributeOldValue: true }));
    const reverse = ${stageNo >= 3};
    const waitTurn = async () => {
      for (let guard = 0; guard < 900; guard++) {
        if (/Your turn/.test(fb.textContent)) return true;
        await sleep(60);
      }
      return false;
    };
    begin.click();
    let harassHeld = null;
    if (${harass}) {
      await sleep(300);                       // inside the Watch phase now
      for (let k = 0; k < 6; k++) pads[0].click();
      harassHeld = /Watch/.test(fb.textContent);   // input must be locked during demonstration
    }
    let first = true;
    let wrongInfo = null;
    while (true) {
      const ok = await waitTurn();
      if (!ok) break;
      if (first && ${wrongFirst}) {
        first = false;
        const wrongPad = (trueSeq[0] + 1) % 4;   // guaranteed ≠ the expected echo
        window.__echoIgnore = true;
        pads[wrongPad].click();
        await sleep(0); await sleep(0);
        window.__echoIgnore = false;
        wrongInfo = { wrongPad, fbAfter: fb.textContent, bannerAfter: document.getElementById("phantom-stage").textContent };
        trueSeq.length = 0; paleSeq.length = 0;   // the retry replays; observe it fresh
        continue;
      }
      const answer = reverse ? [...trueSeq].reverse() : [...trueSeq];
      window.__echoIgnore = true;
      for (const i of answer) { pads[i].click(); await sleep(70); }
      await sleep(0); await sleep(0);
      window.__echoIgnore = false;
      obs.disconnect();
      return { answered: answer.length, trueLen: trueSeq.length, paleLen: paleSeq.length, wrongInfo, harassHeld };
    }
    obs.disconnect();
    return { answered: -1, trueLen: trueSeq.length, paleLen: paleSeq.length, wrongInfo, harassHeld };
  })()`);
}

const r1 = await playStage(1, false, true);
check("rapid clicks during Watch were swallowed", r1.harassHeld === true);
check("stage 1: 3 true echoes, no lies", r1.trueLen === 3 && r1.paleLen === 0, JSON.stringify(r1));
await waitFor(`/Stage 2 of 4/.test(document.getElementById("phantom-stage").textContent)`, 15000, "stage 2 banner");
check("stage 1 cleared → stage 2 banner", await evaluate(
  `/Stage 2 of 4/.test(document.getElementById("phantom-stage").textContent)`, false));

const r2 = await playStage(2, true);
check("stage 2: 4 true echoes, 1 lie", r2.trueLen === 4 && r2.paleLen === 1, JSON.stringify(r2));
check("the deliberate wrong press was rejected with a reason", (r2.wrongInfo?.fbAfter || "").length > 0,
  (r2.wrongInfo?.fbAfter || "").slice(0, 60));
check("the wrong press kept the SAME stage", /Stage 2 of 4/.test(r2.wrongInfo?.bannerAfter || ""),
  (r2.wrongInfo?.bannerAfter || "").slice(0, 40));
const r2b = await playStage(2);
check("stage 2 cleared after the retry", r2b.trueLen === 4, JSON.stringify(r2b));
await waitFor(`/Stage 3 of 4/.test(document.getElementById("phantom-stage").textContent)`, 15000, "stage 3 banner");

const r3 = await playStage(3);
check("stage 3: 4 true echoes, 1 lie, answered in reverse", r3.trueLen === 4 && r3.paleLen === 1, JSON.stringify(r3));
await waitFor(`/Stage 4 of 4/.test(document.getElementById("phantom-stage").textContent)`, 15000, "stage 4 banner");

const r4 = await playStage(4);
check("stage 4: 5 true echoes, 2 lies, answered in reverse", r4.trueLen === 5 && r4.paleLen === 2, JSON.stringify(r4));
await waitFor(`(() => { const e = document.getElementById("ending-overlay"); return e && !e.hidden; })()`, 15000, "the ending");
check("completion triggers the ending sequence", await visible("#ending-overlay"));
// Click through every beat first, THEN assert on the accumulated text (all beats stay rendered).
for (let i = 0; i < 14; i++) {
  if (await evaluate(`/Return to the Sanctum/.test(document.getElementById("ending-continue").textContent)`, false)) break;
  await click("#ending-continue");
  await sleep(320);
}
const endingText = await evaluate(`document.getElementById("ending-text").textContent`, false);
check("the ending reaches its final beat", await evaluate(
  `/Return to the Sanctum/.test(document.getElementById("ending-continue").textContent)`, false));
check("the ending resolves the Lost Epoch", /Lost Epoch/i.test(endingText) && /final/i.test(endingText));
check("the ending lands the privacy theme", /purse|balance/i.test(endingText));
check("the Phantom gets his sign-off", /Phantom/i.test(endingText));
await click("#ending-continue");
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 10000, "sanctum after ending");
check("the ending returns to the Sanctum", await visible("#sanctum"));
check("all three fragments held", await evaluate(
  `document.getElementById("hud-frags").textContent === "3"`, false));

console.log("\n== 7. quorum gate, case file, whispers, persistence, reload ==");
// The stage-4 gate, negative side: a file that claims stage 4 but holds NO fragments.
await goto(GAME);
await evaluate(`localStorage.setItem("${STORE}", JSON.stringify({fragments:{},puzzles:{abyssStage:4},secrets:{},previewUnlocked:[],endingSeen:false}))`, false);
await goto(GAME);
await sleep(500);
await click("#btn-preview");
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 15000, "sanctum (empty file)");
await click("#door-abyss .door-enter");
await waitFor(`(() => { const c = document.getElementById("chamber-abyss"); return c && !c.hidden; })()`, 10000, "abyss (empty file)");
await click("#phantom-begin");
await sleep(400);
check("stage 4 demands a quorum of evidence", await evaluate(
  `/quorum/.test(document.getElementById("phantom-line").textContent)`, false));
check("no ending on an incomplete case", (await hidden("#ending-overlay")) === true);
await click(`#chamber-abyss .chamber-leave`);
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 10000, "sanctum");

// Positive side: the same stage-4 file WITH fragments I and II — the audit may proceed.
await evaluate(`localStorage.setItem("${STORE}", JSON.stringify({fragments:{crypt:1,vault:1},puzzles:{abyssStage:4},secrets:{},previewUnlocked:[],endingSeen:false}))`, false);
await goto(GAME);
await sleep(500);
await click("#btn-preview");
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 15000, "sanctum (partial file)");
await waitFor(`document.getElementById("hud-frags").textContent === "2"`, 15000, "HUD renders the two held fragments");
check("HUD shows the two held fragments", await evaluate(
  `document.getElementById("hud-frags").textContent === "2"`, false));
await waitFor(`["crypt","vault"].every(g => document.getElementById("door-"+g).querySelector(".door-frag").textContent.includes("recovered"))`, 15000, "door fragment lines render");
check("doors report recovered fragments", await evaluate(
  `["crypt","vault"].every(g => document.getElementById("door-"+g).querySelector(".door-frag").textContent.includes("recovered")) &&
   document.getElementById("door-abyss").querySelector(".door-frag").textContent.includes("sealed within")`, false));
await click("#door-abyss .door-enter");
await waitFor(`(() => { const c = document.getElementById("chamber-abyss"); return c && !c.hidden; })()`, 10000, "abyss (partial file)");
await click("#phantom-begin");
await sleep(400);
check("with the quorum held, the final audit proceeds", await evaluate(
  `/Watch/.test(document.getElementById("phantom-feedback").textContent)`, false));
await click(`#chamber-abyss .chamber-leave`);
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 10000, "sanctum");

// Case file + whisper + reload persistence on the partial file.
await click("#btn-casefile");
await sleep(300);
check("the case file lists the held fragments", await evaluate(
  `document.getElementById("casefile-list").textContent.includes("Fragment I") &&
   document.getElementById("casefile-list").textContent.includes("Fragment II") &&
   !document.getElementById("casefile-list").textContent.includes("Fragment III")`, false));
await click("#casefile-close");
await sleep(300);
await click("#door-crypt .door-enter");
await waitFor(`(() => { const c = document.getElementById("chamber-crypt"); return c && !c.hidden; })()`, 10000, "crypt (partial file)");
await click("#chamber-crypt .secret-glyph");
await waitFor(`(() => { const w = document.getElementById("whisper-overlay"); return w && !w.hidden; })()`, 8000, "whisper overlay");
check("a whisper appears on the ∴ glyph", await visible("#whisper-overlay"));
await click("#whisper-close");
await sleep(300);
await click(`#chamber-crypt .chamber-leave`);
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 10000, "sanctum again");
await goto(GAME); // full reload
await sleep(500);
check("reload returns to the title (no trap)", await visible("#title-screen"));
await click("#btn-preview");
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 15000, "sanctum after reload");
await waitFor(`document.getElementById("hud-frags").textContent === "2"`, 15000, "HUD after reload");
check("fragments persist across reload", await evaluate(
  `document.getElementById("hud-frags").textContent === "2"`, false));
check("whispers persist across reload", await evaluate(
  `JSON.parse(localStorage.getItem("${STORE}")).secrets.crypt > 0`, false));

console.log("\n== 8. no-wallet failure path never strands the player ==");
await goto(GAME);
await sleep(500);
await clickNoWait("#btn-enter");
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 20000, "sanctum after Connect a wallet");
check("Connect a wallet reaches the Sanctum", await visible("#sanctum"));
check("no overlay after Connect a wallet", (await hidden("#proof-overlay")) && (await hidden("#fragment-overlay")));
check("wallet status is explained, not silent", await evaluate(
  `document.getElementById("sanctum-status").textContent.trim().length > 0`, false));
await clickNoWait("#door-crypt .door-prove");
await sleep(3000);
check("pressing a door with no wallet leaves NO stuck overlay", (await visible("#proof-overlay")) === false);
check("player is still in the game", await visible("#sanctum"));
await click("#btn-back-title");
await sleep(500);
check("Leave returns to the title screen", await visible("#title-screen"));

console.log("\n== 9. console / network hygiene + mobile ==");
check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | ") || "none");
const realFailed = failedRequests.filter((f) => !/net::ERR_ABORTED/.test(f));
check("no failed network requests", realFailed.length === 0, realFailed.slice(0, 3).join(" | ") || "none");
check("no proof endpoints were EVER called this run", proofCalls.length === 0, proofCalls.join(",") || "none");

// Mobile layout: 390x844, no horizontal overflow on title or sanctum.
await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
await goto(GAME);
await sleep(600);
const mobTitle = await evaluate(`document.documentElement.scrollWidth - document.documentElement.clientWidth`, false);
await click("#btn-preview");
await waitFor(`(() => { const s = document.getElementById("sanctum"); return s && !s.hidden; })()`, 15000, "mobile sanctum");
const mobSanctum = await evaluate(`document.documentElement.scrollWidth - document.documentElement.clientWidth`, false);
check("mobile: no horizontal overflow on the title", mobTitle === 0, `${mobTitle}px`);
check("mobile: no horizontal overflow in the Sanctum", mobSanctum === 0, `${mobSanctum}px`);
await call("Emulation.clearDeviceMetricsOverride");

console.log(`\n== RESULT: ${passCount} passed, ${failCount} failed ==`);
process.exit(failCount ? 1 : 0);
