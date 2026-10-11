/**
 * CDP harness for the real-browser Haunted Vault check (scripts/browser_game_check.sh).
 *
 * Speaks Chrome DevTools Protocol over the WebSocket that Node ships (>=22), so there is no npm
 * dependency and nothing to install. It drives the page the way a person would -- reading computed
 * styles and actually clicking -- because the bug that prompted this harness (an overlay rendered
 * over the title on first paint) was invisible to any test that does not lay the page out.
 *
 * Every assertion prints PASS/FAIL with the evidence it used, and the script exits non-zero on any
 * failure or on any console error / failed request, so it is usable as a gate.
 */

// The port arrives as argv, not env: WSL does not forward environment variables to Windows
// binaries unless they are listed in WSLENV, and silently falling back to a default port would
// attach this harness to some OTHER headless Edge that still holds it.
const PORT = process.argv[2] || process.env.CDP_PORT;
if (!PORT) throw new Error("usage: node cdp-game-check.mjs <cdp-port>");
const GAME = "http://127.0.0.1:7799/game";

let ws, nextId = 1;
const pending = new Map();
const consoleErrors = [];
const failedRequests = [];
const proofCalls = []; // any hit on challenge/prove/credential -- must stay empty in preview

function send(method, params = {}) {
  const id = nextId++;
  const msg = { id, method, params };
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify(msg));
  });
}

const call = (m, p) => send(m, p);

/** Evaluate an expression in the page; returns the JSON value. */
async function evaluate(expression) {
  const r = await call("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
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

/* ------------------------------ connect ------------------------------ */

async function connect() {
  // Attach straight to the page target's own WebSocket -- more robust than the browser socket's
  // flat-session attach, which some Edge builds reject with "Invalid parameters".
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
    // events
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
  // Wait for load event.
  for (let i = 0; i < 80; i++) {
    const ready = await evaluate("document.readyState").catch(() => null);
    if (ready === "complete") return;
    await sleep(50);
  }
}

/* ------------------------------ helpers ------------------------------ */

const visible = (sel) => evaluate(`(() => {
  const el = document.querySelector(${JSON.stringify(sel)});
  if (!el) return "MISSING";
  const cs = getComputedStyle(el);
  const r = el.getBoundingClientRect();
  const shown = cs.display !== "none" && cs.visibility !== "hidden" && parseFloat(cs.opacity) > 0
    && r.width > 0 && r.height > 0;
  return { shown, display: cs.display, visibility: cs.visibility, w: Math.round(r.width), h: Math.round(r.height) };
})()`);

const click = (sel) => evaluate(`(() => {
  const el = document.querySelector(${JSON.stringify(sel)});
  if (!el) return "MISSING";
  el.click();
  return "clicked";
})()`);

/**
 * Wait until `expr` (evaluated in the page) is truthy, instead of sleeping a fixed amount. Entering
 * the Sanctum awaits a gate-metadata fetch per door before it renders them, and on a cold bridge
 * that can outlast any fixed pause -- which is how a green game looked broken in the harness.
 */
async function waitFor(expr, timeoutMs = 15000, label = expr) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let v = false;
    try { v = await evaluate(expr); } catch { /* mid-navigation */ }
    if (v) return true;
    await sleep(100);
  }
  console.log(`  (timeout waiting for: ${label})`);
  return false;
}

/* ------------------------------ the checks ------------------------------ */

async function main() {
  await connect();
  // The abyss plays its sequence from page load, so the recorder is installed as a new-document
  // script BEFORE any navigation -- it must be armed before the puzzle's first flash. It records
  // each time a pad gains .flash (the animation restart), which is exactly one echo of the sequence.
  await call("Page.addScriptToEvaluateOnNewDocument", {
    source: `
      (function () {
        // New-document scripts persist for the life of the browser target, so this file may be
        // installed more than once across harness runs. Arm exactly once, or every flash is
        // recorded N times and the player replays phantom echoes that fail.
        if (window.__echoRecArmed) return;
        window.__echoRecArmed = true;
        var rec = (window.__echoRec = []);
        document.addEventListener("DOMContentLoaded", function () {
          document.querySelectorAll("#abyss-pads .echo").forEach(function (e) {
            new MutationObserver(function (muts) {
              for (var m of muts) {
                var has = m.target.classList.contains("flash");
                var had = (m.oldValue || "").includes("flash");
                // Ignore echoes the PLAYER makes: echoPress flashes the pad it was given, and those
                // are not part of the sequence the abyss is asking us to repeat.
                if (has && !had && !window.__echoIgnore) rec.push(Number(m.target.dataset.i));
              }
            }).observe(e, { attributes: true, attributeOldValue: true });
          });
        });
      })();
    `,
  });

  console.log("\n== 1. startup: /game shows the TITLE screen, overlays hidden ==");
  await goto(GAME);
  // Start from a known-clean save. This is a test fixture, not evidence handling: the reported bug
  // was reproduced and diagnosed with storage intact (see docs/GAME_STARTUP_FIX.md). Progress is
  // cosmetic and persisted by design, so a repeat run must reset it to re-test the first-solve
  // reward path.
  await evaluate(`localStorage.removeItem("ghost-gate-vault-progress-v1"); "cleared"`);
  await goto(GAME); // reload with clean storage
  await sleep(400); // let module script boot

  const title = await visible("#title-screen");
  check("title screen is visible", title.shown, JSON.stringify(title));

  for (const [sel, label] of [
    ["#proof-overlay", "proof overlay"],
    ["#relic-overlay", "relic overlay"],
    ["#sanctum", "sanctum"],
    ["#chamber-crypt", "crypt chamber"],
  ]) {
    const v = await visible(sel);
    check(`${label} is hidden on load`, v.display === "none", `display=${v.display}`);
  }

  // The reported defect in one assertion: no full-screen fixed dark overlay is painted.
  const bodyPaint = await evaluate(`(() => {
    const p = document.querySelector("#proof-overlay");
    const cs = getComputedStyle(p);
    return { display: cs.display, backdrop: cs.backdropFilter || cs.webkitBackdropFilter || "none" };
  })()`);
  check("proof overlay not painted (no dark blur over title)", bodyPaint.display === "none", JSON.stringify(bodyPaint));

  const titleText = await evaluate(`document.querySelector(".title-wrap")?.innerText || ""`);
  check("title shows GHOST GATE", /GHOST/.test(titleText) && /GATE/.test(titleText));

  console.log("\n== 2. Enter Preview navigates to the Sanctum ==");
  await click("#btn-preview");
  // Wait for the doors to actually render (the Sanctum draws them after the gate metadata loads).
  await waitFor(
    `["crypt","vault","abyss"].every(g => { const d = document.getElementById("door-"+g);
       const e = d && d.querySelector(".door-enter"); return e && !e.hidden; })`,
    15000,
    "all three preview doors rendered",
  );
  const sanctum = await visible("#sanctum");
  check("sanctum visible after preview", sanctum.shown, JSON.stringify(sanctum));
  const banner = await visible("#preview-banner");
  check("PREVIEW banner shown", banner.shown, JSON.stringify(banner));
  const doorsOpen = await evaluate(`["crypt","vault","abyss"].map(g => {
    const d = document.getElementById("door-"+g);
    return d.querySelector(".door-enter") && !d.querySelector(".door-enter").hidden;
  })`);
  check("all three doors enterable in preview", doorsOpen.every(Boolean), JSON.stringify(doorsOpen));

  console.log("\n== 3. preview calls NO proof endpoints ==");
  check("no challenge/prove/credential calls in preview", proofCalls.length === 0, proofCalls.join(",") || "none");

  console.log("\n== 4. play The Crypt (candle sequence 2,0,3,1) ==");
  await click("#door-crypt .door-enter");
  await waitFor(`(() => { const c = document.getElementById("chamber-crypt"); return c && !c.hidden; })()`, 10000, "crypt chamber open");
  check("crypt chamber visible", (await visible("#chamber-crypt")).shown);
  const cryptBefore = await evaluate(`document.querySelectorAll("#crypt-candles .candle").length`);
  check("four candles present", cryptBefore === 4, "n=" + cryptBefore);
  // wrong order first, to prove the failure path, then the right one
  await evaluate(`document.querySelectorAll("#crypt-candles .candle")[0].click()`); // wrong (want 2 first)
  await sleep(150);
  const wrongReset = await evaluate(`document.querySelectorAll("#crypt-candles .candle.lit").length`);
  check("wrong candle order resets the vigil", wrongReset === 0, "lit=" + wrongReset);
  await evaluate(`(() => { for (const i of [2,0,3,1]) document.querySelectorAll("#crypt-candles .candle")[i].click(); })()`);
  await waitFor(`(() => { const r = document.getElementById("relic-overlay"); return r && !r.hidden; })()`, 10000, "crypt reward dialog");
  const relicAfterCrypt = await visible("#relic-overlay");
  check("crypt reward dialog appears after solving", relicAfterCrypt.shown, JSON.stringify(relicAfterCrypt));
  const relicTitle = await evaluate(`document.querySelector("#relic-title")?.textContent || ""`);
  check("relic is the Vigil candle (cosmetic 🕯, not a burn)", /Vigil/.test(relicTitle), relicTitle);
  await click("#relic-close");
  await sleep(300);
  check("relic dialog dismisses via Keep it", (await visible("#relic-overlay")).display === "none");

  console.log("\n== 5. play The Forgotten Vault (rings T,T,G) ==");
  await click("#door-vault .door-enter");
  await waitFor(`(() => { const c = document.getElementById("chamber-vault"); return c && !c.hidden; })()`, 10000, "vault chamber open");
  check("vault chamber visible", (await visible("#chamber-vault")).shown);
  // click each ring until its target glyph sits under the pointer (T,T,G), via the on-screen state line
  const solvedVault = await evaluate(`(async () => {
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));
    const rings = [...document.querySelectorAll("#vault-sigil .ring")];
    const target = {0:"T", 1:"T", 2:"G"};
    for (let i = 0; i < 40; i++) {
      const line = document.getElementById("vault-state").textContent;
      const parts = line.split("·");
      const allOk = parts.every(p => p.includes("✓"));
      if (allOk) return true;
      // find first ring not aligned, click it
      const bad = parts.findIndex(p => !p.includes("✓"));
      rings[bad]?.click();
      await sleep(30);
    }
    return document.getElementById("vault-state").textContent;
  })()`);
  await waitFor(`(() => { const r = document.getElementById("relic-overlay"); return r && !r.hidden; })()`, 10000, "vault reward dialog");
  check("vault rings solved", solvedVault === true, String(solvedVault));
  check("vault reward dialog appears", (await visible("#relic-overlay")).shown);
  await click("#relic-close");
  await sleep(300);

  console.log("\n== 6. play The Abyss (echo memory, cumulative, 4 rounds) ==");
  // The abyss plays its sequence from page load, so give it a FRESH page and walk straight in --
  // exactly what a player who enters preview and goes directly to the Abyss experiences. Without
  // the reload, the earlier Crypt/Vault clicks would leave the abyss desynced from the recorder.
  await goto(GAME);
  await sleep(400);
  await click("#btn-preview");
  await waitFor(`["crypt","vault","abyss"].every(g => { const d = document.getElementById("door-"+g);
       const e = d && d.querySelector(".door-enter"); return e && !e.hidden; })`, 15000, "preview doors rendered");
  await click("#door-abyss .door-enter");
  await waitFor(`(() => { const c = document.getElementById("chamber-abyss"); return c && !c.hidden; })()`, 10000, "abyss chamber open");
  check("abyss chamber visible", (await visible("#chamber-abyss")).shown);
  const solvedAbyss = await evaluate(`(async () => {
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));
    const hint = document.getElementById("abyss-hint");
    // Self-synchronising: the recorder holds every echo since the last drain, so on "Your turn"
    // exactly that list is the sequence to repeat -- no need to guess the round number from the
    // "Round N of 4" text, which may already have scrolled past. \`pressed\` stops a second drain
    // inside the same turn (the hint stays "Your turn." until the next round starts watching).
    let pressed = false;
    for (let guard = 0; guard < 900; guard++) {
      const txt = hint.textContent;
      if (txt.includes("stops asking")) return true;
      const yourTurn = txt.includes("Your turn");
      if (!yourTurn) pressed = false;
      if (yourTurn && !pressed && window.__echoRec.length) {
        const toPress = window.__echoRec.splice(0, window.__echoRec.length);
        window.__echoIgnore = true;   // our own presses must not be recorded as sequence echoes
        for (const i of toPress) { document.querySelector("#abyss-pads .echo[data-i=\\"" + i + "\\"]").click(); await sleep(60); }
        // MutationObserver delivers asynchronously, so let the queued records drain into the
        // (ignored) recorder before lowering the flag, or a press is captured a tick too late.
        await sleep(0);
        await sleep(0);
        window.__echoIgnore = false;
        pressed = true;
        await sleep(300);
      }
      await sleep(40);
    }
    return hint.textContent;
  })()`);
  await waitFor(`(() => { const r = document.getElementById("relic-overlay"); return r && !r.hidden; })()`, 10000, "abyss reward dialog");
  check("abyss solved (watch & repeat)", solvedAbyss === true, String(solvedAbyss));
  check("abyss reward dialog appears", (await visible("#relic-overlay")).shown);
  await click("#relic-close");
  await sleep(300);

  console.log("\n== 7. back to menu, reload, no trap ==");
  // leaveChamber runs on relic close; we should be in the sanctum already.
  check("back in sanctum after final relic", (await visible("#sanctum")).shown);
  await goto(GAME); // full reload
  await sleep(500);
  const titleAgain = await visible("#title-screen");
  check("reload returns to the title screen (not trapped)", titleAgain.shown, JSON.stringify(titleAgain));
  check("no overlay re-shown after reload", (await visible("#relic-overlay")).display === "none");

  console.log("\n== 8. console / network hygiene ==");
  check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | ") || "none");
  const realFailed = failedRequests.filter((f) => !/net::ERR_ABORTED/.test(f));
  check("no failed network requests", realFailed.length === 0, realFailed.slice(0, 3).join(" | ") || "none");
  check("still no proof calls across whole run", proofCalls.length === 0, proofCalls.join(",") || "none");

  console.log(`\n== RESULT: ${passCount} passed, ${failCount} failed ==`);
  process.exit(failCount ? 1 : 0);
}

main().catch((e) => { console.error("HARNESS ERROR:", e.message); process.exit(2); });