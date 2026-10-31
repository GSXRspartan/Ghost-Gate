/**
 * CDP harness for the PRIVACY LAB "Resume existing proof" flow (scripts/lab_resume_check.sh).
 *
 * Simulated-provider UI test — NOT a physical wallet test. It injects a RECORDING mock
 * window.tari before page load, drives the real page, and asserts the exact network and
 * wallet-call sequence a resume attempt produces. The physical Sapient signature prompt is
 * the operator's milestone and stays theirs to confirm.
 *
 * Proven here:
 *   A. the default gate is the credential gate (esm10), the resume row is visible, and the
 *      wallet selector defaults to Sapient — never to the wallet daemon
 *   B. after a stale walletd refusal (the physical-test state: outcome denied, step rail
 *      parked at the submit/consensus steps), clicking Resume existing proof
 *        - clears the stale outcome and restarts the rail,
 *        - mints a FRESH challenge (POST /gate/esm10/challenge),
 *        - calls tari_signOwnershipChallenge EXACTLY ONCE, over the EXISTING output, with
 *          the gate's resource passed explicitly,
 *        - POSTs /gate/esm10/credential (the mock signature is refused 409 by the REAL
 *          bridge, which is the honest expected end state in a mock environment),
 *        - and NEVER calls tari_createTransactionRequest, tari_submitTransactionRequest or
 *          POST /gate/esm10/prove for the credential gate.
 *   C. signature failures read through the provider-error taxonomy: -32603 is the wallet's
 *      internal error, 4001 is the user's decline, 4100 is "not connected" — none of them is
 *      mislabelled as a rejected transaction.
 *   D. a successful credential verdict renders the two honest success states (rendering-only:
 *      the POST response is stubbed, clearly labelled in the output):
 *        D1. access: null  ->  "PROOF VERIFIED — SESSION NOT ISSUED" (the preview-bridge truth;
 *            the old page wrongly showed ACCESS GRANTED here),
 *        D2. a real access token -> "ACCESS GRANTED" with the session duration,
 *      and both render the receipt floor AND required threshold in tTARI (the "null tTARI"
 *      regression: the receipt's required_minimum must reach the page).
 *
 * Usage: node cdp-resume-check.mjs <cdp-port> <lab-url>
 */

const PORT = process.argv[2] || process.env.CDP_PORT;
const LAB = process.argv[3] || "http://127.0.0.1:7897/lab";
if (!PORT) throw new Error("usage: node cdp-resume-check.mjs <cdp-port> [lab-url]");

const UTXO = "utxo_0101010101010101010101010101010101010101010101010101010101010101_5ad3313f43e35ac5d89c7e5819ad12852aacc6534a21ddbf6b237b7fc5be8c6f";
const RESOURCE = "resource_0101010101010101010101010101010101010101010101010101010101010101";

let ws, nextId = 1;
const pending = new Map();
const consoleErrors = [];
const passed = [], failed = [];

function check(label, ok, detail = "") {
  (ok ? passed : failed).push(label);
  console.log(`  ${ok ? "ok  " : "FAIL"} ${label.padEnd(58)} ${detail}`);
}

function send(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function evaluate(expression, awaitPromise = false) {
  const r = await send("Runtime.evaluate", {
    expression, returnByValue: true, awaitPromise, userGesture: true,
  });
  if (r.exceptionDetails) {
    throw new Error(`page threw: ${JSON.stringify(r.exceptionDetails).slice(0, 300)}`);
  }
  return r.result?.value;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A recording mock: every wallet call is logged with its params; the ownership signature
 *  succeeds; and any attempt to SHIELD (createTransactionRequest) is recorded and then
 *  rejected by the wallet — so if the resume path ever drifted back to the shield flow, the
 *  page would show WALLET REFUSED and the assertion on the call log fails loudly. */
const MOCK_RECORDING = `
  window.__ggWalletCalls = [];
  window.tari = {
    isTariWallet: true,
    request(args) {
      window.__ggWalletCalls.push({ method: args.method, params: args.params || null });
      const m = args.method;
      if (m === "tari_getCapabilities") {
        return Promise.resolve({
          privateSpend: true, minimumValuePromise: true, ownershipProof: true,
          walletOwnershipProof: true, transactionResultLookup: true, transactionRequests: true,
        });
      }
      if (m === "tari_requestAccounts") {
        return Promise.resolve(["otl_esm_1rghzs3zkfrvajj39r7pm26q7uwne6dxrm2ztf29aq8y4zezpppjs95znmg2rgwr6rjgxq2p7xzrpy3h5nc8q22gnkudn9axgsruxjuqae5f2t"]);
      }
      if (m === "tari_getNetwork") return Promise.resolve("esmeralda");
      if (m === "tari_signOwnershipChallenge") {
        return Promise.resolve({ publicKey: "pk", publicNonce: "ab".repeat(32), signature: "cd".repeat(64) });
      }
      if (m === "tari_createTransactionRequest") {
        // Recorded above; the wallet then REJECTS the shield request. Any shield attempt
        // during a resume therefore ends in WALLET REFUSED — loud, and asserted against.
        return Promise.resolve({ requestId: "mock-shield-1" });
      }
      if (m === "tari_getTransactionRequest") {
        return Promise.resolve({ status: "rejected", error: "mock: shield must never run during resume" });
      }
      return Promise.reject(Object.assign(new Error("mock: unsupported " + m), { code: 4200 }));
    },
  };
  window.__ggFetch = [];
  var __origFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    const url = typeof input === "string" ? input : (input && input.url) || "";
    const method = ((init && init.method) || (input && input.method) || "GET").toUpperCase();
    const entry = { method, url, body: (init && init.body) || null };
    window.__ggFetch.push(entry);
    if (window.__ggStubCredential && method === "POST" && /\\/gate\\/esm10\\/credential$/.test(url)) {
      return Promise.resolve(new Response(JSON.stringify({
        state: "accepted",
        proof_id: "stubbed-rendering-test",
        receipt: { attested_minimum: 10000000, required_minimum: 10000000, proof_kind: "credential", input_count: 1 },
        // The page decides the success title from the "access" field: null = verified-only,
        // a token object = a real granted session. The harness sets this per scenario.
        access: window.__ggStubAccess !== undefined ? window.__ggStubAccess : null,
      }), { status: 200, headers: { "Content-Type": "application/json" } }));
    }
    return __origFetch(input, init);
  };
  window.dispatchEvent(new Event("tari#initialized"));
`;

/** Signature-failure mocks for the taxonomy: each rejects the ownership signature with a
 *  distinct, real-shaped error, and everything else answers normally. */
const mockSignFails = (code, message) => `
  window.__ggWalletCalls = [];
  window.tari = {
    isTariWallet: true,
    request(args) {
      window.__ggWalletCalls.push({ method: args.method, params: args.params || null });
      const m = args.method;
      if (m === "tari_getCapabilities") {
        return Promise.resolve({
          privateSpend: true, minimumValuePromise: true, ownershipProof: true,
          walletOwnershipProof: true, transactionResultLookup: true, transactionRequests: true,
        });
      }
      if (m === "tari_requestAccounts") {
        return Promise.resolve(["otl_esm_1rghzs3zkfrvajj39r7pm26q7uwne6dxrm2ztf29aq8y4zezpppjs95znmg2rgwr6rjgxq2p7xzrpy3h5nc8q22gnkudn9axgsruxjuqae5f2t"]);
      }
      if (m === "tari_getNetwork") return Promise.resolve("esmeralda");
      if (m === "tari_signOwnershipChallenge") {
        return Promise.reject(Object.assign(new Error(${JSON.stringify(message)}), { code: ${code} }));
      }
      return Promise.reject(Object.assign(new Error("mock: unsupported " + m), { code: 4200 }));
    },
  };
  window.__ggFetch = [];
  window.dispatchEvent(new Event("tari#initialized"));
`;

async function connect() {
  const targets = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
  const page = targets.find((t) => t.type === "page");
  if (!page) throw new Error("no page target to drive");
  ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", reject, { once: true });
  });
  ws.addEventListener("message", (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result || {});
      return;
    }
    if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") {
      consoleErrors.push(msg.params.args.map((a) => a.value ?? a.description ?? "").join(" "));
    }
    if (msg.method === "Runtime.exceptionThrown") {
      consoleErrors.push(msg.params.exceptionDetails?.exception?.description || "exception");
    }
  });
  await send("Page.enable");
  await send("Runtime.enable");
}

// Init scripts ACCUMULATE in the browser: every script added stays attached to every later
// navigation, so a second mock re-declaring the same top-level binding kills the whole script
// (a real SyntaxError seen in the first run). Track and remove each one before adding the next.
const attachedScripts = [];

async function loadPage(initScript, url = LAB) {
  for (const id of attachedScripts.splice(0)) {
    try { await send("Page.removeScriptToEvaluateOnNewDocument", { identifier: id }); } catch { /* gone */ }
  }
  const added = await send("Page.addScriptToEvaluateOnNewDocument", { source: initScript });
  if (added && added.identifier) attachedScripts.push(added.identifier);
  await send("Page.navigate", { url });
  // Wait until the page's critical elements are actually in the DOM. A fixed sleep races
  // against a cold-start headless browser; polling for readiness is deterministic.
  for (let i = 0; i < 40; i++) {
    const ready = await evaluate(
      `!!document.getElementById("gate-select") && !!document.getElementById("resume-proof")`,
    ).catch(() => false);
    if (ready) break;
    await sleep(250);
  }
  await sleep(500); // let the page's own JS settle
}

/** Waits until the outcome panel is visible with a title, up to `ms`. */
async function waitOutcome(ms = 15000) {
  const deadline = Date.now() + ms;
  for (;;) {
    const o = await evaluate(`(() => {
      const p = document.getElementById("outcome");
      return p && !p.hidden ? { title: document.getElementById("outcome-title").textContent,
                                 body: document.getElementById("outcome-body").textContent,
                                 detail: document.getElementById("outcome-detail").textContent,
                                 cls: p.className } : null;
    })()`);
    if (o && o.title) return o;
    if (Date.now() > deadline) return null;
    await sleep(400);
  }
}

async function runResume() {
  await evaluate(`(() => {
    document.getElementById("resume-substate").value = ${JSON.stringify(UTXO)};
    document.getElementById("resume-proof").click();
    return true;
  })()`);
  return waitOutcome();
}

async function main() {
  await connect();

  console.log("\n== A. default selection: credential gate, Sapient wallet, resume row visible ==");
  await loadPage(MOCK_RECORDING, LAB);
  const sel = await evaluate(`(() => {
    // Defensive lookups: if the page's JS failed to initialize, these are null — report
    // that honestly instead of throwing an uncaught TypeError that kills the harness.
    const gateEl = document.getElementById("gate-select");
    const modeEl = document.getElementById("gt-mode");
    const walletEl = document.getElementById("wallet-select");
    const rowEl = document.getElementById("resume-row");
    return {
      gate: gateEl ? gateEl.value : null,
      mode: modeEl ? modeEl.textContent : null,
      wallet: walletEl ? walletEl.value : null,
      rowHidden: rowEl ? rowEl.hidden : null,
    };
  })()`);
  check("default gate is the credential gate (esm10)", sel.gate === "esm10", sel.gate);
  check("gate badge reads credential", /credential/.test(sel.mode || ""), sel.mode);
  check("wallet selector defaults to Sapient, not walletd", sel.wallet === "sapient", sel.wallet);
  check("resume row visible on a credential gate", sel.rowHidden === false, `hidden=${sel.rowHidden}`);

  console.log("\n== B. stale walletd refusal, then Resume existing proof ==");
  // Reproduce the operator's stuck state first: a DENIED outcome left on screen, the step rail
  // parked. On the original bridge this was done through the real consensus gate + walletd;
  // the live bridge now carries ONLY the credential gate (the operator removed esm-diag), so
  // when that gate is absent we inject the stale outcome via the page's own outcome panel —
  // the resume flow must clear whatever stale UI state it finds, however it got there.
  const hasDiagGate = await evaluate(`[...document.getElementById("gate-select").options].some(o => o.value === "esm-diag")`);
  let stale;
  if (hasDiagGate) {
    await evaluate(`(() => {
      const g = document.getElementById("gate-select");
      g.value = "esm-diag"; g.dispatchEvent(new Event("change"));
      return true;
    })()`);
    await sleep(500);
    await evaluate(`document.getElementById("prove").click()`);
    stale = await waitOutcome(20000);
    check("stale walletd refusal reproduced (denied outcome)", !!stale && stale.cls.includes("denied"),
      stale ? `${stale.title}: ${stale.body.slice(0, 80)}` : "no outcome");
  } else {
    await evaluate(`(() => {
      const p = document.getElementById("outcome");
      p.hidden = false; p.className = "outcome denied";
      document.getElementById("outcome-title").textContent = "WALLET REFUSED";
      document.getElementById("outcome-body").textContent = "the wallet rejected the proof transaction (injected stale state)";
      // Park the step rail mid-flow the way the stuck physical test left it.
      const li = document.querySelector("#steps li[data-step='consensus']");
      if (li) { li.className = "active"; }
      return true;
    })()`);
    stale = { title: "WALLET REFUSED", cls: "outcome denied" };
    check("stale refusal state injected (single-gate bridge: esm-diag not configured)", true, "injected via outcome panel");
  }
  // Back to the credential gate, paste the EXISTING output, click Resume existing proof.
  await evaluate(`(() => {
    const g = document.getElementById("gate-select");
    g.value = "esm10"; g.dispatchEvent(new Event("change"));
    return true;
  })()`);
  await sleep(500);
  const outcome = await runResume();
  check("resume replaced the stale outcome (no WALLET REFUSED)",
    !!outcome && outcome.title !== "WALLET REFUSED",
    outcome ? `${outcome.title}: ${outcome.body.slice(0, 80)}` : "no outcome");
  check("resume ends in the honest 409 (mock signature cannot verify on the real chain)",
    !!outcome && outcome.title === "PROOF REFUSED",
    outcome ? `${outcome.title} ${(outcome.detail || "").slice(0, 120)}` : "no outcome");
  const activeStep = await evaluate(`document.querySelector("#steps li.active") ? document.querySelector("#steps li.active").dataset.step : null`);
  check("step rail advanced past submit (not stuck at step 5)", ["consensus", "verify"].includes(activeStep), activeStep);
  check("credential step is relabelled (no block wait shown)",
    await evaluate(`[...document.querySelectorAll("#steps .step-title")].some(t => /Verify the signed output/.test(t.textContent))`));
  const fetches = await evaluate(`window.__ggFetch.map(f => f.method + " " + f.url.replace(location.origin, ""))`);
  check("fresh challenge minted on esm10", fetches.includes("POST /gate/esm10/challenge"), fetches.join(" | "));
  check("credential verdict POSTed to esm10", fetches.some((f) => f.startsWith("POST /gate/esm10/credential")), fetches.join(" | "));
  check("NO /prove call on the credential gate", !fetches.includes("POST /gate/esm10/prove"), fetches.join(" | "));
  const credBody = await evaluate(`(window.__ggFetch.find(f => f.method === "POST" && f.url.endsWith("/gate/esm10/credential")) || {}).body`);
  let credOk = false, credNote = "no credential POST body";
  if (credBody) {
    try {
      const b = JSON.parse(credBody);
      credOk = b.substate_id === UTXO && b.gate_id === "esm10"
        && /^[0-9a-f]{64}$/.test(b.challenge_nonce || "")
        && !!b.signature && !!b.public_nonce;
      credNote = `substate_id ok=${b.substate_id === UTXO}, gate=${b.gate_id}, sig=${!!b.signature}`;
    } catch (e) { credNote = String(e); }
  }
  check("credential POST carries the EXISTING output + signature", credOk, credNote);
  const calls = await evaluate(`window.__ggWalletCalls.map(c => c.method)`);
  check("exactly ONE ownership signature call", calls.filter((m) => m === "tari_signOwnershipChallenge").length === 1, calls.join(" | "));
  const signParams = await evaluate(`(window.__ggWalletCalls.find(c => c.method === "tari_signOwnershipChallenge") || {}).params`);
  check("signature names the EXISTING output",
    !!signParams && signParams.substateId === UTXO,
    signParams ? String(signParams.substateId).slice(0, 40) + "…" : "no call");
  check("signature passes the gate's resource explicitly",
    !!signParams && signParams.resourceAddress === RESOURCE,
    signParams ? String(signParams.resourceAddress).slice(0, 50) : "no call");
  check("NO shield request during resume", !calls.includes("tari_createTransactionRequest"), calls.join(" | "));
  check("NO transaction submission during resume", !calls.includes("tari_submitTransactionRequest"), calls.join(" | "));

  console.log("\n== C. signature failures read through the taxonomy ==");
  for (const [code, message, wantTitle, wantBody] of [
    [-32603, "internal JSON-RPC error", "SIGNATURE REFUSED", /internal error/],
    [4001, "User rejected the request", "SIGNATURE REFUSED", /declined the request in your wallet/],
    [4100, "not connected", "SIGNATURE REFUSED", /not connected to your wallet/],
  ]) {
    await loadPage(mockSignFails(code, message), `${LAB}?gate=esm10`);
    const o = await runResume();
    check(`${code} -> honest wording, not "rejected a transaction"`,
      !!o && o.title === wantTitle && wantBody.test(o.body || ""),
      o ? `${o.title}: ${(o.body || "").slice(0, 70)}${o.detail ? " [" + o.detail.slice(0, 40) + "]" : ""}` : "no outcome");
    check(`${code} preserves the provider error code`,
      !!o && (o.detail || "").includes(`code ${code}`),
      o ? (o.detail || "").slice(0, 60) : "no outcome");
    const reEnabled = await evaluate(`!document.getElementById("prove").disabled && !document.getElementById("resume-proof").disabled`);
    check(`${code} leaves both buttons enabled`, reEnabled);
  }

  console.log("\n== D. success rendering: both honest states (rendering-only stubs) ==");
  // D1: the preview-bridge truth — verified but no session. The old page showed
  // ACCESS GRANTED here, conflating a verified proof with an issued session.
  await loadPage(MOCK_RECORDING + "\nwindow.__ggStubCredential = true;\nwindow.__ggStubAccess = null;", `${LAB}?gate=esm10`);
  const verified = await runResume();
  check("access:null renders PROOF VERIFIED — SESSION NOT ISSUED",
    !!verified && verified.title === "PROOF VERIFIED — SESSION NOT ISSUED",
    verified ? verified.title : "no outcome");
  check("access:null does NOT render ACCESS GRANTED",
    !!verified && !/ACCESS GRANTED/.test(verified.title || ""),
    verified ? verified.title : "no outcome");
  check("verified state renders floor AND required threshold in tTARI (no null tTARI)",
    !!verified && /10\s*tTARI/.test(verified.detail || "") && !/null\s*tTARI/.test(verified.detail || ""),
    verified ? (verified.detail || "").slice(0, 100) : "no outcome");

  // D2: the registry-backed truth — a real session token rides in the response.
  await loadPage(MOCK_RECORDING + `
    window.__ggStubCredential = true;
    window.__ggStubAccess = { token: "gg_sess_stub", expiresUnix: ${Math.floor(Date.now() / 1000) + 86400} };`, `${LAB}?gate=esm10`);
  const granted = await runResume();
  check("real session renders ACCESS GRANTED",
    !!granted && granted.title === "ACCESS GRANTED" && granted.cls.includes("granted"),
    granted ? granted.title : "no outcome");
  check("grant renders floor AND required threshold in tTARI (no null tTARI)",
    !!granted && /10\s*tTARI/.test(granted.detail || "") && !/null\s*tTARI/.test(granted.detail || ""),
    granted ? (granted.detail || "").slice(0, 100) : "no outcome");
  check("grant mentions the issued session duration",
    !!granted && /session was issued/i.test(granted.body || ""),
    granted ? (granted.body || "").slice(0, 90) : "no outcome");

  console.log("\n== console health ==");
  check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | "));

  console.log(`\n${passed.length} passed, ${failed.length} failed`);
  if (failed.length) { console.log(failed.map((f) => `  FAIL ${f}`).join("\n")); process.exitCode = 1; }
  ws.close();
  process.exit(process.exitCode || 0);
}

main().catch((e) => {
  console.error("harness error:", e.message);
  if (consoleErrors.length) console.error("console errors:", consoleErrors.join(" | "));
  process.exit(2);
});
