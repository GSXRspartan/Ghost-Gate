/**
 * CDP harness for the PRIVACY LAB wallet-connection UI (scripts/lab_connect_check.sh).
 *
 * Simulated-provider UI wiring test — NOT a physical wallet test. It injects a mock window.tari
 * BEFORE the page loads (so startMatrixEdges/probe see a real-looking extension), drives the
 * section-02 Connect-wallet ceremony, and asserts what a visitor would see. The physical Sapient
 * prompt is the operator's milestone and stays theirs to confirm.
 *
 * Proven:
 *   1. the wallet selector offers the Sapient option
 *   2. the Connect wallet button is visible and enabled
 *   3. clicking it with a mock extension that reports Esmeralda shows the connected state,
 *      the real address, the network verdict for the published gate, the
 *      capability list, and the read-only ownership signature result
 *   4. rejection (4001) surfaces as "you declined", not an error
 *   5. no console errors
 *
 * Usage: node cdp-connect-check.mjs <cdp-port> <lab-url>
 */

const PORT = process.argv[2] || process.env.CDP_PORT;
const LAB = process.argv[3] || "http://127.0.0.1:7799/lab";
if (!PORT) throw new Error("usage: node cdp-connect-check.mjs <cdp-port> [lab-url]");

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

/** A mock window.tari faithful to Tari's documented dApp contract. Reports Esmeralda, the
 *  network of the published Crypt staging gate. */
const MOCK_TARI = `
  window.tari = {
    isTariWallet: true,
    request(args) {
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
      if (m === "tari_signWalletOwnershipChallenge") {
        return Promise.resolve({
          walletAddress: "otl_esm_1rghzs3",
          publicNonce: "ab".repeat(32),
          signature: "cd".repeat(64),
        });
      }
      return Promise.reject(Object.assign(new Error("mock: unsupported " + m), { code: 4200 }));
    },
  };
  window.dispatchEvent(new Event("tari#initialized"));
`;

const MOCK_REJECTING = `
  window.tari = {
    isTariWallet: true,
    request(args) {
      if (args.method === "tari_getCapabilities") return Promise.resolve({});
      return Promise.reject(Object.assign(new Error("user declined"), { code: 4001 }));
    },
  };
  window.dispatchEvent(new Event("tari#initialized"));
`;

/** The physical Sapient's behavior: capability reads BEFORE an authorized account request
 *  answer 4100 (not connected). A mock that accepted caps freely is what let the old call
 *  order look fine in simulation and fail only on the real wallet — this mock is strict so the
 *  harness reproduces the physical failure mode and proves the fix, not just the display. */
const MOCK_STRICT_ORDER = `
  window.tari = (() => {
    let connected = false;
    return {
      isTariWallet: true,
      request(args) {
        const m = args.method;
        if (!connected && m !== "tari_requestAccounts" && m !== "tari_getAccounts") {
          return Promise.reject(Object.assign(new Error("not connected"), { code: 4100 }));
        }
        if (m === "tari_requestAccounts") {
          connected = true;
          return Promise.resolve(["otl_esm_1rghzs3zkfrvajj39r7pm26q7uwne6dxrm2ztf29aq8y4zezpppjs95znmg2rgwr6rjgxq2p7xzrpy3h5nc8q22gnkudn9axgsruxjuqae5f2t"]);
        }
        if (m === "tari_getCapabilities") {
          return Promise.resolve({
            privateSpend: true, minimumValuePromise: true, ownershipProof: true,
            walletOwnershipProof: true, transactionResultLookup: true, transactionRequests: true,
          });
        }
        if (m === "tari_getNetwork") return Promise.resolve("esmeralda");
        if (m === "tari_signWalletOwnershipChallenge") {
          return Promise.resolve({ walletAddress: "otl_esm_1rghzs3", publicNonce: "ab".repeat(32), signature: "cd".repeat(64) });
        }
        return Promise.reject(Object.assign(new Error("mock: unsupported " + m), { code: 4200 }));
      },
    };
  })();
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

async function reloadWithMock(mock) {
  // Inject the mock before any page script runs, then navigate.
  await send("Page.addScriptToEvaluateOnNewDocument", { source: mock });
  await send("Page.navigate", { url: LAB });
  await sleep(2500);
}

async function main() {
  await connect();

  console.log("\n== 1. the selector offers Sapient and the connect button exists ==");
  await reloadWithMock(MOCK_TARI);
  const options = await evaluate(`[...document.querySelectorAll("#wallet-select option")].map(o => o.textContent)`);
  check("wallet selector lists Sapient", options.some((t) => /Sapient/i.test(t)),
    options.join(" | "));
  const btn = await evaluate(`(() => { const b = document.getElementById("connect-wallet");
    return b ? { hidden: b.hidden, disabled: b.disabled, label: b.textContent } : null; })()`);
  check("Connect wallet button present and enabled", !!btn && !btn.hidden && !btn.disabled,
    btn ? `${btn.label} (hidden=${btn.hidden} disabled=${btn.disabled})` : "absent");

  console.log("\n== 2. select Sapient and press Connect ==");
  await evaluate(`(() => { const s = document.getElementById("wallet-select");
    s.value = [...s.options].find(o => /Sapient/i.test(o.textContent)).value;
    s.dispatchEvent(new Event("change")); return s.value; })()`);
  await sleep(300);
  await evaluate(`document.getElementById("connect-wallet").click()`);
  await sleep(1200);
  const d = await evaluate(`(() => {
    const rows = {};
    for (const id of ["wd-status", "wd-address", "wd-network", "wd-caps", "wd-ownership"]) {
      rows[id] = document.getElementById(id) ? document.getElementById(id).textContent : null;
    }
    return { hidden: document.getElementById("wallet-detail").hidden, rows };
  })()`);
  check("detail box opened", d.hidden === false);
  check("status reports connected", /connected/i.test(d.rows["wd-status"] || ""), d.rows["wd-status"]);
  check("real Esmeralda address shown (truncated, not hidden)",
    d.rows["wd-address"].includes("otl_esm") && d.rows["wd-address"].includes("…"),
    d.rows["wd-address"]);
  check("published Esmeralda network verdict surfaced honestly",
    /esmeralda/i.test(d.rows["wd-network"] || "") && /gate's own network/i.test(d.rows["wd-network"] || ""),
    d.rows["wd-network"]);
  const noteAfter = await evaluate(`document.getElementById("wallet-note").textContent`);
  check("stale 'press Connect' note replaced after real connection",
    /connected/i.test(noteAfter || "") && !/press Connect wallet/i.test(noteAfter || ""),
    noteAfter);
  check("capabilities listed",
    (d.rows["wd-caps"] || "").includes("privateSpend") && (d.rows["wd-caps"] || "").includes("ownershipProof"),
    d.rows["wd-caps"]);
  check("read-only ownership signature shown as possession-only",
    /possession only/i.test(d.rows["wd-ownership"] || ""), d.rows["wd-ownership"]);

  console.log("\n== 3. rejection (4001) is a decline, not an error ==") ;
  await reloadWithMock(MOCK_REJECTING);
  await evaluate(`(() => { const s = document.getElementById("wallet-select");
    s.value = [...s.options].find(o => /Sapient/i.test(o.textContent)).value;
    s.dispatchEvent(new Event("change")); return s.value; })()`);
  await sleep(300);
  await evaluate(`document.getElementById("connect-wallet").click()`);
  await sleep(900);
  const rej = await evaluate(`document.getElementById("wd-status").textContent`);
  check("declined state is truthful", /declined/i.test(rej || ""), rej);

  console.log("\n== 4. strict-order mock: caps 4100 before accounts (the physical failure mode) ==");
  await reloadWithMock(MOCK_STRICT_ORDER);
  await evaluate(`(() => { const s = document.getElementById("wallet-select");
    s.value = [...s.options].find(o => /Sapient/i.test(o.textContent)).value;
    s.dispatchEvent(new Event("change")); return s.value; })()`);
  await sleep(300);
  // The passive note must say the wallet was detected and needs connecting — not "cannot prove".
  const passive = await evaluate(`document.getElementById("wallet-note").textContent`);
  check("passive state points at Connect, not 'cannot prove'",
    /Connect wallet/i.test(passive || "") && !/cannot prove/i.test(passive || ""), passive);
  await evaluate(`document.getElementById("connect-wallet").click()`);
  await sleep(1200);
  const strict = await evaluate(`(() => {
    const rows = {};
    for (const id of ["wd-status", "wd-address", "wd-network"]) {
      rows[id] = document.getElementById(id) ? document.getElementById(id).textContent : null;
    }
    return rows;
  })()`);
  check("accounts-first ordering connects the strict wallet",
    /connected/i.test(strict["wd-status"] || ""), strict["wd-status"]);
  check("strict wallet's Esmeralda address shown",
    (strict["wd-address"] || "").includes("otl_esm"), strict["wd-address"]);
  check("strict wallet's published-network verdict shown",
    /esmeralda/i.test(strict["wd-network"] || "") && /gate's own network/i.test(strict["wd-network"] || ""), strict["wd-network"]);

  console.log("\n== 5. pending approval gets immediate feedback and never double-prompts ==");
  await evaluate(`(() => {
    window.__ggSlowAccountCalls = 0;
    window.tari = {
      isTariWallet: true,
      request(args) {
        if (args.method === "tari_requestAccounts") {
          window.__ggSlowAccountCalls += 1;
          return new Promise((resolve) => setTimeout(() => resolve(["otl_esm_1slow" + "x".repeat(80)]), 90));
        }
        if (args.method === "tari_getCapabilities") return Promise.resolve({ privateSpend: true, minimumValuePromise: true, ownershipProof: true });
        if (args.method === "tari_getNetwork") return Promise.resolve("esmeralda");
        return Promise.reject(Object.assign(new Error("mock: unsupported " + args.method), { code: 4200 }));
      },
    };
    const s = document.getElementById("wallet-select");
    s.value = [...s.options].find(o => /Sapient/i.test(o.textContent)).value;
    s.dispatchEvent(new Event("change"));
  })()`);
  await sleep(100);
  const pending = await evaluate(`(() => {
    const b = document.getElementById("connect-wallet");
    b.click(); b.click();
    return { disabled: b.disabled, label: b.textContent, status: document.getElementById("wd-status").textContent };
  })()`);
  check("pending approval disables the button immediately", pending.disabled === true, JSON.stringify(pending));
  check("pending approval names Sapient", /Waiting for Sapient/i.test(`${pending.label} ${pending.status}`), JSON.stringify(pending));
  await sleep(220);
  const pendingResult = await evaluate(`(() => ({
    accountCalls: window.__ggSlowAccountCalls,
    marks: performance.getEntriesByType("mark").map(e => e.name).filter(n => n.startsWith("ghost-gate:connect:")),
    status: document.getElementById("wd-status").textContent,
  }))()`);
  check("repeated click produces one account request", pendingResult.accountCalls === 1, String(pendingResult.accountCalls));
  check("connection marks identify request and completion", pendingResult.marks.includes("ghost-gate:connect:accounts-requested") && pendingResult.marks.includes("ghost-gate:connect:accounts-resolved"), pendingResult.marks.join(", "));

  console.log("\n== 6. missing provider times out without asking for permission ==");
  await evaluate(`window.tari = undefined`);
  const missingStart = Date.now();
  await evaluate(`document.getElementById("connect-wallet").click()`);
  await sleep(1650);
  const missing = await evaluate(`document.getElementById("wd-status").textContent`);
  check("missing provider reports a bounded initialization failure", /did not finish initializing within 1\.5 seconds/i.test(missing || ""), `${Date.now() - missingStart}ms: ${missing}`);

  console.log("\n== 7. mobile status semantics and layout fit the viewport ==");
  await send("Emulation.setDeviceMetricsOverride", {
    width: 360, height: 740, deviceScaleFactor: 2, mobile: true,
  });
  await reloadWithMock(MOCK_TARI);
  const simpleMobile = await evaluate(`(() => {
    const strip = document.getElementById("status-strip");
    const toggle = document.querySelector(".view-switch").getBoundingClientRect();
    const wallet = document.getElementById("pill-walletd");
    return {
      viewport: innerWidth,
      documentWidth: document.documentElement.scrollWidth,
      stripWidth: strip.scrollWidth,
      stripClientWidth: strip.clientWidth,
      toggleRight: toggle.right,
      walletKey: wallet.querySelector(".k").textContent,
      walletValue: wallet.querySelector(".v").textContent,
    };
  })()`);
  check("mobile document and status strip do not overflow", simpleMobile.documentWidth <= simpleMobile.viewport && simpleMobile.stripWidth <= simpleMobile.stripClientWidth, JSON.stringify(simpleMobile));
  check("mobile toggle remains fully visible", simpleMobile.toggleRight <= simpleMobile.viewport, JSON.stringify(simpleMobile));
  check("Simple mode labels hosted browser credential", simpleMobile.walletKey === "WALLET MODE" && simpleMobile.walletValue === "browser credential", JSON.stringify(simpleMobile));
  await evaluate(`document.getElementById("view-technical").click()`);
  const technicalMobile = await evaluate(`(() => {
    const wallet = document.getElementById("pill-walletd");
    return { key: wallet.querySelector(".k").textContent, value: wallet.querySelector(".v").textContent, classes: wallet.className };
  })()`);
  check("Technical mode makes optional walletd neutral", technicalMobile.key === "WALLETD" && technicalMobile.value === "optional · not in use" && !/warn|bad/.test(technicalMobile.classes), JSON.stringify(technicalMobile));
  await send("Emulation.clearDeviceMetricsOverride");

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
