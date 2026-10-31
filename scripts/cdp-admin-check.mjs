/**
 * CDP harness for the ADMIN DASHBOARD (scripts/browser_admin_check.sh).
 *
 * Speaks Chrome DevTools Protocol over Node's built-in WebSocket — no npm dependencies. It drives
 * the REAL served page the way a non-technical administrator would, and it proves the things a
 * backend test cannot:
 *
 *   1.  the dashboard loads and asks for the bootstrap token on a fresh deployment
 *   2.  the PASSKEY ceremony completes against a VIRTUAL WebAuthn authenticator (CTAP2, resident
 *       key, user verification) — the real browser API path, not a stub
 *   3.  gates configured through the API appear in the UI, with their tier checkboxes
 *   4.  ticking a tier checkbox saves, and the saved grants survive a reload
 *   5.  a hostile display name renders as TEXT and never executes
 *   6.  a hostile gate id never escapes into an attribute
 *   7.  no horizontal overflow at 390x844
 *   8.  the operator's own browser is never touched: a fresh port and profile, headless only
 *
 * Usage: node cdp-admin-check.mjs <cdp-port> [admin-url] [bootstrap-token]
 */

const PORT = process.argv[2] || process.env.CDP_PORT;
if (!PORT) throw new Error("usage: node cdp-admin-check.mjs <cdp-port> [admin-url] [bootstrap-token]");
const ADMIN = process.argv[3] || "http://127.0.0.1:7812/admin";
const BOOTSTRAP = process.argv[4] || "";

let ws, nextId = 1;
const pending = new Map();
const consoleErrors = [];
const failedRequests = [];
const passed = [], failed = [];

function check(label, ok, detail = "") {
  (ok ? passed : failed).push(label);
  console.log(`  ${ok ? "ok  " : "FAIL"} ${label.padEnd(54)} ${detail}`);
}

function send(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

/** Evaluate an expression in the page and return its value. `awaitPromise` for async bodies. */
async function evaluate(expression, awaitPromise = false) {
  const r = await send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise,
    userGesture: true,
  });
  if (r.exceptionDetails) {
    throw new Error(`page threw: ${JSON.stringify(r.exceptionDetails).slice(0, 300)}`);
  }
  return r.result?.value;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function connect() {
  // Connect straight to the headless page target this browser was launched with. Talking to the
  // browser endpoint would need a session id on every command, and page-domain methods (Page.enable,
  // WebAuthn.enable) do not exist there.
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
    if (msg.method === "Network.loadingFailed") {
      failedRequests.push(`${msg.params.type} ${msg.params.errorText}`);
    }
  });

  await send("Page.enable");
  await send("Runtime.enable");
  await send("Network.enable");
}
async function main() {
  await connect();
  console.log(`\n== 1. the dashboard loads on ${ADMIN} ==`);
  await send("Page.navigate", { url: ADMIN });
  await sleep(2000);
  // The authenticator is added AFTER the navigation: WebAuthn state belongs to the navigated
  // origin, so one added on about:blank leaves the page with nothing to answer its ceremony.
  //
  // It is added EXPLICITLY rather than through WebAuthn.enable's inline virtualAuthenticatorOptions:
  // in this Edge build an authenticator created that way never answers and every ceremony times
  // out with NotAllowedError, while one added through addVirtualAuthenticator answers immediately.
  // The capability set is the same either way: CTAP2, resident key, user verification, and
  // automatic presence — the path a hardware security key takes through the browser.
  await send("WebAuthn.enable", { enableUI: false });
  await send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  check("the page has a title", !!(await evaluate("document.title")), await evaluate("document.title"));
  check(
    "the first-run panel asks for the bootstrap token",
    (await evaluate("!document.querySelector('#bootstrap-panel').hidden")) === true,
  );
  check("the passkey registration control is present", await evaluate("!!document.querySelector('#reg-passkey')"));

  console.log("\n== 2. register the first administrator with a virtual passkey ==");
  await evaluate(
    `(() => { const t = document.querySelector('#bootstrap-token'); t.value = ${JSON.stringify(BOOTSTRAP)};
       t.dispatchEvent(new Event('input', {bubbles:true})); return true; })()`,
  );
  await evaluate("document.querySelector('#reg-passkey').click(); true");
  // The ceremony is async: WebAuthn + CBOR + fetch. Give it room, then look at the result.
  let signedIn = false;
  for (let i = 0; i < 40; i++) {
    await sleep(300);
    signedIn = (await evaluate("!document.querySelector('#dashboard').hidden")) === true;
    if (signedIn) break;
  }
  check("the passkey ceremony signed the administrator in", signedIn);
  if (!signedIn) {
    // A silent failure is the worst kind for an operator: print everything the page knows.
    const err = await evaluate("(document.querySelector('#bootstrap-error')||{}).textContent || ''");
    const status = await evaluate("(document.querySelector('#admin-status')||{}).textContent || ''");
    const panels = await evaluate(
      "JSON.stringify({bootstrap: !document.querySelector('#bootstrap-panel').hidden," +
      " login: !document.querySelector('#login-panel').hidden," +
      " dashboard: !document.querySelector('#dashboard').hidden})",
    );
    console.log(`       (bootstrap error: ${err || "(empty)"})`);
    console.log(`       (status line:     ${status || "(empty)"})`);
    console.log(`       (panels:          ${panels})`);
    if (consoleErrors.length) console.log(`       (console:         ${consoleErrors.slice(0, 3).join(" | ")})`);
    // Is the ceremony itself broken, or did the page fail before it? Ask the browser directly.
    const probe = await evaluate(`(async () => {
      try {
        const c = await navigator.credentials.create({publicKey:{
          challenge: new Uint8Array([1,2,3,4]), rp:{name:'probe', id: location.hostname},
          user:{id:new Uint8Array([9]), name:'probe', displayName:'probe'},
          pubKeyCredParams:[{type:'public-key', alg:-7}],
          authenticatorSelection:{userVerification:'preferred', residentKey:'preferred'},
          timeout: 6000, attestation:'none'}});
        return 'the virtual authenticator answered (' + new Uint8Array(c.rawId).length + ' bytes)';
      } catch(e) { return 'the ceremony itself failed: ' + e.name + ': ' + e.message.slice(0,80); }
    })()`, true);
    console.log(`       (ceremony probe:  ${typeof probe === "string" ? probe : JSON.stringify(probe)})`);
    throw new Error("registration did not complete");
  }

  console.log("\n== 3. gates configured through the API appear in the UI ==");
  // Create an application and three gates the way the demo did, but through the API the page uses,
  // so this asserts the RENDER, not the create path (already covered by the backend suite).
  await evaluate(
    `(async () => {
       const state = await (await fetch('/admin/api/state')).json();
       const csrf = state.csrf;
       const mk = async (appId, name, topology, production) => (await fetch('/admin/api/app/create', {
         method:'POST', headers:{'Content-Type':'application/json','X-GG-CSRF':csrf},
         body: JSON.stringify({applicationId:appId, displayName:name, topology,
           defaultSessionTtl: production ? 604800 : 3600, production})})).status;
       await mk('browser-demo', 'Browser demo', 'hierarchical', true);
       const gate = (id, raw) => fetch('/admin/api/gate/set', {method:'POST',
         headers:{'Content-Type':'application/json','X-GG-CSRF':csrf},
         body: JSON.stringify({applicationId:'browser-demo', gate:{
           gateId:id, name:id, resourceAddress:'resource_browserbrowserbrowserbrowserbrowserbrowserbrowserbrowserbrowser',
           symbol:'GHOST', divisibility:6, thresholdRaw:raw, proofMode:'consensus',
           challengeDomain:'browser.localhost', sessionTtlOverrideSecs:null, grants:[],
           enabled:true, testLane:false,
           componentAddress:'component_browserbrowserbrowserbrowserbrowserbrowserbrowserbrowser'}})});
       for (const [id, raw] of [['bronze','100000000000'],['silver','500000000000'],['gold','1000000000000']]) await gate(id, raw);
       return true;
     })()`,
    true,
  );
  await evaluate("window.location.reload(); true");
  await sleep(2000);
  const signedInAgain = (await evaluate("!document.querySelector('#dashboard').hidden")) === true;
  check("the session survived a reload", signedInAgain);
  if (!signedInAgain) {
    // The virtual authenticator keeps its credential, so sign in again through the browser API.
    await evaluate("document.querySelector('#login-passkey').click(); true");
    for (let i = 0; i < 30; i++) {
      await sleep(300);
      if ((await evaluate("!document.querySelector('#dashboard').hidden")) === true) break;
    }
  }
  const rowCount = await evaluate(
    `document.querySelectorAll('#apps-list .gate-card[data-app="browser-demo"] table tr[data-gate-id]').length`,
  );
  check("the three gates render as rows", rowCount === 3, `${rowCount} rows`);
  const tierBoxes = await evaluate(
    `document.querySelectorAll('#apps-list .gate-card[data-app="browser-demo"] .tier-check input').length`,
  );
  check("every gate offers a tier checkbox for every other gate", tierBoxes === 6, `${tierBoxes} boxes`);

  console.log("\n== 3b. a gate records where it may be used ==");
  const scopePresent = await evaluate("!!document.querySelector('[id^=scope-]')");
  check("the scope control is offered per application", scopePresent === true);
  const scopeOptions = await evaluate("[...document.querySelectorAll('[id^=scope-] option')].map(o=>o.value).join(',')");
  check("it offers exactly website / telegram / both", scopeOptions === "website,telegram,both", scopeOptions);

  console.log("\n== 4. wiring a tier with a real click saves and survives a reload ==");
  // gold opens silver: click gold's row, silver's box.
  await evaluate(
    `(() => {
       const rows = [...document.querySelectorAll('#apps-list .gate-card[data-app="browser-demo"] .tier-row')];
       const gold = rows.find(r => r.textContent.startsWith('gold'));
       const box = [...gold.querySelectorAll('.tier-check')].find(l => l.textContent.trim() === 'silver')
                    .querySelector('input');
       box.click();
       return true;
     })()`,
  );
  await sleep(1200);
  await evaluate("window.location.reload(); true");
  await sleep(2000);
  const goldGrantsSilver = await evaluate(
    `(() => {
       const rows = [...document.querySelectorAll('#apps-list .gate-card[data-app="browser-demo"] table tr[data-gate-id]')];
       const gold = rows.find(r => r.dataset.gateId === 'gold');
       return gold ? gold.children[6].textContent.trim() : '';
     })()`,
  );
  check("the tier survived the reload", goldGrantsSilver.includes("silver"), `"${goldGrantsSilver}"`);

  console.log("\n== 5. a hostile display name is text, never script ==");
  await evaluate(
    `(async () => {
       const csrf = (await (await fetch('/admin/api/state')).json()).csrf;
       await fetch('/admin/api/app/create', {method:'POST',
         headers:{'Content-Type':'application/json','X-GG-CSRF':csrf},
         body: JSON.stringify({applicationId:'xss-probe',
           displayName:'<img src=x onerror="window.__pwned=1">',
           topology:'independent', defaultSessionTtl:3600, production:false})});
       return true;
     })()`,
    true,
  );
  await evaluate("window.location.reload(); true");
  await sleep(2000);
  check("no injected script ran", (await evaluate("!!window.__pwned")) !== true);
  check(
    "the payload is visible as text",
    (await evaluate(
      `[...document.querySelectorAll('#apps-list strong')].some(e => e.textContent.includes('<img src=x'))`,
    )) === true,
  );
  check("no img element was created from it", (await evaluate("!!document.querySelector('#apps-list img')")) !== true);

  console.log("\n== 6. a hostile gate id never escapes into an attribute ==");
  await evaluate(
    `(async () => {
       const csrf = (await (await fetch('/admin/api/state')).json()).csrf;
       await fetch('/admin/api/gate/set', {method:'POST',
         headers:{'Content-Type':'application/json','X-GG-CSRF':csrf},
         body: JSON.stringify({applicationId:'xss-probe', gate:{
           gateId:'"><script>window.__pwned2=1</script>', name:'"><b>bold</b>',
           resourceAddress:'resource_x', symbol:'X', divisibility:6, thresholdRaw:'1000',
           proofMode:'consensus', challengeDomain:'x.localhost', sessionTtlOverrideSecs:null,
           grants:[], enabled:false, testLane:false, componentAddress:null}})});
       return true;
     })()`,
    true,
  );
  await evaluate("window.location.reload(); true");
  await sleep(2000);
  check("no script ran from a gate id", (await evaluate("!!window.__pwned2")) !== true);
  check("no script element exists in the app list", (await evaluate("!!document.querySelector('#apps-list script')")) !== true);

  console.log("\n== 7. phone width has no horizontal overflow ==");
  await send("Emulation.setDeviceMetricsOverride", {
    width: 390, height: 844, deviceScaleFactor: 2, mobile: true,
  });
  await sleep(800);
  const overflow = await evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth");
  check("390x844 has no horizontal overflow", overflow <= 1, `${overflow}px`);
  if (overflow > 1) {
    // Name the culprits: a layout bug nobody can fix is a bug nobody reports.
    const worst = await evaluate(`(() => {
      const vw = document.documentElement.clientWidth;
      const bad = [];
      for (const el of document.querySelectorAll('#admin-root *')) {
        const r = el.getBoundingClientRect();
        if (r.right > vw + 1 && r.width > 0) {
          bad.push(el.tagName + (el.id ? '#' + el.id : '') + (el.className ? '.' + String(el.className).split(' ')[0] : '')
            + ' right=' + Math.round(r.right) + ' w=' + Math.round(r.width)
            + ' "' + (el.textContent || '').trim().slice(0, 24) + '"');
        }
      }
      return bad.slice(0, 6);
    })()`);
    worst.forEach((w) => console.log(`         · ${w}`));
  }
  await send("Emulation.clearDeviceMetricsOverride");

  console.log("\n== 8. the browser is a secure context (passkeys require it) ==");
  check("loopback counts as secure", (await evaluate("window.isSecureContext")) === true);

  console.log("\n== hygiene ==");
  const noisy = consoleErrors.filter((e) => !/favicon/i.test(e));
  check("no uncaught page errors", noisy.length === 0, noisy.slice(0, 2).join(" | "));
  // ERR_ABORTED on a stylesheet is what a deliberate reload looks like on the wire; this harness
  // reloads on purpose. Anything else is a real failure.
  const netFailures = failedRequests.filter((e) => !/favicon/i.test(e) && !/ERR_ABORTED/.test(e));
  check("no failed network requests", netFailures.length === 0, netFailures.slice(0, 2).join(" | "));

  console.log(`\n${passed.length} passed, ${failed.length} failed`);
  if (failed.length) {
    failed.forEach((f) => console.log("  failed:", f));
    process.exitCode = 1;
  }
}

main()
  .catch((e) => {
    console.error("harness error:", e.message);
    process.exitCode = 1;
  })
  .finally(() => {
    // The CDP socket keeps node's event loop alive; without closing it the harness prints its
    // results and then hangs, which looks like a flaky test to whoever runs it in CI.
    try {
      ws?.close();
    } catch {
      /* already gone */
    }
    process.exit(process.exitCode || 0);
  });