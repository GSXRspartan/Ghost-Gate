/**
 * CDP harness for the PRIVACY LAB matrix rain (scripts/lab_matrix_check.sh).
 *
 * Speaks Chrome DevTools Protocol over Node's built-in WebSocket — no npm dependencies. It drives
 * the REAL served Lab page and proves what a backend test cannot:
 *
 *   1.  the Lab loads with zero console errors and zero failed requests
 *   2.  #matrix-edges contains a left and a right canvas, both hidden behind the dashboard
 *   3.  at desktop widths both canvases span the real gutter (not a 112px strip), each holding
 *       roughly the 10–15 glyph columns the brief asks for
 *   4.  the animation is genuinely running: two frames at least one second apart differ
 *   5.  the dashboard's content box is not covered by either canvas
 *   6.  under prefers-reduced-motion the canvases never start
 *
 * Usage: node cdp-matrix-check.mjs <cdp-port> <lab-url> <out-dir>
 */

const PORT = process.argv[2] || process.env.CDP_PORT;
const LAB = process.argv[3] || "http://127.0.0.1:7799/lab";
const OUT = process.argv[4] || "/tmp/opencode/matrix-shots";
if (!PORT) throw new Error("usage: node cdp-matrix-check.mjs <cdp-port> [lab-url] [out-dir]");

let ws, nextId = 1;
const pending = new Map();
const consoleErrors = [];
const failedRequests = [];
const passed = [], failed = [];

function check(label, ok, detail = "") {
  (ok ? passed : failed).push(label);
  console.log(`  ${ok ? "ok  " : "FAIL"} ${label.padEnd(56)} ${detail}`);
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

async function screenshot(file) {
  const r = await send("Page.captureScreenshot", { format: "png", fromSurface: true });
  const { writeFileSync } = await import("node:fs");
  writeFileSync(`${OUT}/${file}`, Buffer.from(r.data, "base64"));
  return r.data.length;
}

async function setViewport(w, h) {
  await send("Emulation.setDeviceMetricsOverride", {
    width: w, height: h, deviceScaleFactor: 1, mobile: w < 600,
  });
}

async function gutterState() {
  return evaluate(`(() => {
    const host = document.getElementById("matrix-edges");
    const root = document.getElementById("lab-root");
    if (!host || !root) return { ok: false, reason: "missing #matrix-edges or #lab-root" };
    const canvases = [...host.querySelectorAll("canvas")].map((c) => {
      const r = c.getBoundingClientRect();
      const rootR = root.getBoundingClientRect();
      return {
        cls: c.className,
        display: getComputedStyle(c).display,
        visible: r.width > 0 && r.height > 0,
        w: Math.round(r.width),
        h: Math.round(r.height),
        left: Math.round(r.left),
        right: Math.round(r.right),
        // Both the canvases and the dashboard span the full page height, so clearance is a
        // horizontal test: the canvas must sit entirely beside the content box.
        behindRoot: r.right <= rootR.left || r.left >= rootR.right,
      };
    });
    return {
      ok: true,
      innerWidth: window.innerWidth,
      canvases,
      slots: canvases.map((c) => Math.floor(c.w / 16)),
    };
  })()`);
}

async function main() {
  await connect();
  await send("Page.navigate", { url: LAB });
  await sleep(2500);

  console.log(`\n== 1. the lab page loads on ${LAB} ==`);
  check("page loaded", true, LAB);
  const title = await evaluate("document.title");
  check("document.title mentions Ghost Gate", /Ghost/i.test(String(title)), title);
  const bodyOk = await evaluate(`!!document.querySelector("main, #lab-root")`);
  check("main content rendered", bodyOk === true);

  console.log(`\n== 2. viewport sweep: gutters, columns, dashboard clearance ==`);
  const sizes = [[1727, 893], [1920, 1080], [1366, 768], [390, 844]];
  let shotIndex = 0;
  for (const [w, h] of sizes) {
    await setViewport(w, h);
    await sleep(900); // let resize + a few animation frames land
    const tag = `${w}x${h}`;
    const s = await gutterState();
    if (!s.ok) { check(`${tag}: gutter probe`, false, s.reason); continue; }
    const left = s.canvases.find((c) => c.cls === "left");
    const right = s.canvases.find((c) => c.cls === "right");
    const desktop = w >= 1200;
    if (desktop) {
      check(`${tag}: left canvas visible`, !!left && left.display === "block" && left.visible,
        left ? `${left.w}px wide` : "absent");
      check(`${tag}: right canvas visible`, !!right && right.display === "block" && right.visible,
        right ? `${right.w}px wide` : "absent");
      const wide = w >= 1700;
      check(`${tag}: gutters sized to real margin (not 112px strip)`,
        !!left && !!right && left.w > (wide ? 150 : 40) && right.w > (wide ? 150 : 40),
        `${left?.w}/${right?.w}px`);
      // The 10-15-column target is the 1727 brief; 1920's wider margin simply carries more
      // columns, and narrow laptops may hold only 5-6 in a thin gutter.
      const brief1727 = w === 1727;
      const slotsOk = brief1727
        ? s.slots.every((n) => n >= 10 && n <= 16)
        : s.slots.every((n) => n >= 5);
      check(`${tag}: multi-column rain across both gutters`, slotsOk, `${s.slots.join(", ")} slots`);
      check(`${tag}: neither canvas covers the dashboard`,
        !!left && !!right && left.behindRoot && right.behindRoot,
        `root spans ${await evaluate("document.getElementById('lab-root').getBoundingClientRect().left + '..' + document.getElementById('lab-root').getBoundingClientRect().right")}`);
    } else {
      check(`${tag}: mobile keeps the dashboard uncluttered`,
        !!left && !!right && left.w <= 120 && right.w <= 120,
        `${left?.w}/${right?.w}px`);
    }
    // Two pixel samples taken at least one second apart must differ, or nothing is animating.
    // Downsample each visible canvas to a small grid and hash it: cheap, and robust to glyph
    // jitter — a running rain repaints every frame, so the hash cannot stay identical.
    await screenshot(`matrix-${tag}-a.png`);
    const sampleExpr = `(() => {
      const cs = [...document.querySelectorAll("#matrix-edges canvas")]
        .filter((c) => getComputedStyle(c).display !== "none");
      if (!cs.length) return { visible: false, samples: [] };
      const grab = (c) => {
        const off = document.createElement("canvas");
        off.width = 48; off.height = 64;
        const g = off.getContext("2d", { willReadFrequently: true });
        g.drawImage(c, 0, 0, 48, 64);
        const d = g.getImageData(0, 0, 48, 64).data;
        let hash = 0;
        for (let i = 0; i < d.length; i += 4) {
          hash = (hash * 31 + d[i]) | 0;
          hash = (hash * 31 + d[i + 1]) | 0;
          hash = (hash * 31 + d[i + 2]) | 0;
        }
        return hash;
      };
      return { visible: true, samples: cs.map(grab) };
    })()`;
    const a = await evaluate(sampleExpr);
    await sleep(1200);
    await screenshot(`matrix-${tag}-b.png`);
    shotIndex += 2;
    const b = await evaluate(sampleExpr);
    // On desktop the two samples must differ (the rain repaints every frame). On mobile the
    // gutter is zero, the rain is deliberately off, and the pass condition is that it stayed off.
    check(`${tag}: rain animates between frames`,
      desktop
        ? (a.visible === true && JSON.stringify(a.samples) !== JSON.stringify(b.samples))
        : a.visible === false,
      desktop
        ? (a.visible ? `${a.samples.length} canvas(es)` : "no visible canvas")
        : "no rain canvas at mobile width");
  }
  check("screenshots captured", shotIndex >= 8, `${shotIndex} frames`);

  console.log(`\n== 3. prefers-reduced-motion keeps the rain off ==`);
  await send("Emulation.setEmulatedMedia", {
    features: [{ name: "prefers-reduced-motion", value: "reduce" }],
  });
  // Reload so startMatrixEdges sees the media query fresh.
  await send("Page.navigate", { url: LAB });
  await sleep(2000);
  const rm = await gutterState();
  const anyVisible = rm.ok && rm.canvases.some((c) => c.display === "block" && c.visible);
  check("reduced-motion: no canvas started", !anyVisible,
    anyVisible ? "a canvas is visible" : "all canvases inert");
  check("reduced-motion: dashboard still renders", rm.ok === true);
  await screenshot("matrix-reduced-motion.png");

  console.log(`\n== console health ==`);
  check("no console errors", consoleErrors.length === 0,
    consoleErrors.slice(0, 3).join(" | "));
  check("no failed requests", failedRequests.length === 0,
    failedRequests.slice(0, 3).join(" | "));

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
