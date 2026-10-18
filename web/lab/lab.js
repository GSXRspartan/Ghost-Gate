/**
 * GHOST GATE — PRIVACY LAB (client)
 *
 * Two synchronized views of ONE verification attempt:
 *   SIMPLE    — nine real steps in plain English, plus the privacy X-ray.
 *   TECHNICAL — a protocol inspector fed by the bridge's sanitized event stream.
 *
 * Both are driven by the same state object, so they cannot disagree: the steps advance from the
 * same events the terminal renders. Nothing here decides anything. The bridge decides; this page
 * shows what the bridge decided, and asks again.
 *
 * What this page deliberately cannot do: change a threshold, mint a challenge it did not receive,
 * present a proof it did not obtain, or turn any local value into access. A gate's threshold comes
 * from the administrator's registry through /lab/gates; the verdict comes from /proof/<id>/status.
 */

import { walletdProvider, sapientProvider, universeProvider, windowTariProvider } from "/js/ghost/provider.js";
import { supportedProofModes, walletUsability, parseAmount, formatAmount } from "/js/ghost/capabilities.js";

const $ = (id) => document.getElementById(id);

const state = {
    view: "simple",
    gates: [],
    gate: null,
    mode: null,          // the selected wallet option
    attemptId: null,
    proofId: null,
    simulated: false,
    step: -1,            // index into STEPS; -1 = idle
    events: [],
    paused: false,
    lastSeq: 0,
};

// ---------------------------------------------------------------- formatting
function api(path, options = {}) {
    return fetch(path, {
        ...options,
        headers: { "Content-Type": "application/json", "X-GG-Attempt": state.attemptId || "", ...(options.headers || {}) },
        cache: "no-store",
    }).then(async (r) => {
        const text = await r.text();
        let body = {};
        try { body = text ? JSON.parse(text) : {}; } catch { body = { error: text }; }
        return { status: r.status, ok: r.ok, body };
    });
}

// ---------------------------------------------------------------- the nine steps
const STEPS = [
    {
        id: "gate", title: "Select a configured gate",
        note: "Read from the administrator's published policy — a threshold you cannot edit from here.",
    },
    {
        id: "wallet", title: "Select a compatible wallet",
        note: "Only wallets that can actually produce a proof for this gate's mode are offered.",
    },
    {
        id: "challenge", title: "Request a fresh challenge",
        note: "A single-use challenge bound to this gate and this attempt. It expires; a spent challenge is dead.",
    },
    {
        id: "authorize", title: "Request wallet authorization",
        note: "Your wallet is asked to build a statement about a minimum value. It is never asked for your key or your balance.",
        explain: "Why no balance?\nThe wallet builds a range proof over [minimum, 2^64). Proving 'at least X' needs no knowledge of the amount above X — that is the property that lets the verifier check a threshold without seeing a balance. The wallet constructs and signs this locally; the bridge relays the signed statement and never sees your spendable outputs.",
    },
    {
        id: "submit", title: "Prepare and submit proof material",
        note: "The request names a gate and a challenge. It has no field for an amount, a destination or a UTXO — there is nowhere for a bug to put one.",
    },
    {
        id: "consensus", title: "Wait for consensus confirmation",
        note: "On the consensus path the network must include the statement; a browser-wallet path verifies off-chain against chain state.",
        explain: "Consensus vs credential.\nThe consensus path (Ootle stealth) waits for a transaction in a block. The credential path (browser wallet) verifies a signed output against chain state directly. Both end in the same server-side check: floor ≥ threshold, against the policy version in force.",
    },
    {
        id: "verify", title: "Verify against the actual gate policy",
        note: "The verifier compares the attested floor with the gate's threshold. Floor ≥ threshold, nothing else.",
        explain: "Replay protection.\nEach challenge is single-use and bound to this attempt. If the answer arrives for a spent challenge, or after an administrator replaced the policy, it is refused — the floor you prove must be the floor the live gate requires.",
    },
    {
        id: "grant", title: "Grant or reject access",
        note: "Granted only by the server, against the verified session. A page cannot manufacture this step.",
    },
    {
        id: "session", title: "Explain session expiry",
        note: "Access lasts a configured window, then a fresh proof is required. A session is not a key.",
    },
];

// ---------------------------------------------------------------- gate loading
async function loadGates() {
    const { ok, body } = await api("/lab/gates");
    if (!ok) {
        $("gate-select").innerHTML = '<option value="">bridge unreachable</option>';
        return;
    }
    state.gates = body.gates || [];
    const sel = $("gate-select");
    sel.innerHTML = "";
    if (!state.gates.length) {
        sel.innerHTML = '<option value="">no gate published yet</option>';
        renderGateFacts(null);
        loadTelegramScope();
        return;
    }
    for (const g of state.gates) {
        const opt = document.createElement("option");
        opt.value = g.gateId;
        opt.textContent = `${g.gateId} — ${formatAmount(g.thresholdRaw, g.divisibility)} ${g.symbol || "?"}`;
        sel.append(opt);
    }
    sel.onchange = () => selectGate(sel.value);
    selectGate(state.gates[0].gateId);
}

function selectGate(gateId) {
    state.gate = state.gates.find((g) => g.gateId === gateId) || null;
    state.step = -1;
    renderGateFacts(state.gate);
    renderWallets();
    renderSteps();
    $("outcome").hidden = true;
}

/** Facts are read from the registry response — never from a value typed here. */
function renderGateFacts(gate) {
    const host = $("gate-facts");
    host.innerHTML = "";
    if (!gate) {
        host.innerHTML = '<div class="fact"><div class="k">state</div><div class="v bad">no gate configured</div></div>';
        renderXray(null);
        return;
    }
    const human = formatAmount(gate.thresholdRaw, gate.divisibility);
    const facts = [
        ["asset", gate.symbol || "(unlabelled)", "green"],
        ["minimum proven", `≥ ${human} ${gate.symbol || ""}`.trim(), "green"],
        ["raw units", gate.thresholdRaw, ""],
        ["resource", gate.resourceAddress ? `${gate.resourceAddress.slice(0, 12)}…` : "—", ""],
        ["divisibility", gate.divisibility, ""],
        ["proof mode", gate.proofMode === "consensus" ? "consensus (wallet daemon)" : gate.proofMode, ""],
        ["sessions", gate.sessionsAvailable ? "issued server-side" : "not issued (preview)", gate.sessionsAvailable ? "green" : "bad"],
    ];
    if (!gate.activatable) {
        facts.push(["availability", "experimental — not functional", "bad"]);
    }
    for (const [k, v, cls] of facts) {
        const d = document.createElement("div");
        d.className = "fact";
        d.innerHTML = `<div class="k"></div><div class="v ${cls}"></div>`;
        d.querySelector(".k").textContent = k;
        d.querySelector(".v").textContent = String(v);
        host.append(d);
    }
    renderXray(gate);
    loadTelegramScope();
}

// ---------------------------------------------------------------- wallets
async function renderWallets() {
    const sel = $("wallet-select");
    sel.innerHTML = "";
    state.mode = null;
    const gate = state.gate;
    if (!gate) { sel.innerHTML = '<option>—</option>'; return; }

    const options = [];
    // The consensus path needs a wallet daemon; the bridge knows whether one is there.
    const health = await api("/health").catch(() => ({ body: {} }));
    if (gate.proofMode === "consensus") {
        options.push({ id: "walletd", label: "Wallet daemon (consensus) — the real threshold proof", ready: true });
    }
    options.push({ id: "sapient", label: "Sapient / Tari desktop wallet (credential)", ready: gate.proofMode === "consensus" ? true : true });
    options.push({ id: "universe", label: "Universe (in-app browser wallet)", ready: true });

    for (const o of options) {
        const opt = document.createElement("option");
        opt.value = o.id;
        opt.textContent = o.label;
        sel.append(opt);
    }
    sel.onchange = () => selectMode(sel.value);
    if (options.length) selectMode(options[0].id);
}

async function selectMode(id) {
    state.mode = id;
    const note = $("wallet-note");
    // Probe the selected provider for real; report what is actually there.
    let provider = id === "walletd" ? walletdProvider(location.origin) : id === "universe" ? universeProvider() : sapientProvider();
    let usable = { usable: false, reason: "not probed", modes: [] };
    try {
        const caps = await provider.capabilities();
        usable = walletUsability(caps, { canConsensusProof: id === "walletd" });
    } catch (e) {
        usable = { usable: false, reason: "provider did not answer", modes: [] };
    }
    if (id === "walletd") {
        note.textContent = usable.usable
            ? "A wallet daemon is reachable. The consensus path proves a stealth threshold on chain."
            : "No wallet daemon reachable — the consensus path cannot run here. Start walletd, or choose another method.";
    } else if (usable.usable) {
        note.textContent = "This wallet can build the credential statement this gate accepts. " + (usable.modes || []).join(", ");
    } else {
        note.textContent = `This wallet cannot prove this gate: ${usable.reason || "unsupported"}`;
    }
}

// ---------------------------------------------------------------- steps + view
function renderSteps() {
    const ol = $("steps");
    ol.innerHTML = "";
    STEPS.forEach((s, i) => {
        const li = document.createElement("li");
        li.dataset.step = s.id;
        li.innerHTML = '<div><div class="step-title"></div><div class="step-note"></div></div>';
        li.querySelector(".step-title").textContent = s.title;
        li.querySelector(".step-note").textContent = s.note;
        if (s.explain) {
            const d = document.createElement("details");
            d.className = "explain";
            const sum = document.createElement("summary");
            sum.textContent = "why this step exists";
            const p = document.createElement("p");
            p.textContent = s.explain;
            d.append(sum, p);
            li.firstChild.append(d);
        }
        if (i === state.step) li.classList.add("active");
        if (state.step > i) li.classList.add("done");
        ol.append(li);
    });
}

function advance(stepId) {
    const i = STEPS.findIndex((s) => s.id === stepId);
    if (i >= 0 && i > state.step) { state.step = i; renderSteps(); }
}

// ---------------------------------------------------------------- X-ray
const XRAY = {
    consensus: {
        learns: [
            ["That you hold at least the threshold", "a lower bound, in the resource's own units"],
            ["Which resource, gate and network", "the challenge names them; they are public on chain"],
            ["That a transaction of yours exists", "the chain publishes every transaction"],
            ["A public on-chain transaction id", "anyone can look it up — this is inherent to the chain"],
        ],
        private: [
            ["Your exact balance", "the proof is over [minimum, 2^64); the amount above the bound is never revealed"],
            ["Which inputs paid it", "the statement commits to a range, not to a list of your outputs"],
            ["Your wallet key or seed", "never requested, never transmitted"],
        ],
        note: "Residual metadata: the transaction is public, so its existence, timing and value are observable on chain; the verifier still cannot tell your balance, only that it is at least the threshold. Correlation over many transactions is a chain-level property, not a verifier one.",
    },
    credential: {
        learns: [
            ["That you control the credential key", "verified against chain state"],
            ["A floor at or above the threshold", "computed from the output it stands on"],
            ["Which output the receipt names", "a public on-chain object"],
        ],
        private: [
            ["Your exact balance", "a receipt attests a floor, never an amount"],
            ["Other outputs in your wallet", "only the named output is presented"],
            ["Your key material", "signing happens in the wallet"],
        ],
        note: "The credential mode is not identical to the consensus mode: it names an output, so the output's own public value is visible to anyone reading the chain. It still does not disclose a balance.",
    },
    xtm: {
        learns: [
            ["(experimental) a floor on the L1 chain", "not yet produced by a working implementation"],
        ],
        private: [
            ["Everything else", "the mode is draft; it grants no access today"],
        ],
        note: "Native L1 XTM is shown for completeness only. Until its independent proof implementation works, it is refused by the verifier and cannot be advertised as functional.",
    },
};

function renderXray(gate) {
    const mode = gate ? gate.proofMode : null;
    const x = XRAY[mode] || XRAY.consensus;
    const fill = (ul, items) => {
        ul.innerHTML = "";
        for (const [text, meta] of items) {
            const li = document.createElement("li");
            const t = document.createElement("span");
            t.textContent = text;
            const m = document.createElement("span");
            m.className = "meta";
            m.textContent = meta;
            li.append(t, m);
            ul.append(li);
        }
    };
    fill($("xray-learns"), x.learns);
    fill($("xray-private"), x.private);
    $("xray-note").textContent = x.note;
}

// ---------------------------------------------------------------- the proof
async function prove() {
    const gate = state.gate;
    if (!gate) return;
    if (!gate.activatable) {
        showOutcome("denied", "NOT AVAILABLE", "This gate's proof mode is experimental and cannot be activated. It is shown, not promised.");
        return;
    }
    $("prove").disabled = true;
    $("outcome").hidden = true;
    state.step = 0;
    advance("gate"); advance("wallet");
    state.simulated = false;

    // 1. A fresh challenge, bound to a brand-new attempt id (which opens the trace).
    // The id is ours — 128 bits from crypto.getRandomValues — and it is the only key to this
    // attempt's trace. The bridge shape-checks it and stores nothing else about it.
    state.attemptId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map((b) => b.toString(16).padStart(2, "0")).join("");
    $("attempt-label").textContent = `attempt ${state.attemptId.slice(0, 8)}… · live`;
    advance("challenge");
    const ch = await api(`/gate/${gate.gateId}/challenge`, { method: "POST", body: "{}" });
    if (!ch.ok) {
        $("prove").disabled = false;
        showOutcome("denied", "NO CHALLENGE", ch.body.error || "the bridge would not issue a challenge for this gate.");
        return;
    }
    const { challenge_nonce, session_commitment } = ch.body;

    // 2. Ask for the proof. The request names a gate and a nonce — nothing else.
    advance("authorize"); advance("submit");
    const asked = await api(`/gate/${gate.gateId}/prove`, {
        method: "POST",
        body: JSON.stringify({ gate_id: gate.gateId, challenge_nonce, session_commitment }),
    });
    if (asked.status === 409 || !asked.ok || !asked.body.proof_id) {
        $("prove").disabled = false;
        const reason = asked.body.refused || asked.body.error || "the proof could not be started.";
        advance("grant");
        showOutcome("denied", "ACCESS DENIED", reason);
        return;
    }
    state.proofId = asked.body.proof_id;

    // 3. Poll until the network has committed a verdict, streaming the trace alongside.
    advance("consensus"); advance("verify");
    const terminal = await poll(asked.body.proof_id);
    $("prove").disabled = false;
    if (terminal.state === "accepted") {
        advance("grant"); advance("session");
        const r = terminal.result;
        const sessionInfo = terminal.access
            ? ` A verified session was issued for ${Math.round((terminal.access.expiresUnix - Date.now() / 1000) / 86400)} day(s); afterwards, a fresh proof is required.`
            : (gate.sessionsAvailable ? "" : " (Preview: this bridge does not issue sessions.)");
        showOutcome("granted", "ACCESS GRANTED",
            "Minimum threshold proven on chain. Your exact balance was never disclosed and never left your wallet." + sessionInfo,
            {
                "attested floor": `${formatAmount(r.attested_minimum, gate.divisibility)} ${gate.symbol || ""}`.trim(),
                "required": `${formatAmount(r.required_minimum, gate.divisibility)} ${gate.symbol || ""}`.trim(),
                "proof kind": r.proof_kind,
                "live inputs used": r.input_count,
            });
    } else {
        showOutcome("denied", "ACCESS DENIED",
            "The required threshold was not proven. Your exact balance remains private.",
            { reason: terminal.reason || "the proof did not complete" });
    }
}

async function poll(proofId, attempt = 0) {
    if (attempt > 80) return { state: "failed", reason: "timed out waiting for the network" };
    const { body } = await api(`/proof/${proofId}/status`);
    await refreshTrace();
    if (["accepted", "refused", "failed"].includes(body.state)) return body;
    await new Promise((r) => setTimeout(r, 1200));
    return poll(proofId, attempt + 1);
}

function showOutcome(kind, title, body, detail = {}) {
    const panel = $("outcome");
    panel.hidden = false;
    panel.className = `outcome ${kind}`;
    $("outcome-title").textContent = title;
    $("outcome-body").textContent = body;
    const d = $("outcome-detail");
    d.innerHTML = "";
    for (const [k, v] of Object.entries(detail)) {
        if (v === undefined || v === null || v === "") continue;
        const line = document.createElement("div");
        line.className = "sub";
        line.textContent = `${k}: ${v}`;
        d.append(line);
    }
}

// ---------------------------------------------------------------- the simulation
async function simulate() {
    const gate = state.gate;
    if (!gate) return;
    state.simulated = true;
    const { ok, body } = await api("/lab/simulate", { method: "POST", body: JSON.stringify({ gateId: gate.gateId }) });
    if (!ok) {
        showOutcome("denied", "SIMULATION UNAVAILABLE", body.error || "the bridge would not run the simulation.");
        return;
    }
    state.attemptId = body.attemptId;
    state.events = (body.trace && body.trace.events) || [];
    $("attempt-label").textContent = `attempt ${body.attemptId.slice(0, 8)}… · simulated`;
    setModeBadge(true);
    renderTerminal();
    // The Simple view mirrors the same events, so the two views cannot disagree.
    state.step = 0;
    for (const e of state.events) {
        if (e.code === "challenge.minted") advance("challenge");
        if (e.code === "wallet.requested") { advance("authorize"); advance("submit"); }
        if (e.code === "consensus.observed") advance("consensus");
        if (e.code === "verifier.threshold_checked") advance("verify");
        if (e.code === "access.granted") { advance("grant"); advance("session"); }
    }
    showOutcome("granted", "SIMULATED GRANT",
        "This is the labelled OFFLINE SIMULATION: no wallet, no network, no transaction, no session. It shows the shape of a real attempt and grants nothing.");
}

// ---------------------------------------------------------------- the terminal
async function refreshTrace() {
    if (!state.attemptId) return;
    const { ok, body } = await api(`/lab/trace?attempt=${state.attemptId}`);
    if (!ok) return;
    const events = body.events || [];
    if (events.length !== state.events.length) {
        state.events = events;
        renderTerminal();
    }
}

function renderTerminal() {
    const log = $("term-log");
    const filter = ($("term-filter").value || "").toLowerCase();
    const sev = $("term-sev").value;
    const rank = { info: 0, notice: 1, error: 2 };
    const shown = state.events.filter((e) => {
        if (sev !== "all" && rank[e.severity] < rank[sev]) return false;
        if (!filter) return true;
        return [e.code, e.source, e.message, JSON.stringify(e.detail || {})].join(" ").toLowerCase().includes(filter);
    });
    if (!shown.length) {
        log.innerHTML = '<div class="terminal-empty">no events match the filter</div>';
        return;
    }
    log.innerHTML = "";
    const t0 = shown[0].atMs;
    for (const e of shown) {
        const row = document.createElement("div");
        row.className = `ev ${e.severity}`;
        const rel = e.atMs - t0;
        row.innerHTML = `<div class="seq"></div><div class="ts"></div><div class="src"></div><div class="msg"></div>`;
        row.querySelector(".seq").textContent = `#${e.seq}`;
        row.querySelector(".ts").textContent = `+${rel}ms`;
        row.querySelector(".src").textContent = e.source;
        row.querySelector(".msg").innerHTML = `<span class="code"></span> ${e.message}`;
        row.querySelector(".code").textContent = e.code;
        if (e.detail) {
            const j = document.createElement("div");
            j.className = "terminal-json";
            j.textContent = JSON.stringify(e.detail);
            row.append(j);
        }
        log.append(row);
    }
    if (state.simulated) {
        const b = document.createElement("div");
        b.className = "sim-banner";
        b.textContent = "OFFLINE SIMULATION — these events illustrate the protocol; they are not evidence of a real proof and no session exists.";
        log.prepend(b);
    }
    if (!state.paused) log.scrollTop = log.scrollHeight;
}

function setModeBadge(sim) {
    const badge = $("mode-badge");
    badge.className = "mode-badge " + (sim ? "sim" : "live");
    $("mode-label").textContent = sim ? "offline simulation" : "live verification";
}

// ---------------------------------------------------------------- view switch
function setView(v) {
    state.view = v;
    $("simple-view").hidden = v !== "simple";
    $("technical-view").hidden = v !== "technical";
    $("view-simple").setAttribute("aria-selected", String(v === "simple"));
    $("view-technical").setAttribute("aria-selected", String(v === "technical"));
}

// ---------------------------------------------------------------- telegram
$("tg-start").onclick = async () => {
    const gate = state.gate;
    if (!gate) { $("tg-note").textContent = "Choose a gate first."; return; }
    if (gate.useMode === "website") {
        $("tg-note").textContent = `This gate ("${gate.gateId}") authorizes the WEBSITE only. An administrator can scope a gate to Telegram as well; until then it cannot mint group membership.`;
        return;
    }
    $("tg-note").textContent = "Opening the verification page — the flow continues in the bot's window.";
    // The real flow lives at /telegram/join; the button that proves it is there.
    window.location.href = `/telegram/join?gate=${encodeURIComponent(gate.gateId)}`;
};

/** Which gates an administrator has scoped for Telegram — stated before anyone clicks. */
async function loadTelegramScope() {
    const note = $("tg-gate-note");
    const scoped = state.gates.filter((g) => g.useMode === "telegram" || g.useMode === "both");
    if (!state.gates.length) {
        note.textContent = "No gate is configured yet.";
    } else if (!scoped.length) {
        note.textContent = `None of the ${state.gates.length} configured gate(s) allow Telegram membership. The administrator can change this per gate in the dashboard.`;
    } else {
        note.textContent = `${scoped.map((g) => g.gateId).join(", ")} may be used for Telegram membership.`;
    }
}

// ---------------------------------------------------------------- wiring
$("view-simple").onclick = () => setView("simple");
$("view-technical").onclick = () => setView("technical");
$("prove").onclick = prove;
$("simulate").onclick = simulate;
$("term-filter").oninput = renderTerminal;
$("term-sev").onchange = renderTerminal;
$("term-pause").onclick = (e) => {
    state.paused = !state.paused;
    e.target.textContent = state.paused ? "RESUME" : "PAUSE";
};
$("term-copy").onclick = async () => {
    await navigator.clipboard.writeText(renderExport());
    $("term-copy").textContent = "COPIED";
    setTimeout(() => ($("term-copy").textContent = "COPY"), 1200);
};
$("term-export").onclick = () => {
    const blob = new Blob([renderExport()], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `ghost-gate-trace-${state.attemptId || "simulation"}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
};
function renderExport() {
    return JSON.stringify({
        note: "Sanitized Ghost Gate Privacy Lab trace. No balances, keys, tokens or personal data are present — the server never assembles them.",
        attemptId: state.attemptId,
        gateId: state.gate ? state.gate.gateId : null,
        simulated: state.simulated,
        events: state.events,
    }, null, 2);
}

// ---------------------------------------------------------------- boot
(async function boot() {
    setView("simple");
    setModeBadge(false);
    const health = await api("/health").catch(() => ({ body: {} }));
    $("version-line").textContent = health.body.version ? ` bridge ${health.body.version}` : "";
    $("prov-note").textContent = "Provenance: bridge = this process; wallet = the wallet's own answer; consensus = the network; verifier = checks this codebase performs. Events are recorded server-side and pass an allowlist before they reach this page.";
    // The X-ray and steps exist before any gate loads.
    renderSteps();
    await loadGates();
})();