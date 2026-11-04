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
import { supportedProofModes, walletUsability, parseAmount, formatAmount, networkVerdict, describeProviderError } from "/js/ghost/capabilities.js";
import { advanceTechnicalLifecycle, newTechnicalLifecycle, switchTechnicalView, technicalSummaryRows } from "/lab/technical-state.js";
import { connectButtonState, connectedWallet, disconnectedWallet, newWalletConnection, switchWalletView } from "/lab/wallet-connection-state.js";

const $ = (id) => document.getElementById(id);

const state = {
    view: "simple",
    gates: [],
    gate: null,
    mode: null,          // the selected wallet option
    requestedGate: null, // an explicit ?gate= in the URL, honoured before any default
    attemptId: null,
    proofId: null,
    simulated: false,
    step: -1,            // index into STEPS; -1 = idle
    events: [],
    paused: false,
    lastSeq: 0,
    gateListSig: null,   // signature of the last-rendered gate list (avoid rebuilding an open dropdown)
    walletFailures: 0,   // consecutive polls where the wallet was absent or unreachable
    walletConnecting: false, // one user gesture may create at most one pending wallet request
    walletConnection: newWalletConnection(),
    walletConnectionAddress: null,
    walletConnectionUnsubscribe: null,
    technical: newTechnicalLifecycle(),
    bridgeStatus: "unavailable / not reported",
};

// Local browser instrumentation only. These marks never leave the page and contain no wallet
// material; they let an operator distinguish an injection delay from the wallet's own approval UI.
function markWalletConnect(stage) {
    if (typeof performance === "undefined" || typeof performance.mark !== "function") return;
    performance.mark(`ghost-gate:connect:${stage}`);
}

function measureWalletConnect(name, start, end) {
    if (typeof performance === "undefined" || typeof performance.measure !== "function") return;
    try { performance.measure(`ghost-gate:connect:${name}`, start, end); } catch { /* optional diagnostic */ }
}

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

function middleEllipsis(value, maxChars = 32) {
    const text = String(value || "");
    if (text.length <= maxChars) return text;
    const available = Math.max(2, maxChars - 1);
    const prefix = Math.ceil(available / 2);
    const suffix = Math.floor(available / 2);
    return `${text.slice(0, prefix)}…${text.slice(-suffix)}`;
}

function clearOutputPresentation() {
    const row = $("outcome-output");
    if (row) row.hidden = true;
    const value = $("outcome-output-value");
    if (value) value.textContent = "";
    const copy = $("copy-output");
    if (copy) {
        copy.disabled = false;
        copy.textContent = "COPY";
        copy.onclick = null;
    }
}

function setOutputPresentation(substateId) {
    const output = String(substateId || "");
    const row = $("outcome-output");
    const value = $("outcome-output-value");
    const copy = $("copy-output");
    if (!row || !value || !output) return;
    value.textContent = middleEllipsis(output, 34);
    value.title = output;
    row.hidden = false;
    if (copy) {
        copy.onclick = async () => {
            try {
                await navigator.clipboard.writeText(output);
                copy.textContent = "COPIED";
                setTimeout(() => { copy.textContent = "COPY"; }, 1200);
            } catch {
                copy.textContent = "UNAVAILABLE";
            }
        };
    }
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

/** The step list the selected gate actually exercises. A credential gate has no consensus wait:
 *  its verdict is a signature checked against chain state, so that step is relabelled rather
 *  than shown as a block wait that never happens. Ids are stable across modes, so step
 *  advancement is unaffected. */
function stepList() {
    if (state.gate && state.gate.proofMode === "credential") {
        return STEPS.map((s) => s.id === "consensus"
            ? {
                ...s,
                title: "Verify the signed output against chain state",
                note: "No block wait: the bridge reads the named output from chain state, checks its public value promise against the gate's threshold, and checks the signature against the output's own on-chain spend key.",
            }
            : s);
    }
    return STEPS;
}

/** Which gate to select when nothing (or nothing valid) is selected.
 *  Order: an explicit ?gate= in the URL, then this session's or a remembered explicit choice,
 *  then the first credential-mode gate — the only mode a browser wallet can complete end to end
 *  without a wallet daemon — then the cheapest gate. The old behaviour, always the cheapest
 *  gate, silently picked the consensus gate and steered a Sapient holder into the wrong flow. */
function pickDefaultGate(gates) {
    const wanted = state.requestedGate || (() => { try { return localStorage.getItem("gg-lab-gate"); } catch { return null; } })();
    if (wanted && gates.some((g) => g.gateId === wanted)) return wanted;
    const cred = gates.find((g) => g.proofMode === "credential");
    return (cred || gates[0]).gateId;
}

/** Populate the gate picker from the registry. The registry is the only source; a value typed
 *  here can never become a threshold. */
function populateGateSelect() {
    const sel = $("gate-select");
    sel.innerHTML = "";
    if (!state.gates.length) {
        sel.innerHTML = '<option value="">no gate published yet</option>';
        return;
    }
    for (const g of state.gates) {
        const opt = document.createElement("option");
        opt.value = g.gateId;
        opt.textContent = `${g.gateId} — ${formatAmount(g.thresholdRaw, g.divisibility)} ${g.symbol || "?"}`;
        sel.append(opt);
    }
    sel.onchange = () => {
        // An explicit choice sticks — for this session and the next. The default logic only
        // ever applies when nothing valid is selected.
        try { localStorage.setItem("gg-lab-gate", sel.value); } catch { /* private mode */ }
        selectGate(sel.value);
    };
}

function selectGate(gateId) {
    state.gate = state.gates.find((g) => g.gateId === gateId) || null;
    if (gateId) $("gate-select").value = gateId;
    state.step = -1;
    state.technical = newTechnicalLifecycle();
    renderGateFacts(state.gate);
    renderTechnicalFacts();
    renderWallets();
    renderSteps();
    $("outcome").hidden = true;
}

function updateTechnical(update) {
    state.technical = advanceTechnicalLifecycle(state.technical, update);
    renderTechnicalFacts();
}

function renderTechnicalFacts() {
    const facts = $("technical-facts");
    if (!facts) return;
    const threshold = state.gate ? `${formatAmount(state.gate.thresholdRaw, state.gate.divisibility)} ${state.gate.symbol || "asset"}` : "unavailable / not reported";
    facts.replaceChildren(...technicalSummaryRows(state.gate, state.technical, state.bridgeStatus, threshold).flatMap(([key, value]) => {
        const term = document.createElement("dt");
        term.textContent = key;
        const detail = document.createElement("dd");
        detail.textContent = value;
        return [term, detail];
    }));
}

/** Facts are read from the registry response — never from a value typed here.
 *  The "minimum proven" is the visually dominant fact: it is the ONLY thing being proven,
 *  and the one number a judge should read in the first two seconds. */
function renderGateFacts(gate) {
    $("gate-count-note").textContent = state.gates.length
        ? `${state.gates.length} configured gate${state.gates.length === 1 ? "" : "s"} — read from the administrator's published policy; this page cannot change a threshold.`
        : "Gates come from the administrator's published policy. This page cannot change a threshold.";

    if (!gate) {
        $("gt-minimum").textContent = "no gate configured";
        $("gt-minimum").classList.add("bad");
        $("gt-asset").textContent = "—";
        $("gt-raw").textContent = "—";
        $("gt-div").textContent = "—";
        $("gt-resource").firstElementChild.textContent = "—";
        $("copy-resource").hidden = true;
        $("gt-mode").textContent = "no gate";
        $("gt-mode").className = "badge";
        $("gt-sessions").textContent = "sessions unavailable";
        $("gt-sessions").className = "badge bad";
        $("gt-availability").hidden = true;
        renderXray(null);
        loadTelegramScope();
        return;
    }
    $("gt-minimum").classList.remove("bad");
    const human = formatAmount(gate.thresholdRaw, gate.divisibility);
    $("gt-minimum").textContent = `≥ ${human} ${gate.symbol || ""}`.trim();
    $("gt-asset").textContent = gate.symbol || "(unlabelled)";
    $("gt-asset").title = gate.resourceAddress || "";
    $("gt-raw").textContent = String(gate.thresholdRaw);
    $("gt-div").textContent = String(gate.divisibility);

    const resource = gate.resourceAddress || "";
    const code = $("gt-resource").firstElementChild;
    code.textContent = resource ? `${resource.slice(0, 12)}…${resource.slice(-6)}` : "—";
    code.title = resource;
    $("copy-resource").hidden = !resource;
    $("copy-resource").onclick = async () => {
        await navigator.clipboard.writeText(resource);
        $("copy-resource").textContent = "COPIED";
        setTimeout(() => ($("copy-resource").textContent = "COPY"), 1200);
    };

    const modeName = gate.proofMode === "consensus" ? "consensus · wallet daemon" : gate.proofMode;
    $("gt-mode").textContent = modeName;
    $("gt-mode").className = `badge ${gate.activatable ? "ok" : "warn"}`;
    $("gt-mode").title = gate.activatable
        ? "This proof mode can be activated on this deployment."
        : "Experimental: shown, refused, never advertised as functional.";

    if (gate.sessionsAvailable) {
        $("gt-sessions").textContent = "sessions · issued server-side";
        $("gt-sessions").className = "badge ok";
        $("gt-sessions").title = "Access is granted by the server against the verified session.";
    } else {
        $("gt-sessions").textContent = "sessions · not issued (preview)";
        $("gt-sessions").className = "badge bad";
        $("gt-sessions").title = "This bridge is not registry-backed, so no access session is issued.";
    }

    if (!gate.activatable) {
        $("gt-availability").hidden = false;
        $("gt-availability").textContent = "experimental — cannot activate";
        $("gt-availability").className = "badge bad";
    } else {
        $("gt-availability").hidden = true;
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
    // The consensus path needs a wallet daemon; the bridge knows whether one is there. A
    // credential-only gate has no component for a consensus proof to execute against, so the
    // wallet daemon is not offered at all — advertising it here is how a Sapient holder was
    // once steered into a walletd route that could only refuse.
    if (gate.proofMode === "consensus") {
        options.push({ id: "walletd", label: "Wallet daemon · consensus (advanced)" });
    }
    if (gate.proofMode === "credential" || gate.proofMode === "consensus") {
        options.push({ id: "sapient", label: "Sapient — Ootle L2 · credential" });
        options.push({ id: "universe", label: "Tari Universe — in-app · credential" });
    }

    for (const o of options) {
        const opt = document.createElement("option");
        opt.value = o.id;
        opt.textContent = o.label;
        sel.append(opt);
    }
    if (!options.length) {
        // An experimental gate no wallet can prove: say so instead of leaving a silent dropdown.
        sel.innerHTML = '<option value="">no wallet can prove this gate</option>';
        state.mode = null;
        const note = $("wallet-note");
        note.classList.remove("ok", "warn", "bad");
        note.classList.add("bad");
        note.textContent = "This gate's proof mode is experimental; no wallet on this page can prove it.";
        renderConnectIntro();
        return;
    }
    sel.onchange = () => selectMode(sel.value);
    selectMode(options[0].id);
}

async function selectMode(id) {
    if (state.walletConnecting) return;
    if (state.walletConnection.connected && state.walletConnection.mode !== id) {
        forgetWalletConnection("Wallet selection changed. Connect the selected wallet before proving.");
    }
    state.mode = id;
    const note = $("wallet-note");
    note.classList.remove("ok", "warn", "bad");
    // Probe the selected provider for real; report what is actually there.
    let provider = id === "walletd" ? walletdProvider(location.origin) : id === "universe" ? universeProvider() : sapientProvider();
    let usable = { usable: false, reason: "not probed", modes: [] };
    try {
        // The provider surface is probe() — the same discovery + capability read every adapter
        // implements. (Calling a non-existent capabilities() here used to throw and report
        // every wallet — including a reachable wallet daemon — as "not reachable".)
        const probe = await provider.probe();
        usable = walletUsability(probe.capabilities || {}, {
            canConsensusProof: id === "walletd" && probe.available === true,
        });
        if (!probe.available) {
            usable = { usable: false, reason: probe.unavailableReason || "this wallet is not reachable from this page", modes: [] };
        } else if (!probe.capabilities) {
            // The extension is present but this site is not authorized yet (the real Sapient
            // answers 4100 for capability reads before the account request). The wallet exists —
            // say so, and point at the Connect button instead of declaring it unusable.
            usable = { usable: false, reason: null, modes: [] };
            usable.notConnectedReason = probe.unusableReason || "the wallet is not connected to this site yet";
        }
    } catch (e) {
        usable = { usable: false, reason: "provider did not answer", modes: [] };
    }
    if (id === "walletd") {
        if (usable.usable) {
            note.classList.add("ok");
            note.textContent = "Wallet daemon reachable. The consensus path proves a stealth threshold on chain.";
        } else {
            note.classList.add("warn");
            note.textContent = "Wallet daemon not reachable. Start walletd or choose another supported proof method.";
        }
    } else if (usable.usable) {
        note.classList.add("ok");
        note.textContent = "This wallet can build the credential statement this gate accepts.";
    } else if (usable.notConnectedReason) {
        note.classList.add("warn");
        note.textContent = "Sapient detected — press Connect wallet to authorize this site.";
    } else {
        note.classList.add("bad");
        note.textContent = `This wallet cannot prove this gate: ${usable.reason || "unsupported"}`;
    }
    renderConnectIntro();
    // The resume row exists only for a credential gate driven by a browser wallet: resuming
    // signs over an output that already exists on chain — there is nothing for the wallet
    // daemon to build, and nothing for it to do here.
    const resumeRow = $("resume-row");
    if (resumeRow) {
        resumeRow.hidden = !(state.gate && state.gate.proofMode === "credential" && state.mode !== "walletd");
        if (!resumeRow.hidden) {
            try {
                const saved = localStorage.getItem("gg-last-output");
                if (saved) $("resume-substate").value = saved;
            } catch { /* private mode */ }
        }
    }
}

// ---------------------------------------------------- connection-only ceremony
// "Connect wallet" reads identity facts and nothing more: an address, the wallet's own network
// name, the capability flags, and — only when the wallet offers it — a read-only signature over
// a locally-generated nonce that proves the person holds the wallet. It deliberately does not
// mint a bridge challenge, does not build a proof, and never authorizes a spend: per the
// integration contract, a connection can never grant access by itself.
async function connectWallet() {
    // Disabled buttons stop ordinary pointer clicks, but this guard also covers keyboard and
    // synthetic/re-entrant events. A second click must never produce a second permission prompt.
    if (state.walletConnecting || state.walletConnection.connected) return;
    state.walletConnecting = true;
    const walletSelect = $("wallet-select");
    if (walletSelect) walletSelect.disabled = true;
    const detail = $("wallet-detail");
    const walletName = state.mode === "universe" ? "Tari Universe" : "Sapient";
    const setRow = (id, cls, text) => {
        const row = $(id).closest(".wd-row");
        row.classList.remove("ok", "warn", "bad");
        if (cls) row.classList.add(cls);
        $(id).textContent = text;
    };
    detail.hidden = false;
    $("wd-caps-row").hidden = true;
    $("wd-ownership-row").hidden = true;
    markWalletConnect("click");
    setRow("wd-status", null, `Waiting for ${walletName}…`);
    $("wd-address").textContent = "—";
    $("wd-network").textContent = "—";
    renderConnectIntro();
    try {
        if (state.mode === "walletd") {
            const res = await api("/wallet/status");
            const b = res.body || {};
            if (!res.ok || b.reachable !== true) {
                setRow("wd-status", "bad", b.error || "The wallet daemon is not reachable.");
            } else {
                setRow("wd-status", "ok", "Wallet daemon reachable — the bridge's trusted-local proof path.");
            }
            $("wd-network").textContent = b.network_name
                ? `${b.network_name} (byte ${b.network})` : "not reported";
            $("wd-address").textContent = b.has_default_account
                ? "default account present (held by the daemon, not this browser)" : "no default account";
            return;
        }

        // window.tari may not exist at parse time: the extension injects at document_start, the
        // connector on script load. Wait briefly (or for tari#initialized) so a slow-injecting
        // wallet is not mistaken for "no wallet installed".
        if (!window.tari) {
            markWalletConnect("provider-wait-start");
            setRow("wd-status", null, `Waiting for ${walletName} to finish initializing…`);
            await new Promise((resolve) => {
                let settled = false;
                const done = () => { if (!settled) { settled = true; window.removeEventListener("tari#initialized", done); resolve(); } };
                window.addEventListener("tari#initialized", done);
                setTimeout(done, 1500);
            });
            markWalletConnect("provider-wait-end");
            measureWalletConnect("provider-wait", "ghost-gate:connect:provider-wait-start", "ghost-gate:connect:provider-wait-end");
            if (!window.tari) {
                setRow("wd-status", "bad", `${walletName} did not finish initializing within 1.5 seconds. It was not asked to connect; wait for the wallet and try again.`);
                return;
            }
        }
        const provider = state.mode === "universe" ? universeProvider() : sapientProvider();

        // 1) Accounts — FIRST, and the only wallet call this button makes that can prompt. The
        //    real Sapient answers 4100 (not connected) for any capability read that arrives
        //    before an authorized account request — authorization must precede every other
        //    call. Read-only: it shares the public address and grants no spend authority. The
        //    request fires exactly once per click; nothing here retries approval-triggering
        //    calls, so a declined prompt is never re-asked by accident.
        let accounts;
        try {
            setRow("wd-status", null, `Waiting for ${provider.label} approval…`);
            markWalletConnect("accounts-requested");
            accounts = await provider.request("tari_requestAccounts");
            markWalletConnect("accounts-resolved");
            measureWalletConnect("approval", "ghost-gate:connect:accounts-requested", "ghost-gate:connect:accounts-resolved");
        } catch (e) {
            markWalletConnect("accounts-rejected");
            measureWalletConnect("approval", "ghost-gate:connect:accounts-requested", "ghost-gate:connect:accounts-rejected");
            const d = describeProviderError(e);
            setRow("wd-status", d.cls, d.text);
            return;
        }
        const address = Array.isArray(accounts) && accounts.length ? accounts[0] : null;
        if (!address) {
            setRow("wd-status", "bad", "The wallet returned no account address, so there is nothing to connect to.");
            return;
        }
        state.walletConnection = connectedWallet(state.mode);
        state.walletConnectionAddress = address;
        watchWalletConnection();
        renderConnectIntro();
        $("wd-address").textContent = `${address.slice(0, 24)}…${address.slice(-10)} (${address.length} chars)`;
        setRow("wd-status", "ok", `${provider.label} connected.`);
        // The passive note under the selector must not keep last session's "press Connect" text:
        // once the wallet has actually answered, it reports the connected state and — once the
        // network verdict is in — whether the selected gate is even attemptable from here.
        const note = $("wallet-note");
        note.classList.remove("ok", "warn", "bad");
        note.classList.add("ok");
        note.textContent = `${provider.label} connected. Connecting is diagnostic only — this grants nothing.`;

        // 2) Capabilities — only after an authorized connection, or the real wallet refuses
        //    them with 4100. A refusal here is a warning, never a hard stop: the connection
        //    itself already succeeded.
        let caps = null;
        try {
            caps = await provider.request("tari_getCapabilities");
        } catch (e) {
            if (e && e.code === 4100) {
                forgetWalletConnection("Wallet authorization ended. Connect wallet again before proving.");
                return;
            }
            const d = describeProviderError(e);
            setRow("wd-network", d.cls, d.text);
        }

        // 3) Network — compare the wallet's own report against the gate's Ootle byte.
        let netName = null;
        try { netName = await provider.request("tari_getNetwork"); } catch (e) {
            if (e && e.code === 4100) {
                forgetWalletConnection("Wallet authorization ended. Connect wallet again before proving.");
                return;
            }
        }
        const gate = state.gate;
        if (gate) {
            const v = networkVerdict(netName, gate.network);
            setRow("wd-network", v.ok ? "ok" : "warn", v.verdict);
            // The note now carries the compatibility verdict: the connected state plus whether
            // the selected gate can be attempted from this wallet, in one honest sentence.
            if (!v.ok) {
                note.classList.remove("ok");
                note.classList.add("warn");
                note.textContent = `${provider.label} connected — but this gate is on a different network, so proving is blocked here. Connecting for diagnostics is fine.`;
            } else {
                note.textContent = `${provider.label} connected and on the gate's network — this account may prove the gate.`;
            }
        } else {
            $("wd-network").textContent = netName ? `${netName} (no gate selected, so no verdict)` : "the wallet did not report a network";
        }

        // 4) Capabilities — the flags that decide which proof modes this account can offer.
        const capNames = caps ? Object.entries(caps).filter(([, v]) => v === true).map(([k]) => k) : [];
        $("wd-caps-row").hidden = false;
        $("wd-caps").textContent = capNames.length
            ? capNames.join(", ")
            : "the wallet did not report capabilities, so no proof mode can be assessed yet";
        const credOk = caps && caps.privateSpend === true && caps.minimumValuePromise === true && caps.ownershipProof === true;
        if (!credOk) {
            setRow("wd-status", "warn", "Connected, but this account cannot offer the credential proof this gate's mode needs.");
        }

        // 5) Wallet-ownership signature — only when the wallet offers it, and only over a nonce
        //    this page generated. It proves the person holds the wallet, not that the wallet
        //    holds any asset, and it is never an eligibility proof.
        if (caps && caps.walletOwnershipProof === true) {
            const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)),
                (b) => b.toString(16).padStart(2, "0")).join("");
            try {
                const proof = await provider.request("tari_signWalletOwnershipChallenge", { challenge: nonce });
                $("wd-ownership-row").hidden = false;
                $("wd-ownership").textContent = proof && proof.signature
                    ? `signed over nonce ${nonce.slice(0, 12)}… (signature ${proof.signature.slice(0, 14)}…) — proof of wallet possession only`
                    : "the wallet returned no signature";
            } catch (e) {
                if (e && e.code === 4100) forgetWalletConnection("Wallet authorization ended. Connect wallet again before proving.");
                $("wd-ownership-row").hidden = false;
                $("wd-ownership").textContent = e && e.code === 4001
                    ? "you declined the signature request"
                    : `signature step refused: ${e && e.message ? e.message : e}`;
            }
        } else {
            $("wd-ownership-row").hidden = false;
            $("wd-ownership").textContent = "this wallet does not offer a wallet-ownership signature";
        }
    } catch (e) {
        setRow("wd-status", "bad", `Connection failed: ${e && e.message ? e.message : e}`);
    } finally {
        state.walletConnecting = false;
        if (walletSelect) walletSelect.disabled = false;
        renderConnectIntro();
    }
}

/** One line under the connect button, refreshed whenever the mode changes. */
function renderConnectIntro() {
    const btn = $("connect-wallet");
    if (!btn) return;
    // A removed provider is an actual loss, not an invitation to reconnect automatically. The
    // next user click is the only path that can request permission again.
    if (state.walletConnection.connected && state.walletConnection.mode !== "walletd" && !window.tari) {
        forgetWalletConnection("Wallet provider is no longer available. Connect again when it returns.", true);
    }
    const presentation = connectButtonState({
        hasGate: Boolean(state.gate), mode: state.mode, connecting: state.walletConnecting,
        connection: state.walletConnection,
    });
    btn.hidden = presentation.hidden;
    btn.disabled = presentation.disabled;
    btn.textContent = presentation.label;
    btn.title = presentation.title;
    btn.setAttribute("aria-label", presentation.label);
}

function forgetWalletConnection(message, fromRender = false) {
    if (typeof state.walletConnectionUnsubscribe === "function") state.walletConnectionUnsubscribe();
    state.walletConnectionUnsubscribe = null;
    state.walletConnection = disconnectedWallet();
    state.walletConnectionAddress = null;
    const note = $("wallet-note");
    if (message && note) {
        note.classList.remove("ok", "bad");
        note.classList.add("warn");
        note.textContent = message;
    }
    if (!fromRender) renderConnectIntro();
}

function watchWalletConnection() {
    if (typeof state.walletConnectionUnsubscribe === "function") state.walletConnectionUnsubscribe();
    state.walletConnectionUnsubscribe = null;
    const rawProvider = window.tari;
    if (!rawProvider || typeof rawProvider.on !== "function") return;
    const unsubscribe = rawProvider.on("accountsChanged", (accounts) => {
        if (!state.walletConnection.connected) return;
        if (Array.isArray(accounts) && accounts.includes(state.walletConnectionAddress)) return;
        const reason = Array.isArray(accounts) && accounts.length ? "Wallet account changed. Connect wallet again before proving." : "Wallet disconnected. Connect wallet again before proving.";
        forgetWalletConnection(reason);
    });
    if (typeof unsubscribe === "function") state.walletConnectionUnsubscribe = unsubscribe;
}

// ---------------------------------------------------------------- steps + view
function renderSteps() {
    const ol = $("steps");
    ol.innerHTML = "";
    stepList().forEach((s, i) => {
        const li = document.createElement("li");
        li.dataset.step = s.id;
        li.innerHTML = '<span class="step-marker" aria-hidden="true"></span><div><div class="step-title"></div><div class="step-note"></div></div>';
        li.querySelector(".step-marker").textContent = String(i + 1);
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
    // Defence in depth: a credential-only gate offers no wallet daemon (see renderWallets), but
    // if a stale list or a race ever pairs the two, this refuses before anything is asked.
    if (gate.proofMode === "credential" && state.mode === "walletd") {
        showOutcome("denied", "WRONG PROOF MODE",
            "This gate is credential-only: it binds no on-chain component, so the wallet daemon cannot prove it. Choose Sapient or Tari Universe.");
        return;
    }
    $("prove").disabled = true;
    $("outcome").hidden = true;
    clearOutputPresentation();
    state.step = 0;
    advance("gate"); advance("wallet");
    state.simulated = false;

    // 1. A fresh challenge, bound to a brand-new attempt id (which opens the trace).
    // The id is ours — 128 bits from crypto.getRandomValues — and it is the only key to this
    // attempt's trace. The bridge shape-checks it and stores nothing else about it.
    state.attemptId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map((b) => b.toString(16).padStart(2, "0")).join("");
    state.technical = newTechnicalLifecycle();
    updateTechnical({ challenge: "requesting fresh single-use challenge", replay: "pending issuance" });
    $("attempt-label").textContent = `attempt ${state.attemptId.slice(0, 8)}… · live`;
    advance("challenge");
    const ch = await api(`/gate/${gate.gateId}/challenge`, { method: "POST", body: "{}" });
    if (!ch.ok) {
        updateTechnical({ challenge: `not issued · HTTP ${ch.status}`, verification: "not started", failure: "challenge refused" });
        $("prove").disabled = false;
        showOutcome("denied", "NO CHALLENGE", ch.body.error || "the bridge would not issue a challenge for this gate.");
        return;
    }
    const { challenge_nonce, session_commitment } = ch.body;
    updateTechnical({ challenge: "issued · fresh single-use", replay: "fresh / unconsumed" });

    // 2. Two proof paths, dispatched on the wallet the visitor chose — never on a guess.
    //    walletd  → the consensus path: the bridge drives the local daemon (Mode A).
    //    Sapient / Universe → the credential path: the wallet shields an output carrying the
    //    gate's threshold as its PUBLIC minimum-value promise, then signs this attempt's
    //    challenge over that one output; the bridge verifies both against chain state (Mode B).
    //    The credential route serves both website and Telegram flows; only telegram-only
    //    gates are refused here (those arrive through the Telegram join flow).
    advance("authorize"); advance("submit");
    if (state.mode !== "walletd") {
        await proveCredential(gate, challenge_nonce, session_commitment);
        return;
    }
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
        if (r && r.substate_id) {
            updateTechnical({ output: r.substate_id });
            setOutputPresentation(r.substate_id);
        }
        const sessionInfo = terminal.access
            ? ` A verified session was issued for ${Math.round((terminal.access.expiresUnix - Date.now() / 1000) / 86400)} day(s); afterwards, a fresh proof is required.`
            : (gate.sessionsAvailable ? "" : " (Preview: this bridge does not issue sessions.)");
        showOutcome("granted", "ACCESS GRANTED",
            "Minimum threshold proven on chain. Your exact balance was never disclosed and never left your wallet." + sessionInfo,
            {
                "attested floor": `${formatAmount(r.attested_minimum, gate.divisibility)} ${gate.symbol || ""}`.trim(),
                // A missing threshold in the receipt means the backend did not report one —
                // say exactly that. Never substitute a success-looking value for absent
                // backend evidence: "null tTARI" was the old silent failure mode.
                "required": r.required_minimum == null
                    ? "unknown — the bridge did not report a threshold"
                    : `${formatAmount(r.required_minimum, gate.divisibility)} ${gate.symbol || ""}`.trim(),
                "proof kind": r.proof_kind,
                "live inputs used": r.input_count,
            });
    } else {
        showOutcome("denied", "ACCESS DENIED",
            "The required threshold was not proven. Your exact balance remains private.",
            { reason: terminal.reason || "the proof did not complete" });
    }
}

/**
 * Mode B — the credential path, driven through the browser wallet.
 *
 * The wallet shields a fresh output carrying the gate's threshold as its public
 * minimum-value promise (the user approves this in the wallet's own UI, with the
 * "permanent and public" warning the wallet itself shows), then signs this attempt's
 * challenge over that one output. The bridge reads the output from chain state, checks
 * floor ≥ threshold against the live policy, checks the signature against the output's
 * own on-chain spend key, and grants the session. This page never sees a key, a balance,
 * or a UTXO inventory: it relays four identifiers and a signature.
 */
async function proveCredential(gate, challenge_nonce, session_commitment) {
    if (gate.useMode === "telegram") {
        updateTechnical({ credential: "not submitted", verification: "not started", failure: "gate is scoped to Telegram" });
        await refreshTrace();
        $("prove").disabled = false;
        showOutcome("denied", "WRONG GATE SCOPE",
            `This gate is scoped to Telegram membership only. Use the Telegram join flow instead.`);
        return;
    }
    const provider = state.mode === "universe" ? universeProvider() : sapientProvider();
    // Shield exactly the threshold: the promise is the floor, and the user's headroom above
    // it is the user's choice, disclosed on the wallet's approval screen.
    const threshold = String(gate.thresholdRaw);
    let built;
    try {
        updateTechnical({ credential: "wallet approval requested" });
        built = await provider.approveAndBuildProof("credential", {
            gateId: gate.gateId,
            resourceAddress: gate.resourceAddress,
            amount: threshold,
            minimumValuePromise: threshold,
            maxFee: "50000",
        });
    } catch (e) {
        if (e && e.code === 4100) forgetWalletConnection("Wallet authorization ended. Connect wallet again before proving.");
        updateTechnical({ credential: "wallet did not provide a proof", verification: "not started", failure: "wallet authorization refused" });
        await refreshTrace();
        $("prove").disabled = false;
        const d = describeProviderError(e, gate);
        showOutcome("denied", "WALLET REFUSED", d.text, {
            ...(e && e.code !== undefined ? { "provider error": `code ${e.code}` } : {}),
        });
        return;
    }
    if (!built || !built.substateId) {
        updateTechnical({ credential: "wallet returned no proof artifact", verification: "not started", failure: "no proof artifact" });
        await refreshTrace();
        $("prove").disabled = false;
        showOutcome("denied", "NO PROOF ARTIFACT", "The wallet produced no output to verify; there is nothing to check against chain state.");
        return;
    }
    // Remember the output so a later attempt can resume from it instead of shielding again:
    // a qualifying output stays qualifying, and re-shielding spends funds for nothing.
    try { localStorage.setItem("gg-last-output", built.substateId); } catch { /* private mode */ }
    await finishCredential(gate, challenge_nonce, session_commitment, built.substateId, provider);
}

/**
 * RESUME EXISTING PROOF — the same credential verdict, over an output that already exists.
 *
 * A shielded output with a qualifying minimum-value promise stays qualifying: re-shielding
 * spends funds for nothing. The resume path mints a FRESH challenge (challenges are
 * single-use and bound to the policy in force), asks the wallet to sign it over the named
 * existing output — the gate's resource is passed explicitly, because no shield ran in this
 * session to set it — and posts the same credential request the fresh path posts. The bridge
 * decides everything; this page only relays identifiers and a signature.
 *
 * The whole operation is one try/catch/finally: a stale outcome from an earlier attempt is
 * cleared FIRST (so this attempt's result can never be mistaken for the last one's), the
 * steps rail restarts from the top (advance() is forward-only and would otherwise leave an
 * old attempt's position on screen), and every failure is named with the provider-error
 * taxonomy rather than a generic rejection. No path here touches the shield request or the
 * walletd prove route — resuming signs; it does not build anything.
 */
async function resumeProof() {
    const gate = state.gate;
    if (!gate) return;
    // Start clean, BEFORE anything can fail: the old outcome panel goes away and the steps
    // rail restarts, so what the visitor reads from here on is THIS attempt only.
    $("outcome").hidden = true;
    clearOutputPresentation();
    state.step = 0;
    renderSteps();
    const proveBtn = $("prove");
    const resumeBtn = $("resume-proof");
    try {
        if (gate.proofMode !== "credential") {
            showOutcome("denied", "WRONG GATE",
                `Resuming applies to a credential-mode gate; "${gate.gateId}" is ${gate.proofMode}. Select a credential gate first.`);
            return;
        }
        if (!state.mode || state.mode === "walletd") {
            showOutcome("denied", "WRONG WALLET",
                "Resuming needs a browser wallet (Sapient or Tari Universe) to sign over the existing output; the wallet daemon cannot do that.");
            return;
        }
        const substateId = ($("resume-substate").value || "").trim();
        // Shape-check only: the bridge verifies existence, ownership and value against chain state.
        // A malformed id here is a typo, not an attack — refuse it before any wallet prompt.
        if (!/^utxo_[0-9a-f]{64}_[0-9a-f]{64}$/i.test(substateId)) {
            showOutcome("denied", "BAD OUTPUT ID",
                "Resume needs the substate id of an existing qualifying output — the utxo_… string the wallet returned when it shielded. Nothing was signed and no challenge was spent.");
            return;
        }

        // A fresh attempt id and a fresh challenge, exactly as the fresh path mints them:
        // single-use, bound to this attempt and to the gate's live policy.
        state.attemptId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map((b) => b.toString(16).padStart(2, "0")).join("");
        state.technical = newTechnicalLifecycle();
        updateTechnical({ challenge: "requesting fresh single-use challenge", replay: "pending issuance" });
        $("attempt-label").textContent = `attempt ${state.attemptId.slice(0, 8)}… · live`;
        advance("challenge");
        const ch = await api(`/gate/${gate.gateId}/challenge`, { method: "POST", body: "{}" });
        if (!ch.ok) {
            updateTechnical({ challenge: `not issued · HTTP ${ch.status}`, verification: "not started", failure: "challenge refused" });
            showOutcome("denied", "NO CHALLENGE", ch.body.error || "the bridge would not issue a challenge for this gate.");
            return;
        }
        const { challenge_nonce, session_commitment } = ch.body;
        updateTechnical({ challenge: "issued · fresh single-use", replay: "fresh / unconsumed" });
        advance("authorize"); advance("submit");
        const provider = state.mode === "universe" ? universeProvider() : sapientProvider();
        await finishCredential(gate, challenge_nonce, session_commitment, substateId, provider);
    } catch (e) {
        // Anything uncaught above — a network failure on the challenge call, a provider that
        // threw before its own handler, anything — lands here with its real shape preserved,
        // and the finally below guarantees the page is never left disabled.
        const d = describeProviderError(e, gate);
        showOutcome("denied", "RESUME FAILED", d.text,
            e && e.code !== undefined ? { "provider error": `code ${e.code}`, detail: String(e && e.message ? e.message : e) } : {});
    } finally {
        proveBtn.disabled = false;
        resumeBtn.disabled = false;
    }
}

/**
 * The credential tail, shared by the fresh and resume paths: sign, submit, report.
 *
 * Every failure mode is named, and the buttons always come back: a network error used to
 * leave the page stuck at a disabled button with no message at all. Signature failures go
 * through the provider-error taxonomy so a decline (4001), a not-connected wallet (4100), an
 * unsupported call (4200/-32601) and the wallet's own internal failure (-32603) each read as
 * what they are — "the user rejected a transaction" is claimed only when it happened.
 */
async function finishCredential(gate, challenge_nonce, session_commitment, substateId, provider) {
    // The ownership signature over THIS bridge's challenge. The wallet re-derives the
    // output's one-time key from the gate's resource — passed explicitly, so a resume does
    // not depend on a shield having run; the bridge re-checks everything against chain state.
    let signed;
    try {
        updateTechnical({ credential: "ownership signature requested" });
        signed = await provider.signChallenge(substateId, challenge_nonce, gate.resourceAddress);
    } catch (e) {
        if (e && e.code === 4100) forgetWalletConnection("Wallet authorization ended. Connect wallet again before proving.");
        updateTechnical({ credential: "signature not provided", verification: "not started", failure: "wallet signature refused" });
        await refreshTrace();
        $("prove").disabled = false;
        $("resume-proof").disabled = false;
        const providerError = String(e && e.message ? e.message : e || "unknown provider error");
        updateTechnical({ providerError: providerError.slice(0, 400) });
        const d = describeProviderError(e, gate);
        showOutcome("denied", "SIGNATURE REFUSED", d.text, {
            ...(e && e.code !== undefined ? { "provider error": `code ${e.code}` } : {}),
            detail: String(e && e.message ? e.message : e),
        });
        return;
    }
    // An unusable signature is refused HERE, not forwarded: the bridge would only refuse it
    // again, and the visitor should be told the wallet's answer was incomplete.
    if (!signed || !signed.publicNonce || !signed.signature) {
        updateTechnical({ credential: "incomplete signature", verification: "not started", failure: "incomplete wallet signature" });
        await refreshTrace();
        $("prove").disabled = false;
        $("resume-proof").disabled = false;
        showOutcome("denied", "INCOMPLETE SIGNATURE",
            "The wallet returned a signature missing its nonce or signature component, so the proof cannot be verified. Nothing was submitted.",
            { received: signed ? Object.keys(signed).join(", ") : "nothing" });
        return;
    }
    advance("consensus"); advance("verify");
    let asked = null;
    try {
        updateTechnical({ credential: "submitted", verification: "awaiting bridge verdict" });
        asked = await api(`/gate/${gate.gateId}/credential`, {
            method: "POST",
            body: JSON.stringify({
                gate_id: gate.gateId,
                challenge_nonce,
                session_commitment,
                substate_id: substateId,
                // camelCase from the wallet, snake_case on the wire.
                public_key: signed.publicKey || "",
                public_nonce: signed.publicNonce,
                signature: signed.signature,
            }),
        });
    } catch (e) {
        updateTechnical({ verification: "bridge unavailable", failure: "credential submission could not be verified" });
        await refreshTrace();
        showOutcome("denied", "BRIDGE UNREACHABLE",
            `The proof was signed but the bridge could not be reached to verify it. The challenge stays single-use and expires on its own; the signed output is untouched. ${e && e.message ? e.message : e}`);
        return;
    } finally {
        $("prove").disabled = false;
        $("resume-proof").disabled = false;
    }
    if (asked.ok && asked.body.state === "accepted") {
        advance("grant"); advance("session");
        const r = asked.body.receipt || {};
        // The bridge decides, the page reports: a session token in the response means ACCESS
        // GRANTED; its absence is reported as exactly that — a verified proof on a bridge
        // that issues no session. The two states must never be conflated.
        const hasSession = !!asked.body.access;
        updateTechnical({
            verification: "accepted · verified against chain evidence",
            session: hasSession ? "issued" : "not issued · bridge did not report an access session",
            replay: "single-use challenge consumed on verification",
            output: substateId,
            failure: null,
        });
        setOutputPresentation(substateId);
        const title = hasSession ? "ACCESS GRANTED" : "PROOF VERIFIED — SESSION NOT ISSUED";
        const sessionInfo = hasSession
            ? ` A verified session was issued for ${Math.round((asked.body.access.expiresUnix - Date.now() / 1000) / 86400)} day(s); afterwards, a fresh proof is required.`
            : " The proof was verified against chain state, but this bridge issues no session token (not registry-backed). No access was granted.";
        showOutcome(hasSession ? "granted" : "verified", title,
            (hasSession
                ? "Threshold verified on chain against an output you control. The output's public floor was checked, not your balance — the amount above the threshold was never disclosed."
                : "The proof was verified against chain state: the output exists, is unspent, and its floor meets the gate's threshold. However, this bridge does not issue authorization sessions (not registry-backed), so nothing was unlocked.") + sessionInfo,
            {
                "attested floor": `${formatAmount(r.attested_minimum, gate.divisibility)} ${gate.symbol || ""}`.trim(),
                // A missing threshold in the receipt means the backend did not report one —
                // say exactly that. Never substitute a success-looking value for absent
                // backend evidence: "null tTARI" was the old silent failure mode.
                "required": r.required_minimum == null
                    ? "unknown — the bridge did not report a threshold"
                    : `${formatAmount(r.required_minimum, gate.divisibility)} ${gate.symbol || ""}`.trim(),
                "output": substateId.slice(0, 18) + "…",
            });
        await refreshTrace();
        return;
    }
    const reason = asked.body.refused || asked.body.error || "the proof did not complete";
    const titles = {
        400: "MALFORMED REQUEST",
        403: "WRONG GATE SCOPE",
        409: "PROOF REFUSED",
        503: "BRIDGE NOT CONFIGURED",
    };
    const title = titles[asked.status] || (asked.status >= 500 ? "BRIDGE ERROR" : "ACCESS DENIED");
    const body = asked.status === 409
        ? "The required threshold was not proven. Your exact balance remains private."
        : "The proof was not accepted.";
    updateTechnical({ verification: `not accepted · HTTP ${asked.status}`, session: "not issued", failure: title.toLowerCase() });
    showOutcome("denied", title, body, { reason, status: asked.status });
    await refreshTrace();
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
    // Failures that occur before a bridge response (for example an unsupported mode or a wallet
    // refusal) still deserve a Technical-view explanation.  Use our fixed UI title only; raw
    // error text remains in the Simple outcome and never becomes protocol-inspector data.
    if (["denied", "error", "declined"].includes(kind)) {
        updateTechnical({ failure: title.toLowerCase() });
    }
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
    let response;
    try { response = await api(`/lab/trace?attempt=${state.attemptId}`); } catch { return; }
    const { ok, body } = response;
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
    if (!shown.length && state.events.length) {
        renderTerminalEmpty($("term-log"), "No events match the current filter.", false);
        return;
    }
    if (!shown.length) {
        // The honest empty state: the REAL event categories the inspector will show, ghosted.
        // Nothing here is a log — these are the labels and what each source means.
        renderTerminalEmpty($("term-log"), null, true);
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

/** The inspector's empty states. `categories` renders the REAL event categories the inspector will
 *  show once an attempt runs — ghosted, clearly labelled as categories, never as fabricated logs. */
function renderTerminalEmpty(log, filterMessage, categories) {
    log.innerHTML = "";
    const box = document.createElement("div");
    box.className = "terminal-empty";
    if (filterMessage) {
        const h = document.createElement("div");
        h.className = "headline";
        h.textContent = filterMessage;
        box.append(h);
    } else {
        const h = document.createElement("div");
        h.className = "headline";
        h.innerHTML = `No verification attempt yet.<span class="caret"></span>`;
        const hint = document.createElement("div");
        hint.textContent = "Choose a gate and press Prove access, or run the offline simulation to inspect a safe example trace.";
        box.append(h, hint);
    }
    if (categories) {
        const catsTitle = document.createElement("span");
        catsTitle.className = "cats-title";
        catsTitle.textContent = "EVENT CATEGORIES — labels, not logs:";
        const cats = document.createElement("div");
        cats.className = "cats";
        const rows = [
            ["bridge", "issues the single-use challenge, records the verdict"],
            ["wallet", "builds and signs the statement; its contents never cross the boundary"],
            ["consensus", "commits the transaction; the floor becomes public"],
            ["verifier", "compares floor ≥ threshold against the published policy"],
        ];
        for (const [src, note2] of rows) {
            const r = document.createElement("div");
            r.className = "cat";
            r.innerHTML = '<span class="src"></span><span class="note2"></span>';
            r.querySelector(".src").textContent = src;
            r.querySelector(".note2").textContent = note2;
            cats.append(r);
        }
        box.append(catsTitle, cats);
    }
    log.append(box);
}

function setModeBadge(sim) {
    const badge = $("mode-badge");
    badge.className = "mode-badge " + (sim ? "sim" : "live");
    $("mode-label").textContent = sim ? "offline simulation" : "live verification";
}

// ---------------------------------------------------------------- view switch
function setView(v) {
    const switched = switchTechnicalView(state.technical, v);
    state.view = switched.view;
    state.technical = switched.lifecycle;
    state.walletConnection = switchWalletView(state.walletConnection, v).connection;
    $("simple-view").hidden = v !== "simple";
    $("technical-view").hidden = v !== "technical";
    $("view-simple").setAttribute("aria-selected", String(v === "simple"));
    $("view-technical").setAttribute("aria-selected", String(v === "technical"));
    renderTechnicalFacts();
    renderTerminal();
    updateWalletPill();
    renderConnectIntro();
}

function updateWalletPill() {
    const k = document.getElementById("pill-walletd-k");
    if (!k) return;
    const hasCredentialGate = state.gates.some((g) => g.proofMode === "credential");
    const walletdUnconfigured = k.dataset.walletdConfigured === "false";
    if (walletdUnconfigured && hasCredentialGate && state.view === "simple") {
        k.textContent = "WALLET MODE";
        setPill("pill-walletd", "ok", "browser credential");
    } else if (walletdUnconfigured) {
        k.textContent = "WALLETD";
        // Hosted browser credentials do not use walletd. Keep the diagnostic available in
        // Technical view, but present its absence as neutral information rather than a fault.
        setPill("pill-walletd", "", "optional · not in use");
    }
}

// ---------------------------------------------------------------- status strip
// Honest states only: configuration is reported from /health (what this process was WIRED with),
// reachability is probed live (/wallet/status), and a mode that cannot activate is BLOCKED —
// never "unavailable for now", which would imply it might work later today.
const NETWORK_NAMES = { 0: "mainnet", 1: "stagenet", 2: "nextnet", 16: "localnet", 36: "igor", 38: "esmeralda" };
const networkName = (b) => NETWORK_NAMES[b] || `byte 0x${Number(b || 0).toString(16).padStart(2, "0")}`;

function setPill(id, cls, text) {
    const pill = $(id);
    if (!pill) return;
    pill.classList.remove("ok", "warn", "bad");
    if (cls) pill.classList.add(cls);
    const valueEl = pill.querySelector(".v");
    if (valueEl) valueEl.textContent = text;
    const keyEl = pill.querySelector(".k");
    if (keyEl) pill.title = `${keyEl.textContent}: ${text}`;
}

async function refreshStatus() {
    // Bridge + configuration flags: one cheap call, and the ONLY place that may say "healthy".
    const health = await api("/health").catch(() => null);
    if (health && health.ok) {
        const bridgeVersion = String(health.body.version || "").trim();
        // `version` may be a semantic version or a deployment label such as `edge-proxy`.
        // A separator is truthful for both and avoids the malformed `vedge-proxy` display.
        setPill("pill-bridge", "ok", bridgeVersion ? `healthy · ${bridgeVersion}` : "healthy");
        state.bridgeStatus = bridgeVersion ? `healthy · ${bridgeVersion}` : "healthy";
        setPill("pill-indexer", health.body.credential_configured ? "ok" : "", health.body.credential_configured ? "configured" : "not configured");
        // Chain sync is not asserted here: "configured" says what this process was wired with,
        // nothing more. The verifier refuses proofs it cannot verify against real chain state.
    } else {
        setPill("pill-bridge", "bad", "unreachable");
        state.bridgeStatus = "unreachable";
        setPill("pill-indexer", "", "unknown");
    }
    renderTechnicalFacts();

    // Walletd reachability: probed for real, and the network name comes from the WALLET when it
    // answers (the operator's configured cohort), falling back to the gates' registry byte.
    // Three honest states, never conflated: configured-and-answering, configured-but-failing
    // (a real service error — the route says 503), and not configured at all (the bridge runs in
    // offline demonstration mode, which is a configuration the operator chose).
    const ws = await api("/wallet/status").catch(() => null);
    const wk = document.getElementById("pill-walletd-k");
    if (ws && ws.ok && ws.body.configured === false) {
        if (wk) wk.dataset.walletdConfigured = "false";
        updateWalletPill();
        state.walletFailures++;
    } else if (ws && ws.ok && ws.body.reachable) {
        if (wk) { wk.textContent = "WALLETD"; wk.dataset.walletdConfigured = "true"; }
        setPill("pill-walletd", "ok", ws.body.has_default_account ? "reachable · account ready" : "reachable · no account");
        state.walletFailures = 0;
    } else {
        if (wk) { wk.textContent = "WALLETD"; delete wk.dataset.walletdConfigured; }
        setPill("pill-walletd", "bad", ws && ws.status === 503 ? "not reachable" : "unreachable");
        state.walletFailures++;
    }

    // Capabilities + network from the registry. Sorted by threshold ascending: the first gate a
    // judge sees should be the cheapest one, not an alphabetical accident of the registry's map.
    const { ok, body } = await api("/lab/gates").catch(() => ({ ok: false, body: {} }));
    const gates = (ok && body.gates) || [];
    gates.sort((a, b) => {
        const d = BigInt(a.thresholdRaw) < BigInt(b.thresholdRaw) ? -1 : BigInt(a.thresholdRaw) > BigInt(b.thresholdRaw) ? 1 : String(a.gateId).localeCompare(String(b.gateId));
        return d;
    });
    state.gates = gates;
    updateWalletPill();
    const modes = [];
    if (gates.some((g) => g.proofMode === "consensus")) modes.push("consensus");
    if (gates.some((g) => g.proofMode === "credential")) modes.push("credential");
    modes.push("XTM blocked");
    setPill("pill-modes", "", modes.join(" · "));
    setPill("pill-gates", gates.length ? "ok" : "warn", gates.length ? `${gates.length} configured` : "none");

    const netByte = gates[0] && gates[0].network !== undefined ? gates[0].network : null;
    const netName = (ws && ws.ok && ws.body.reachable && ws.body.network_name) || (netByte !== null ? networkName(netByte) : null);
    if (netName) setPill("pill-network", "ok", netName);
    else setPill("pill-network", "warn", "unknown");

    // Rebuild the picker only when the list actually changed: rebuilding on every refresh would
    // slam a dropdown shut under the operator's cursor.
    const sig = JSON.stringify(gates.map((g) => [g.gateId, g.thresholdRaw, g.useMode]));
    if (sig !== state.gateListSig) {
        state.gateListSig = sig;
        populateGateSelect();
    }
    const stillThere = state.gate && gates.some((g) => g.gateId === state.gate.gateId);
    if (!stillThere) {
        if (gates.length) selectGate(pickDefaultGate(gates));
        else if (state.gate) selectGate(null);
        else renderGateFacts(null);
    }
    loadTelegramScope();
    // This is a passive presence check only. It never calls a wallet method or asks for
    // permission; it merely releases a stale disabled button if an injected provider vanished.
    renderConnectIntro();
    return gates;
}

// ---------------------------------------------------------------- matrix edges
// A real digital rain: one small canvas per margin, drawn with requestAnimationFrame.
// Each frame lays a translucent wash over the strip — that wash is what fades the
// glyphs already on it into a trail — then drops the next glyph at each column's
// head, brighter than the trail behind it. Decorative only: no wallet data, no
// addresses, nothing that leaves this process. Paused when the tab is hidden and
// never started under prefers-reduced-motion.
function startMatrixEdges() {
    const host = document.getElementById("matrix-edges");
    if (!host) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    // Halfwidth katakana + latin hex-ish set: the classic rain look, Tari green.
    const glyphs = "01ｱｲｳｴｵｶｷｸｹｺｻｼｽｾﾀﾁﾂﾃﾄﾅﾆﾈﾊﾋﾎﾏﾐﾑﾒﾓﾗﾘﾙﾚﾛABCDEF0123456789";
    const SLOT = 14;          // px per glyph column — tighter for denser rain
    const FONT = "600 13px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
    const BG = "rgb(11, 15, 13)";        // --ink, matched to the page
    const HEAD = "rgb(196, 255, 220)";   // brighter than the trail
    const BODY = "rgb(41, 212, 124)";    // --green
    const PAD = 0;           // let the rain reach the edge of the content
    const MIN_STRIP = 32;    // show rain even on narrower screens
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    // The dashboard is #lab-root: max-width 1180, centered. The gutter is whatever is left of
    // that box, measured from its laid-out rect (correct under either box-sizing mode) on load
    // and on resize — not a hard-coded strip.
    const gutterWidth = () => {
        const w = window.innerWidth || document.documentElement.clientWidth;
        const root = document.getElementById("lab-root");
        const content = root ? root.getBoundingClientRect().width : 1180;
        return Math.max(0, Math.floor((w - content) / 2));
    };

    for (const side of ["left", "right"]) {
        const canvas = document.createElement("canvas");
        canvas.className = side;
        host.append(canvas);
        const ctx = canvas.getContext("2d", { alpha: false });
        let w = 0, h = 0, drops = [], raf = 0;

        const seedDrop = (slot, count, stagger) => ({
            slot,
            y: stagger === undefined ? -20 - Math.random() * (h || 600) : stagger,
            speed: 0.6 + Math.random() * 1.9,   // px/frame: visibly different speeds
            trail: 8 + Math.floor(Math.random() * 22), // glyphs kept in the streak
            next: 40 + Math.floor(Math.random() * 260), // frames until the next reset
        });

        const resize = () => {
            const g = gutterWidth();
            const strip = Math.max(0, g - PAD);
            canvas.style.display = strip < MIN_STRIP ? "none" : "block";
            w = strip;
            h = canvas.clientHeight || window.innerHeight || 600;
            canvas.width = Math.max(1, Math.round(w * dpr));
            canvas.height = Math.max(1, Math.round(h * dpr));
            canvas.style.width = w + "px";
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            ctx.fillStyle = BG;
            ctx.fillRect(0, 0, Math.max(1, w), h);
            const slots = Math.max(1, Math.floor(w / SLOT));
            // Scatter the drops across every slot and stagger them down the strip so the
            // columns never fall in lockstep: many independent streams, not one line.
            drops = Array.from({ length: slots }, (_, i) => seedDrop(i, slots, (h / slots) * i + Math.random() * 40));
        };

        const frame = () => {
            if (w > 0) {
                // The fade wash: previous glyphs dim rather than vanish, which is the trail.
                ctx.globalAlpha = 0.16;
                ctx.fillStyle = BG;
                ctx.fillRect(0, 0, w, h);
                ctx.globalAlpha = 1;
                ctx.font = FONT;
                ctx.textBaseline = "top";
                for (const d of drops) {
                    const x = d.slot * SLOT + 1;
                    // Trail body first, then the head on top so the head reads bright.
                    ctx.fillStyle = BODY;
                    ctx.globalAlpha = 0.85;
                    for (let t = 1; t <= d.trail; t++) {
                        const ty = d.y - t * 13;
                        if (ty < -13) break;
                        ctx.globalAlpha = 0.85 * (1 - t / (d.trail + 2));
                        ctx.fillText(glyphs[(Math.random() * glyphs.length) | 0], x, ty);
                    }
                    ctx.globalAlpha = 1;
                    ctx.fillStyle = HEAD;
                    ctx.fillText(glyphs[(Math.random() * glyphs.length) | 0], x, d.y);
                    d.y += d.speed;
                    if (d.y > h + 30 || --d.next <= 0) {
                        d.y = -20 - Math.random() * 60;
                        d.next = 40 + Math.random() * 260;
                        d.speed = 0.6 + Math.random() * 1.9;
                        d.trail = 8 + Math.floor(Math.random() * 22);
                    }
                }
            }
            raf = requestAnimationFrame(frame);
        };

        resize();
        window.addEventListener("resize", resize);
        raf = requestAnimationFrame(frame);

        // A hidden tab animates nobody: stop the loop, restart it on return.
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                if (raf) cancelAnimationFrame(raf);
                raf = 0;
            } else if (!raf) {
                raf = requestAnimationFrame(frame);
            }
        });
    }
}

/** Which gates an administrator has scoped for Telegram — stated before anyone clicks. A gate with
 *  no Telegram scope must never feel clickable: the card goes inactive and the button is disabled. */
function loadTelegramScope() {
    const card = $("telegram-card");
    const btn = $("tg-start");
    const note = $("tg-gate-note");
    const scoped = state.gates.filter((g) => g.useMode === "telegram" || g.useMode === "both");
    const currentScoped = state.gate && (state.gate.useMode === "telegram" || state.gate.useMode === "both");

    const setInactive = (why) => {
        card.classList.add("inactive");
        btn.disabled = true;
        btn.textContent = "Not configured for these gates";
        note.textContent = why;
    };
    const setActive = () => {
        card.classList.remove("inactive");
        btn.disabled = false;
        btn.textContent = "Open the Telegram verification";
    };

    if (!state.gates.length) {
        setInactive("No gate is configured yet. An administrator can scope a gate to Telegram in the dashboard.");
    } else if (!scoped.length) {
        setInactive(`Telegram access is not configured: none of the ${state.gates.length} configured gate(s) allow Telegram membership. The administrator can change this per gate in the dashboard.`);
    } else if (!currentScoped) {
        // state.gate is null between the gates list loading and a selection being made —
        // read the scoped gate names without dereferencing a gate that isn't selected yet.
        const names = scoped.map((g) => g.gateId).join(", ");
        if (!state.gate) {
            setInactive(`Telegram access is configured on ${names}. Select a gate to see whether it may be used.`);
        } else {
            setInactive(`This gate ("${state.gate.gateId}") authorizes the website only. Switch to ${names} or re-scope in the dashboard.`);
        }
    } else {
        setActive();
        note.textContent = `${scoped.map((g) => g.gateId).join(", ")} may be used for Telegram membership.`;
    }
}

const tgStart = $("tg-start");
if (tgStart) {
    tgStart.onclick = async () => {
        const gate = state.gate;
        if (!gate) return;
        if (gate.useMode === "website") {
            loadTelegramScope();
            return;
        }
        const note = $("tg-note");
        if (note) note.textContent = "Opening the verification page — the flow continues in the bot's window.";
        // A user must start at the bot: only it mints the account-bound, single-use join token.
        // /bot redirects to the configured official bot, or explains why Telegram is not yet
        // configured.  The public /claim route is intentionally not enough on its own.
        // Keep Telegram navigation outside an embedded Web Tari Universe dApp frame. The click
        // remains user-initiated so popup blockers and wallet permissions are not bypassed.
        window.open("/bot", "_blank", "noopener,noreferrer");
    };
}

// ---------------------------------------------------------------- wiring
// Every element is looked up defensively: a missing element degrades gracefully instead of
// throwing a TypeError that aborts the whole module (which used to leave the page dead and
// every DOM element unpopulated, including the gate selector).
const wire = (id, ev, handler) => { const el = $(id); if (el) el.addEventListener(ev, handler); };
wire("view-simple", "click", () => setView("simple"));
wire("view-technical", "click", () => setView("technical"));
wire("prove", "click", prove);
wire("resume-proof", "click", resumeProof);
wire("simulate", "click", simulate);
wire("term-filter", "input", renderTerminal);
wire("term-sev", "change", renderTerminal);
wire("term-pause", "click", (e) => {
    state.paused = !state.paused;
    e.target.textContent = state.paused ? "RESUME" : "PAUSE";
});
wire("term-copy", "click", async () => {
    await navigator.clipboard.writeText(renderExport());
    const el = $("term-copy");
    if (el) {
        el.textContent = "COPIED";
        setTimeout(() => (el.textContent = "COPY"), 1200);
    }
});
wire("term-export", "click", () => {
    const blob = new Blob([renderExport()], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `ghost-gate-trace-${state.attemptId || "simulation"}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
});
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
    // An explicit ?gate= wins over every default, once, on load.
    state.requestedGate = new URLSearchParams(location.search).get("gate");
    setView("simple");
    setModeBadge(false);
    $("prov-note").textContent = "Provenance: bridge = this process; wallet = the wallet's own answer; consensus = the network; verifier = checks this codebase performs. Events are recorded server-side and pass an allowlist before they reach this page.";
    renderSteps();
    renderTerminalEmpty($("term-log"), null, true);
    startMatrixEdges();
    $("connect-wallet").onclick = connectWallet;
    // The status strip is the first thing a judge reads; refresh it quietly so a walletd that
    // comes up (or dies) is reflected without a manual reload.
    await refreshStatus();
    await loadTelegramScope();
    const health = await api("/health").catch(() => ({ body: {} }));
    $("version-line").textContent = health.body.version ? ` bridge ${health.body.version}` : "";
    // Adaptive polling: 20s while the wallet answers, 60s after sustained unavailability. A
    // repeating 503 in the console was the symptom; the fix is the honest 200-plus-JSON the
    // bridge now answers for an unconfigured wallet, and this backoff covers the genuinely
    // failing case so the page never hammers a dependency that is not coming back.
    const NORMAL_POLL_MS = 20_000;
    const DEGRADED_POLL_MS = 60_000;
    const scheduleStatusPoll = () => {
        setTimeout(async () => {
            try { await refreshStatus(); } catch { /* offline stays offline */ }
            scheduleStatusPoll();
        }, state.walletFailures >= 3 ? DEGRADED_POLL_MS : NORMAL_POLL_MS);
    };
    scheduleStatusPoll();
})().catch((e) => {
    // A silent boot failure used to leave a dead page with a wall of console noise and no
    // honest signal to the operator. This surfaces the failure where it can be read.
    console.error("GHOST GATE: the Lab page failed to initialize:", e);
    const note = document.getElementById("prov-note");
    if (note) note.textContent = `Lab initialization failed: ${e && e.message ? e.message : e}. Reload the page or check the bridge.`;
});
