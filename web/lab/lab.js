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
import { supportedProofModes, walletUsability, parseAmount, formatAmount, networkVerdict } from "/js/ghost/capabilities.js";

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
    gateListSig: null,   // signature of the last-rendered gate list (avoid rebuilding an open dropdown)
    walletFailures: 0,   // consecutive polls where the wallet was absent or unreachable
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
    sel.onchange = () => selectGate(sel.value);
}

function selectGate(gateId) {
    state.gate = state.gates.find((g) => g.gateId === gateId) || null;
    state.step = -1;
    renderGateFacts(state.gate);
    renderWallets();
    renderSteps();
    $("outcome").hidden = true;
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
    // The consensus path needs a wallet daemon; the bridge knows whether one is there.
    if (gate.proofMode === "consensus") {
        options.push({ id: "walletd", label: "Wallet daemon · consensus (advanced)" });
    }
    options.push({ id: "sapient", label: "Sapient — Ootle L2 · credential" });
    options.push({ id: "universe", label: "Tari Universe — in-app · credential" });

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
    } else {
        note.classList.add("bad");
        note.textContent = `This wallet cannot prove this gate: ${usable.reason || "unsupported"}`;
    }
    renderConnectIntro();
}

// ---------------------------------------------------- connection-only ceremony
// "Connect wallet" reads identity facts and nothing more: an address, the wallet's own network
// name, the capability flags, and — only when the wallet offers it — a read-only signature over
// a locally-generated nonce that proves the person holds the wallet. It deliberately does not
// mint a bridge challenge, does not build a proof, and never authorizes a spend: per the
// integration contract, a connection can never grant access by itself.
async function connectWallet() {
    const btn = $("connect-wallet");
    const detail = $("wallet-detail");
    const setRow = (id, cls, text) => {
        const row = $(id).closest(".wd-row");
        row.classList.remove("ok", "warn", "bad");
        if (cls) row.classList.add(cls);
        $(id).textContent = text;
    };
    detail.hidden = false;
    $("wd-caps-row").hidden = true;
    $("wd-ownership-row").hidden = true;
    setRow("wd-status", null, "Connecting…");
    $("wd-address").textContent = "—";
    $("wd-network").textContent = "—";
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = "Connecting…";
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
            await new Promise((resolve) => {
                let settled = false;
                const done = () => { if (!settled) { settled = true; window.removeEventListener("tari#initialized", done); resolve(); } };
                window.addEventListener("tari#initialized", done);
                setTimeout(done, 1500);
            });
        }
        const provider = state.mode === "universe" ? universeProvider() : sapientProvider();
        const probe = await provider.probe();
        if (!probe.available) {
            setRow("wd-status", "bad", probe.unavailableReason || "No Tari wallet answered on this page.");
            return;
        }
        const caps = probe.capabilities || {};

        // 1) Accounts — the wallet's own approval prompt. Read-only: it shares the public
        //    address and grants no spend authority.
        let accounts;
        try {
            accounts = await provider.request("tari_requestAccounts");
        } catch (e) {
            if (e && e.code === 4001) {
                setRow("wd-status", "warn", "You declined the connection request. Nothing was shared.");
            } else {
                setRow("wd-status", "bad", `The wallet refused the account request: ${e && e.message ? e.message : e}`);
            }
            return;
        }
        const address = Array.isArray(accounts) && accounts.length ? accounts[0] : null;
        if (!address) {
            setRow("wd-status", "bad", "The wallet returned no account address, so there is nothing to connect to.");
            return;
        }
        $("wd-address").textContent = `${address.slice(0, 24)}…${address.slice(-10)} (${address.length} chars)`;
        setRow("wd-status", "ok", `${provider.label} connected.`);

        // 2) Network — compare the wallet's own report against the gate's Ootle byte.
        let netName = null;
        try { netName = await provider.request("tari_getNetwork"); } catch { /* optional */ }
        const gate = state.gate;
        if (gate) {
            const v = networkVerdict(netName, gate.network);
            setRow("wd-network", v.ok ? "ok" : "warn", v.verdict);
        } else {
            $("wd-network").textContent = netName ? `${netName} (no gate selected, so no verdict)` : "the wallet did not report a network";
        }

        // 3) Capabilities — the flags that decide which proof modes this account can offer.
        const capNames = Object.entries(caps).filter(([, v]) => v === true).map(([k]) => k);
        $("wd-caps-row").hidden = false;
        $("wd-caps").textContent = capNames.length
            ? capNames.join(", ")
            : "the wallet reported no capabilities this gate can use";
        if (!probe.modes.length) {
            setRow("wd-status", "warn", `Connected, but this account supports none of Ghost Gate's proof modes.`);
        }

        // 4) Wallet-ownership signature — only when the wallet offers it, and only over a nonce
        //    this page generated. It proves the person holds the wallet, not that the wallet
        //    holds any asset, and it is never an eligibility proof.
        if (caps.walletOwnershipProof === true) {
            const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)),
                (b) => b.toString(16).padStart(2, "0")).join("");
            try {
                const proof = await provider.request("tari_signWalletOwnershipChallenge", { challenge: nonce });
                $("wd-ownership-row").hidden = false;
                $("wd-ownership").textContent = proof && proof.signature
                    ? `signed over nonce ${nonce.slice(0, 12)}… (signature ${proof.signature.slice(0, 14)}…) — proof of wallet possession only`
                    : "the wallet returned no signature";
            } catch (e) {
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
        btn.disabled = false;
        btn.textContent = label;
    }
}

/** One line under the connect button, refreshed whenever the mode changes. */
function renderConnectIntro() {
    const el = $("connect-wallet");
    if (!el) return;
    el.hidden = !state.gate;
    el.textContent = state.mode === "walletd" ? "Check wallet daemon" : "Connect wallet";
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

    // 2. Two proof paths, dispatched on the wallet the visitor chose — never on a guess.
    //    walletd  → the consensus path: the bridge drives the local daemon (Mode A).
    //    Sapient / Universe → the credential path: the wallet shields an output carrying the
    //    gate's threshold as its PUBLIC minimum-value promise, then signs this attempt's
    //    challenge over that one output; the bridge verifies both against chain state (Mode B).
    //    The credential route is the Telegram membership flow, so it is offered only on gates
    //    the administrator scoped to Telegram.
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
    const scoped = gate.useMode === "telegram" || gate.useMode === "both";
    if (!scoped) {
        $("prove").disabled = false;
        showOutcome("denied", "WRONG GATE SCOPE",
            `This gate authorizes the website only. The credential proof mode is the Telegram membership flow; pick a Telegram-scoped gate or use the wallet daemon path.`);
        return;
    }
    const provider = state.mode === "universe" ? universeProvider() : sapientProvider();
    // Shield exactly the threshold: the promise is the floor, and the user's headroom above
    // it is the user's choice, disclosed on the wallet's approval screen.
    const threshold = String(gate.thresholdRaw);
    let built;
    try {
        built = await provider.approveAndBuildProof("credential", {
            gateId: gate.gateId,
            resourceAddress: gate.resourceAddress,
            amount: threshold,
            minimumValuePromise: threshold,
            maxFee: "50000",
        });
    } catch (e) {
        $("prove").disabled = false;
        showOutcome("denied", "WALLET REFUSED", String(e && e.message ? e.message : e));
        return;
    }
    if (!built || !built.substateId) {
        $("prove").disabled = false;
        showOutcome("denied", "NO PROOF ARTIFACT", "The wallet produced no output to verify; there is nothing to check against chain state.");
        return;
    }
    // The ownership signature over THIS bridge's challenge. The wallet re-derives the
    // output's one-time key from the gate's resource; the bridge re-checks everything.
    let signed;
    try {
        signed = await provider.signChallenge(built.substateId, challenge_nonce);
    } catch (e) {
        $("prove").disabled = false;
        showOutcome("denied", "SIGNATURE REFUSED", String(e && e.message ? e.message : e));
        return;
    }
    advance("consensus"); advance("verify");
    const asked = await api(`/gate/${gate.gateId}/credential`, {
        method: "POST",
        body: JSON.stringify({
            gate_id: gate.gateId,
            challenge_nonce,
            session_commitment,
            substate_id: built.substateId,
            // camelCase from the wallet, snake_case on the wire.
            public_key: signed.publicKey || "",
            public_nonce: signed.publicNonce,
            signature: signed.signature,
        }),
    });
    $("prove").disabled = false;
    if (asked.ok && asked.body.state === "accepted") {
        advance("grant"); advance("session");
        const r = asked.body.receipt || {};
        const sessionInfo = asked.body.access
            ? ` A verified session was issued for ${Math.round((asked.body.access.expiresUnix - Date.now() / 1000) / 86400)} day(s); afterwards, a fresh proof is required.`
            : "";
        showOutcome("granted", "ACCESS GRANTED",
            "Threshold proven on chain against a real output you own. The output's own public floor was checked, not your balance — the amount above the floor was never disclosed." + sessionInfo,
            {
                "attested floor": `${formatAmount(r.attested_minimum, gate.divisibility)} ${gate.symbol || ""}`.trim(),
                "required": `${formatAmount(r.required_minimum, gate.divisibility)} ${gate.symbol || ""}`.trim(),
                "output": built.substateId.slice(0, 18) + "…",
            });
    } else {
        showOutcome("denied", "ACCESS DENIED",
            "The required threshold was not proven. Your exact balance remains private.",
            { reason: asked.body.refused || asked.body.error || "the proof did not complete" });
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
    state.view = v;
    $("simple-view").hidden = v !== "simple";
    $("technical-view").hidden = v !== "technical";
    $("view-simple").setAttribute("aria-selected", String(v === "simple"));
    $("view-technical").setAttribute("aria-selected", String(v === "technical"));
}

// ---------------------------------------------------------------- status strip
// Honest states only: configuration is reported from /health (what this process was WIRED with),
// reachability is probed live (/wallet/status), and a mode that cannot activate is BLOCKED —
// never "unavailable for now", which would imply it might work later today.
const NETWORK_NAMES = { 0: "mainnet", 1: "stagenet", 2: "nextnet", 16: "localnet", 36: "igor", 38: "esmeralda" };
const networkName = (b) => NETWORK_NAMES[b] || `byte 0x${Number(b || 0).toString(16).padStart(2, "0")}`;

function setPill(id, cls, text) {
    const pill = $(id);
    pill.classList.remove("ok", "warn", "bad");
    if (cls) pill.classList.add(cls);
    pill.querySelector(".v").textContent = text;
    pill.title = `${pill.querySelector(".k").textContent}: ${text}`;
}

async function refreshStatus() {
    // Bridge + configuration flags: one cheap call, and the ONLY place that may say "healthy".
    const health = await api("/health").catch(() => null);
    if (health && health.ok) {
        setPill("pill-bridge", "ok", `healthy v${health.body.version || "?"}`);
        setPill("pill-indexer", health.body.credential_configured ? "ok" : "", health.body.credential_configured ? "configured" : "not configured");
        // Chain sync is not asserted here: "configured" says what this process was wired with,
        // nothing more. The verifier refuses proofs it cannot verify against real chain state.
    } else {
        setPill("pill-bridge", "bad", "unreachable");
        setPill("pill-indexer", "", "unknown");
    }

    // Walletd reachability: probed for real, and the network name comes from the WALLET when it
    // answers (the operator's configured cohort), falling back to the gates' registry byte.
    // Three honest states, never conflated: configured-and-answering, configured-but-failing
    // (a real service error — the route says 503), and not configured at all (the bridge runs in
    // offline demonstration mode, which is a configuration the operator chose).
    const ws = await api("/wallet/status").catch(() => null);
    if (ws && ws.ok && ws.body.configured === false) {
        setPill("pill-walletd", "warn", "not configured (offline demo)");
        state.walletFailures++;
    } else if (ws && ws.ok && ws.body.reachable) {
        setPill("pill-walletd", "ok", ws.body.has_default_account ? "reachable · account ready" : "reachable · no account");
        state.walletFailures = 0;
    } else {
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
        if (gates.length) selectGate(gates[0].gateId);
        else if (state.gate) selectGate(null);
        else renderGateFacts(null);
    }
    loadTelegramScope();
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
    const SLOT = 16;          // px per glyph column
    const FONT = "600 13px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
    const BG = "rgb(11, 15, 13)";        // --ink, matched to the page
    const HEAD = "rgb(196, 255, 220)";   // brighter than the trail
    const BODY = "rgb(41, 212, 124)";    // --green
    const PAD = 10;          // keep the rain clear of the dashboard's own padding
    const MIN_STRIP = 64;    // below this (narrow laptops) the gutter is too thin to bother
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
        setInactive(`This gate ("${state.gate.gateId}") authorizes the website only. Switch to ${scoped.map((g) => g.gateId).join(", ")} or re-scope in the dashboard.`);
    } else {
        setActive();
        note.textContent = `${scoped.map((g) => g.gateId).join(", ")} may be used for Telegram membership.`;
    }
}

$("tg-start").onclick = async () => {
    const gate = state.gate;
    if (!gate) return;
    if (gate.useMode === "website") {
        loadTelegramScope();
        return;
    }
    $("tg-note").textContent = "Opening the verification page — the flow continues in the bot's window.";
    // The real flow lives at /telegram/join; the button that proves it is there.
    window.location.href = `/telegram/join?gate=${encodeURIComponent(gate.gateId)}`;
};

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
})();