/**
 * GHOST GATE — MAINNET (client)
 *
 * Preview state. Mainnet admissions are not enabled, so this page deliberately:
 *   - requests no wallet connection and mints no challenge
 *   - calls no admission API
 *   - grants nothing and implies nothing
 *
 * It reports what is actually detectable (wallet presence, bridge reachability and
 * which network that bridge serves) and says "not published" everywhere a mainnet
 * dependency genuinely does not exist yet.
 *
 * Network bytes: Ootle mainnet 0x00, Esmeralda testnet 0x26.
 */

import { startMatrixEdges } from "/js/ghost/matrix-edges.js";

const MAINNET_NETWORK = 0x00;

const $ = (id) => document.getElementById(id);

function setPill(id, state, text) {
    const pill = $(id);
    if (!pill) return;
    pill.className = `pill${state ? ` ${state}` : ""}`;
    const value = pill.querySelector(".v");
    if (value) value.textContent = text;
}

/** Presence only. Reading `window.tari` triggers no prompt and requests no account. */
function describeSapient() {
    const tari = window.tari;
    if (tari && tari.isTariWallet && !tari.isEmbedded) return "detected in this browser";
    if (tari && tari.isEmbedded) return "a wallet frame is hosting this page";
    return "not detected";
}

function describeUniverse() {
    return window.tari && window.tari.isEmbedded
        ? "running inside a Tari Universe frame"
        : "not running inside Tari Universe";
}

/** The bridge this origin serves. A testnet bridge is reported as testnet, not as mainnet. */
async function bridgeStatus() {
    try {
        const response = await fetch("/health", {
            cache: "no-store",
            headers: { accept: "application/json" },
            signal: AbortSignal.timeout(4000),
        });
        if (!response.ok) return { reachable: false };
        const body = await response.json();
        return {
            reachable: true,
            gates: Array.isArray(body.gates) ? body.gates.length : 0,
            credential: Boolean(body.credential_configured),
        };
    } catch {
        return { reachable: false };
    }
}

async function init() {
    $("sapient-status").textContent = describeSapient();
    $("universe-status").textContent = describeUniverse();

    const bridge = await bridgeStatus();
    if (!bridge.reachable) {
        setPill("pill-bridge", "bad", "unreachable");
        setPill("pill-gates", "", "0 published");
    } else {
        // Reachable, but this origin's bridge is configured for the test network: no
        // mainnet bridge endpoint exists yet. Say that rather than implying mainnet.
        setPill("pill-bridge", "warn", "testnet-configured");
        setPill("pill-gates", "", `${bridge.gates} on testnet`);
    }

    // Static facts: these do not depend on anything reachable from this page.
    setPill("pill-network", "gold", `mainnet 0x${MAINNET_NETWORK.toString(16).padStart(2, "0")}`);
    setPill("pill-admissions", "warn", "disabled");

    $("version-line").textContent = "";
}

startMatrixEdges("lab-root");
init().catch(() => setPill("pill-bridge", "bad", "unavailable"));
