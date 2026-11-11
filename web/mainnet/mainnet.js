/**
 * GHOST GATE — MAINNET PREVIEW (client)
 *
 * Preview-only page. Mainnet admissions are NOT yet enabled. This page:
 *  - Displays accurate mainnet and wallet support status
 *  - Does NOT initiate any wallet connection or proof flow
 *  - Does NOT call the bridge admission API
 *  - Does NOT grant or imply access
 *
 * Network byte reference: Ootle mainnet = 0x00 (0), Esmeralda testnet = 0x26 (38).
 */

const MAINNET_NETWORK_BYTE = 0;    // Ootle mainnet (0x00)
const ESMERALDA_NETWORK_BYTE = 38; // Esmeralda testnet (0x26)

const $ = (id) => document.getElementById(id);

function detectSapient() {
    if (typeof window === "undefined") return "unknown";
    if (window.tari && window.tari.isTariWallet) return "detected";
    return "not-detected";
}

function detectUniverse() {
    if (typeof window === "undefined") return "unknown";
    // Web Tari Universe injects tari-dapp-bridge/1 into embedded contexts only.
    if (window.tari && window.tari.isEmbedded) return "embedded";
    return "not-detected";
}

async function checkBridgeNetwork() {
    // The bridge running locally may be testnet-configured.
    // Check its /health to surface the network mismatch explicitly.
    try {
        const r = await fetch("/health", {
            cache: "no-store",
            signal: AbortSignal.timeout(4000),
            headers: { accept: "application/json" },
        });
        if (!r.ok) return { ok: false, network: null };
        const body = await r.json();
        return { ok: true, service: body.service, network: body.network ?? null };
    } catch {
        return { ok: false, network: null };
    }
}

function setPill(id, stateClass, labelText) {
    const el = $(id);
    if (!el) return;
    el.className = `pill ${stateClass}`;
    const v = el.querySelector(".v");
    if (v) v.textContent = labelText;
}

async function init() {
    // Static wallet detection (non-interactive, no connection request)
    const sapient = detectSapient();
    const universe = detectUniverse();

    $("sapient-status").textContent =
        sapient === "detected" ? "extension detected" : "not detected in this browser";
    $("sapient-status").className =
        sapient === "detected" ? "wallet-facts v ok" : "wallet-facts v warn";

    $("universe-status").textContent =
        universe === "embedded" ? "embedded context" : "not in Tari Universe frame";
    $("universe-status").className = "wallet-facts v";

    // Bridge network check — only used to show honest network status, not for admission
    const bridge = await checkBridgeNetwork();
    if (bridge.ok) {
        const isMainnet = bridge.network === MAINNET_NETWORK_BYTE;
        const label = isMainnet ? "mainnet (0x00)" : `testnet detected (0x${(bridge.network ?? 0).toString(16).padStart(2, "0")})`;
        setPill("pill-bridge", isMainnet ? "ok" : "warn", isMainnet ? "mainnet" : "testnet-configured");
        $("bridge-network-note").textContent = bridge.ok
            ? `Bridge reached (${bridge.service ?? "ghost-gate-bridge"}). Network: ${label}.`
            : "Bridge not reachable.";
    } else {
        setPill("pill-bridge", "bad", "unreachable");
        $("bridge-network-note").textContent =
            "Bridge not reachable. A mainnet bridge endpoint has not yet been configured.";
    }

    // Always show ADMISSIONS = disabled (mainnet preview)
    setPill("pill-admissions", "warn", "disabled — preview");

    // Network pill is static
    setPill("pill-network", "gold", `mainnet (0x${MAINNET_NETWORK_BYTE.toString(16).padStart(2, "0")})`);
}

document.addEventListener("DOMContentLoaded", () => {
    init().catch(() => {
        setPill("pill-bridge", "bad", "error");
    });
});
