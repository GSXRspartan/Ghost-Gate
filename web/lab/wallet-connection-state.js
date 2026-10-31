/* Local presentation state for the browser-wallet connect control.
 *
 * This records only whether this page received an account answer. It contains no address,
 * account list, signature, nonce, or permission capability, and it never reconnects a wallet.
 */

export function newWalletConnection() {
    return { connected: false, mode: null };
}

export function connectedWallet(mode) {
    return { connected: true, mode };
}

export function disconnectedWallet() {
    return newWalletConnection();
}

export function switchWalletView(connection, view) {
    // Display mode is presentation-only: it must not change browser-wallet authorization state.
    return { connection, view };
}

export function connectButtonState({ hasGate, mode, connecting, connection }) {
    const walletName = mode === "universe" ? "Tari Universe" : "Sapient";
    const connected = Boolean(connection && connection.connected && connection.mode === mode);
    if (!hasGate) return { hidden: true, disabled: true, label: "Connect wallet", title: "Select a gate first" };
    if (connecting) return { hidden: false, disabled: true, label: `Waiting for ${walletName}…`, title: "Waiting for wallet approval" };
    if (connected) return { hidden: false, disabled: true, label: "Wallet Connected", title: `${walletName} is connected for this page` };
    if (mode === "walletd") return { hidden: false, disabled: false, label: "Check wallet daemon", title: "Check local wallet daemon status" };
    return { hidden: false, disabled: false, label: "Connect wallet", title: `Connect ${walletName}` };
}
