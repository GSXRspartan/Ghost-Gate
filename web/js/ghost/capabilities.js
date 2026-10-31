/**
 * Capability → Ghost Gate proof-mode mapping.
 *
 * Pure functions with no `window` and no network, so `node --test` can run them without a browser.
 * Everything here branches on capabilities, never on wallet identity — the integration contract's
 * "feature-detect, never wallet-detect" rule, applied to our own domain.
 *
 * Mode names are the two this project actually has, from docs/PROVIDER_COMPATIBILITY.md:
 *
 *   "consensus"  — Mode A. An MVP-bearing StealthTransferStatement reaches the gate's
 *                  prove_access inside the signed transaction, and consensus attests the floor.
 *                  Only the trusted-local walletd path can do this (see the doc's §2 for why no
 *                  browser provider can).
 *   "credential" — Mode B. A real on-chain output carrying minimumValuePromise, proven live by an
 *                  ownership signature over the site's challenge, verified by the bridge against
 *                  the output's on-chain key and unspent status.
 */

/**
 * The fields this project reads. Unknown fields are ignored, so a wallet adding capabilities is
 * not an error, and a wallet omitting them fails closed.
 *
 * @typedef {Object} ProviderCapabilities
 * @property {boolean} [privateSpend]              shield / unshield / sendPrivately
 * @property {boolean} [minimumValuePromise]       shield/sendPrivately can carry the promise
 * @property {boolean} [ownershipProof]            tari_signOwnershipChallenge
 * @property {boolean} [walletOwnershipProof]      tari_signWalletOwnershipChallenge
 * @property {boolean} [privateBalanceView]
 * @property {boolean} [privateViewGranted]
 * @property {boolean} [transactionRequests]       the create/get/submit trio
 * @property {boolean} [transactionResultLookup]
 * @property {boolean} [walletAddress]
 * @property {boolean} [dryRunIsLocal]
 */

/**
 * @typedef {Object} ProofModeInfo
 * @property {"consensus"|"credential"} mode
 * @property {string} label                 what the UI shows
 * @property {string} disclosure            the sentence a user must be able to read
 * @property {string[]} requires            capability names that gate this mode
 */

/** @type {Record<string, ProofModeInfo>} */
export const PROOF_MODES = {
  consensus: {
    mode: "consensus",
    label: "Consensus proof",
    disclosure:
      "Your wallet builds a proof transaction over the gate's own resource. The network itself " +
      "attests a public minimum; no output address and no balance is disclosed to the site.",
    requires: [],
  },
  credential: {
    mode: "credential",
    label: "Credential proof",
    disclosure:
      "Your wallet first creates a dedicated output that permanently and publicly commits to a " +
      "minimum value on chain, then signs the site's challenge over that output. The site learns " +
      "the output's identifier and that it is worth at least the threshold — and re-using the same " +
      "output for a later session links the two.",
    requires: ["privateSpend", "minimumValuePromise", "ownershipProof"],
  },
};

/**
 * Whether the browser-provider family can be offered for the selected gate.
 *
 * `window.tari` is an Ootle (L2) provider contract. It does not expose Minotari L1 output
 * ownership, authenticated inclusion, or current-UTXO-state evidence. Treating its Esmeralda
 * name as an L1 network assertion would let an L2 connection look like an XTM verification.
 * Keep this guard independent of wallet-reported capabilities: an unrecognised extension must
 * not be able to opt itself into native-L1 authorization merely by returning extra fields.
 *
 * @param {{ proof_kind?: string, proofKind?: string }|null} gate
 * @returns {{ ok: boolean, reason: string|null }}
 */
export function browserProviderGateCompatibility(gate) {
  const kind = gate?.proof_kind ?? gate?.proofKind;
  if (kind === "minotari_xtm" || kind === "xtm") {
    return {
      ok: false,
      reason:
        "This is a native Minotari L1 XTM gate. Tari Universe and Sapient expose the Tari Ootle " +
        "L2 window.tari contract, not a Minotari L1 output-ownership and live-UTXO proof API. " +
        "No wallet connection, challenge, or access session will be requested.",
    };
  }
  return { ok: true, reason: null };
}

/**
 * Parses the RFC-0154 *send intent* shape without opening it, connecting a wallet, or treating it
 * as a Ghost Gate proof. This is deliberately a diagnostic boundary: a send deep link can only
 * prefill a wallet's ordinary payment review; it cannot attest output ownership, value, or current
 * unspent state.
 *
 * Amounts stay strings because microTari values must not pass through JavaScript Number.
 * Address validity remains wallet-owned: the URI syntax carries a Base58 address, but only the
 * selected Minotari network and wallet can decide whether it is a usable recipient.
 *
 * @param {string} raw
 * @returns {{ ok: boolean, network?: string, address?: string, amountMicro?: string|null,
 *   note?: string|null, canAuthorizeGate: false, reason?: string }}
 */
export function inspectMinotariSendDeepLink(raw) {
  let url;
  try {
    url = new URL(String(raw));
  } catch {
    return { ok: false, canAuthorizeGate: false, reason: "Not a valid URI." };
  }
  if (url.protocol !== "tari:") {
    return { ok: false, canAuthorizeGate: false, reason: "A Minotari wallet URI must use the tari: scheme." };
  }
  if (!url.hostname || url.pathname !== "/transactions/send") {
    return {
      ok: false,
      canAuthorizeGate: false,
      reason: "Only the RFC-0154 /transactions/send intent is recognised here.",
    };
  }
  const address = url.searchParams.get("tariAddress");
  if (!address || /\s/.test(address)) {
    return { ok: false, canAuthorizeGate: false, reason: "The send intent has no usable tariAddress." };
  }
  const amountMicro = url.searchParams.get("amount");
  if (amountMicro !== null && !/^(0|[1-9]\d*)$/.test(amountMicro)) {
    return { ok: false, canAuthorizeGate: false, reason: "amount must be an unsigned integer in microTari." };
  }
  return {
    ok: true,
    network: url.hostname.toLowerCase(),
    address,
    amountMicro,
    note: url.searchParams.get("note"),
    canAuthorizeGate: false,
    reason: "This is a payment-review intent only; it is never Ghost Gate authorization evidence.",
  };
}

/**
 * Which proof modes a provider's capabilities support.
 *
 * Mode A is offered by the walletd adapter only, and deliberately not derived from any capability
 * flag a browser provider reports: the reason Mode A is absent for browsers is not a missing
 * capability bit but the soundness argument in PROVIDER_COMPATIBILITY.md §2. A browser wallet
 * reporting `minimumValuePromise: true` is reporting Mode B's primitive, nothing more.
 *
 * @param {ProviderCapabilities} caps
 * @param {{ canConsensusProof?: boolean }} [extra] adapter-supplied facts beyond the shared caps
 * @returns {ProofModeInfo[]}
 */
export function supportedProofModes(caps, extra = {}) {
  const capsOk = (names) => names.every((n) => caps[n] === true);
  const modes = [];
  if (extra.canConsensusProof === true) modes.push(PROOF_MODES.consensus);
  if (capsOk(PROOF_MODES.credential.requires)) modes.push(PROOF_MODES.credential);
  return modes;
}

/**
 * Whether the wallet can be used at all for Ghost Gate, and why not when it cannot.
 *
 * @param {ProviderCapabilities|null} caps null when the wallet answered nothing usable
 * @param {{ canConsensusProof?: boolean }} [extra]
 * @returns {{ usable: boolean, reason: string|null, modes: ProofModeInfo[] }}
 */
export function walletUsability(caps, extra = {}) {
  if (!caps) {
    return {
      usable: false,
      reason: "The wallet did not report capabilities, so nothing can be verified about what it supports.",
      modes: [],
    };
  }
  const modes = supportedProofModes(caps, extra);
  if (modes.length > 0) return { usable: true, reason: null, modes };
  const missing = PROOF_MODES.credential.requires.filter((n) => caps[n] !== true);
  // Say plainly when the wallet CAN move funds but cannot prove anything. Burn/bridge (transfer)
  // capability is not a proof capability: naming that explicitly stops a transfer-only wallet from
  // being mistaken for an unlock path. Ghost Gate never asks a wallet to burn anything.
  const canTransfer = caps.burnAndBridgeIncoming === true || caps.burnAndBridgeOutgoing === true;
  return {
    usable: false,
    reason:
      "This account supports none of Ghost Gate's proof modes. Missing: " +
      missing.join(", ") +
      ". A daemon-relayed account, for instance, cannot sign stealth outputs at all." +
      (canTransfer
        ? " This wallet can transfer or bridge funds, but transferring is not a proof: Ghost Gate " +
          "never requires a burn, and a transfer-only wallet cannot open a gate."
        : ""),
    modes,
  };
}

/**
 * Network check, deliberately byte-based.
 *
 * `tari_getNetwork` returns a network *name* whose casing and naming differ between wallets, and in
 * Tari Universe Web it returns the **Ootle** network even though the wallet's L1 side is on a
 * different chain. The gate binds to an Ootle network byte, so that byte is what must match.
 *
 * @param {string} reportedName
 * @param {Record<string, number>} nameToByte
 * @param {number} expectedByte
 * @returns {{ ok: boolean, byte: number|null }}
 */
export function networkMatches(reportedName, nameToByte, expectedByte) {
  const key = String(reportedName ?? "").trim().toLowerCase();
  const byte = Object.prototype.hasOwnProperty.call(nameToByte, key) ? nameToByte[key] : null;
  return { ok: byte !== null && byte === expectedByte, byte };
}

/**
 * The Ootle cohort table, transcribed from the pinned v0.42.0 source (`ootle_network::Network`).
 * The bridge's Rust side holds the same table (`ghost_gate_core::network`); this copy exists so the
 * browser can render a network verdict without a server round trip. A name missing from this table
 * maps to no byte, and a no-byte wallet can never satisfy a gate — fail closed.
 *
 * @type {Record<string, number>}
 */
export const NETWORK_NAME_TO_BYTE = {
  mainnet: 0x00,
  stagenet: 0x01,
  nextnet: 0x02,
  localnet: 0x10,
  igor: 0x24,
  esmeralda: 0x26,
};

/**
 * The verdict a visitor reads after connecting: which network the wallet reports, which byte that
 * name resolves to, and whether it matches the gate's byte.
 *
 * @param {string|null} reportedName the name from tari_getNetwork (null = wallet did not say)
 * @param {number} expectedByte the gate's bound Ootle byte
 * @returns {{ ok: boolean, reported: string|null, byte: number|null, expectedByte: number, verdict: string }}
 */
export function networkVerdict(reportedName, expectedByte) {
  const reported = reportedName === null || reportedName === undefined ? null : String(reportedName).trim();
  const { ok, byte } = networkMatches(reported, NETWORK_NAME_TO_BYTE, expectedByte);
  if (!reported) {
    return { ok: false, reported, byte, expectedByte,
      verdict: "The wallet did not report a network, so the gate cannot be attempted on it." };
  }
  const expectedName = Object.entries(NETWORK_NAME_TO_BYTE).find(([, b]) => b === expectedByte)?.[0] ?? `byte ${expectedByte}`;
  if (ok) {
    return { ok: true, reported, byte, expectedByte,
      verdict: `Wallet is on ${reported} — the gate's own network.` };
  }
  if (byte === null) {
    return { ok: false, reported, byte, expectedByte,
      verdict: `Wallet reports the network "${reported}", which is not a cohort this gate can bind to. Proofs on it would not be verifiable.` };
  }
  return { ok: false, reported, byte, expectedByte,
    verdict: `Network mismatch: the wallet is on ${reported} (byte ${byte}) but this gate is bound to ${expectedName} (byte ${expectedByte}). Connecting for diagnostics is fine; proving here is blocked by the gate, not by your wallet.` };
}

/**
 * One place that knows the provider error taxonomy, so every caller reports the same distinct
 * states instead of a generic failure. Codes follow the provider convention carried in
 * Tari dApp integration: 4001 rejected · 4100 not connected · 4200 unsupported · -32603 internal.
 * 4100 is an actionable authorization state — never evidence that the wallet lacks capabilities.
 *
 * @param {{ code?: number, message?: string }|string} e
 * @param {{ thresholdRaw?: string|number|bigint, divisibility?: string|number|bigint, symbol?: string }|null} [gate]
 * @returns {{ cls: "warn"|"bad", text: string }}
 */
export function describeProviderError(e, gate = null) {
  const code = e && typeof e === "object" ? e.code : undefined;
  const message = e && typeof e === "object" ? String(e.message || e) : String(e || "unknown error");
  if (code === 4001) {
    return { cls: "warn", text: "You declined the request in your wallet. Nothing was shared." };
  }
  if (code === 4100) {
    return { cls: "bad", text:
      "This site is not connected to your wallet yet. Connect or reconnect Sapient — unlock the " +
      "wallet, approve this site if it asks — then press Connect wallet again." };
  }
  if (code === 4200 || code === -32601) {
    return { cls: "bad", text: "This wallet does not support that call." };
  }
  if (code === -32603) {
    const insufficient = message.match(/InsufficientFunds.*?Required:\s*(\d+),\s*Available:\s*(\d+)/);
    if (insufficient) {
      const req = insufficient[1], avail = insufficient[2];
      const configured = gate && gate.thresholdRaw != null
        ? formatAmount(gate.thresholdRaw, gate.divisibility)
        : null;
      const label = configured
        ? `${configured} ${gate.symbol || "tokens"}`.trim()
        : `${req} raw units`;
      return { cls: "bad", text: `Insufficient revealed funds. Reveal at least ${label} in a qualifying output and try again. The wallet reported ${avail} available.` };
    }
    const execFail = message.match(/ExecutionFailure.*?message":"([^"]+)"/);
    if (execFail) {
      return { cls: "bad", text: `Wallet transaction failed: ${execFail[1]}` };
    }
    return { cls: "bad", text: `The wallet hit an internal error: ${message.length > 200 ? message.slice(0, 200) + "…" : message}` };
  }
  if (/lock/i.test(message)) {
    return { cls: "warn", text: "The wallet appears to be locked. Unlock Sapient, then press Connect wallet again." };
  }
  return { cls: "bad", text: `The wallet refused the request: ${message}` };
}

/**
 * Amounts are strings or bigints, never JS numbers (they exceed MAX_SAFE_INTEGER). Returns a BigInt
 * or null; null means "not a usable amount", which the caller must treat as an error rather than 0.
 *
 * @param {string|bigint|number} value
 * @returns {bigint|null}
 */
export function parseAmount(value) {
  if (typeof value === "bigint") return value;
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) return BigInt(value.trim());
  if (typeof value === "number" && Number.isInteger(value)) return BigInt(value);
  return null;
}

/** Formats a raw amount for display using the resource's own divisibility. Never assumes 6. */
export function formatAmount(raw, divisibility) {
  const v = parseAmount(raw);
  const d = parseAmount(divisibility);
  if (v === null || d === null || d < 0n) return null;
  const base = 10n ** d;
  const whole = v / base;
  const frac = (v % base).toString().padStart(Number(d), "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
}
