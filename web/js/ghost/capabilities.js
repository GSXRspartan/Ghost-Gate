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
  return {
    usable: false,
    reason:
      "This account supports none of Ghost Gate's proof modes. Missing: " +
      missing.join(", ") +
      ". A daemon-relayed account, for instance, cannot sign stealth outputs at all.",
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
