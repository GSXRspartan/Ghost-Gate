/**
 * Type definitions for the Tari dApp provider (`window.tari`).
 *
 * The same interface is implemented by the Sapient browser extension and by the Tari Universe web
 * wallet. A dApp calls methods and feature-detects with `tari_getCapabilities`; it never detects
 * which wallet it has. Both wallets implement every method below.
 *
 * Docs: https://universe.tari.mw/integration
 */

export type TariMethod =
  | "tari_requestAccounts"
  | "tari_getAccounts"
  | "tari_getNetwork"
  | "tari_getWalletAddress"
  | "tari_getBalances"
  | "tari_getSubstate"
  | "tari_getCapabilities"
  | "tari_getTransactionResult"
  | "tari_signAndSubmitTransaction"
  | "tari_withdrawStealthAndExecute"
  | "tari_htlcFund"
  | "tari_createTransactionRequest"
  | "tari_getTransactionRequest"
  | "tari_submitTransactionRequest"
  | "tari_requestViewAccess"
  | "tari_getViewAccess"
  | "tari_revokeViewAccess"
  | "tari_getPrivateBalances"
  | "tari_getShieldedOutputs"
  | "tari_scanForPrivatePayments"
  | "tari_scanForResourceUtxos"
  | "tari_claimPrivatePayment"
  | "tari_signOwnershipChallenge"
  | "tari_signWalletOwnershipChallenge"
  | "tari_disconnect";

/** Raw units. Divide by `10 ** divisibility` to display — never assume 6. */
export interface TariTokenBalance {
  resourceAddress: string;
  kind: "Fungible" | "NonFungible" | "Confidential" | "Stealth";
  symbol: string | null;
  name: string | null;
  divisibility: number;
  /** The revealed (publicly spendable) balance. */
  amount: string | bigint;
  /** The stealth/confidential balance. "0" when the site lacks view access, not necessarily empty. */
  confidentialAmount: string | bigint;
}

/** Feature detection. Branch on these, never on wallet identity. */
export interface TariWalletCapabilities {
  exactInputSelection: boolean;
  stealthWithdraw: boolean;
  stealthRedeem: boolean;
  stealthRedeemPrivateFee: boolean;
  htlcFund: boolean;
  scriptPathSpend: boolean;
  /** shield / unshield / sendPrivately via tari_createTransactionRequest. */
  privateSpend: boolean;
  /** Whether shield/sendPrivately's minimumValuePromise (proof-of-funds) is available. */
  minimumValuePromise: boolean;
  /** Whether tari_signOwnershipChallenge is available. */
  ownershipProof: boolean;
  /** Whether tari_signWalletOwnershipChallenge is available. */
  walletOwnershipProof: boolean;
  /** Whether this account can serve confidential reads at all. */
  privateBalanceView: boolean;
  /** Whether *this site* currently holds a view-access grant. */
  privateViewGranted: boolean;
  transactionResultLookup: boolean;
  transactionRequests: boolean;
  walletAddress: boolean;
  dryRunIsLocal: boolean;
}

export interface TariSignAndSubmitParams {
  instructions: unknown[];
  /** Raw units, as a string. Defaults to the wallet's own limit when omitted. */
  maxFee?: string;
  /** Substates to pin. Optional — the wallet resolves what it needs. */
  inputs?: Array<{ substate_id: string; version: number | null }>;
  /** Simulate only. Never prompts, spends nothing — use for quotes. */
  dryRun?: boolean;
}

/**
 * What to pass to `tari_createTransactionRequest`. The `shield`/`sendPrivately`/`withdrawStealth-
 * AndExecute`/`redeemStealthOutputAndExecute`/`htlcFund`/`htlcClaim`/`htlcRefund` kinds cannot be
 * replicated as a raw `instructions` call — they need a balance proof and per-input authorizations
 * only the wallet's signer can make.
 */
export type TariTransactionRequestOperation =
  | { kind: "instructions"; instructions: unknown[]; maxFee?: string; inputs?: Array<{ substate_id: string; version: number | null }> }
  | {
      kind: "withdrawStealthAndExecute";
      resourceAddress: string;
      amount: string;
      workspaceVarName: string;
      followUpInstructions: unknown[];
      relatedComponents?: string[];
      maxFee?: string;
    }
  | {
      /** Spends one specific, externally-known stealth commitment (e.g. a ballot/ticket token
       * minted directly to this wallet by another party) into your own follow-up contract call —
       * see the "Moving stealth value into your own contract call" section of the docs. */
      kind: "redeemStealthOutputAndExecute";
      resourceAddress: string;
      commitmentHex: string;
      /** The output's actual value — there's no client-side way to discover it other than
       * decrypting the output yourself first; a wrong value fails the balance proof. */
      revealedAmount: string;
      followUpInstructions: unknown[];
      relatedComponents?: string[];
      maxFee?: string;
    }
  | {
      /** Identical to `redeemStealthOutputAndExecute`, except the fee is ALSO paid from a
       * stealth UTXO instead of this wallet's revealed balance — required whenever
       * `followUpInstructions` carries something that would deanonymize the wallet if the fee
       * input did (a voting ballot's ranking, say). See "Paying the fee privately too". */
      kind: "redeemStealthOutputWithPrivateFee";
      resourceAddress: string;
      commitmentHex: string;
      revealedAmount: string;
      followUpInstructions: unknown[];
      /** The fee-currency resource (almost always XTR/TARI). */
      feeResourceAddress: string;
      /** A stealth UTXO of `feeResourceAddress` this wallet owns, worth more than `maxFee`. */
      feeCommitmentHex: string;
      /** Revealed publicly as part of this transaction — bucket-paid fees are non-refundable,
       * so pick a flat value comfortably above the real cost rather than an exact one. */
      maxFee: string;
      relatedComponents?: string[];
    }
  | {
      kind: "htlcFund";
      resourceAddress: string;
      amount: string;
      claimantWalletAddress: string;
      hashLockHex: string;
      refundEpoch: string;
      maxFee?: string;
    }
  | {
      kind: "shield";
      resourceAddress: string;
      amount: string;
      maxFee?: string;
      memo?: string;
      /** Proof of funds: publicly commits this output is worth at least this much (raw units). */
      minimumValuePromise?: string;
    }
  | { kind: "unshield"; resourceAddress: string; revealedAmount: string; maxFee?: string; memo?: string }
  | {
      kind: "sendPrivately";
      resourceAddress: string;
      recipientWalletAddress: string;
      amount: string;
      maxFee?: string;
      memo?: string;
      /** Applies to the recipient's output only, never your own change. */
      minimumValuePromise?: string;
    }
  | {
      kind: "htlcClaim";
      resourceAddress: string;
      commitment: string;
      conditions: object[];
      preimageHex: string;
      maxFee?: string;
    }
  | {
      kind: "htlcRefund";
      resourceAddress: string;
      commitment: string;
      conditions: object[];
      amount: string;
      outputMask: string;
      maxFee?: string;
    };

export interface TariTransactionRequestSummary {
  requestId: string;
  status: "pending" | "approved" | "submitting" | "submitted" | "rejected" | "failed";
  note: string;
  createdAt: number;
  expiresAt: number;
  result?: unknown;
  error?: string;
}

export interface TariPrivateBalance {
  resourceAddress: string;
  amount: string;
  outputCount: number;
  divisibility: number;
  symbol: string | null;
  name: string | null;
}

export interface TariShieldedOutputSummary {
  resourceAddress: string;
  commitment: string;
  amount: string;
  transactionId: string;
  createdAt: number;
  memo?: string;
}

/**
 * `publicKey` is the output's one-time spend key (hex). Verify against the substate's own on-chain
 * `auth.Key` (from `tari_getSubstate`) — never against this field taken at face value, since anyone
 * can self-report any key. `publicNonce`/`signature` are the Schnorr signature (hex) over a
 * domain-tagged message the wallet builds itself, disjoint from real transaction signing — it can
 * never be replayed as spend authorization.
 */
export interface TariOwnershipProof {
  publicKey: string;
  publicNonce: string;
  signature: string;
}

/**
 * `walletAddress` is echoed for convenience. Verify against the owner key decoded from the
 * address *you* already have in mind (`parseOotleAddress`) — never against this field at face
 * value, for the same self-reporting reason as `TariOwnershipProof.publicKey`.
 */
export interface TariWalletOwnershipProof {
  walletAddress: string;
  publicNonce: string;
  signature: string;
}

/** 4001 rejected · 4100 not connected · 4200 unsupported · -32603 internal. */
export interface TariProviderError extends Error {
  code?: number;
}

export interface TariProvider {
  isTariWallet: true;
  /** Only on the embedded (iframe) provider: true when running inside a wallet. */
  isEmbedded?: boolean;

  request(args: { method: "tari_requestAccounts" }): Promise<string[]>;
  request(args: { method: "tari_getAccounts" }): Promise<string[]>;
  request(args: { method: "tari_getNetwork" }): Promise<string>;
  request(args: { method: "tari_getWalletAddress" }): Promise<string>;
  request(args: { method: "tari_getBalances" }): Promise<TariTokenBalance[]>;
  request(args: { method: "tari_getCapabilities" }): Promise<TariWalletCapabilities>;
  request(args: { method: "tari_getSubstate"; params: { substateId: string; version?: number | null } }): Promise<unknown>;
  request(args: { method: "tari_getTransactionResult"; params: { transactionId: string } }): Promise<unknown>;
  request(args: { method: "tari_signAndSubmitTransaction"; params: TariSignAndSubmitParams }): Promise<unknown>;
  request(args: { method: "tari_createTransactionRequest"; params: TariTransactionRequestOperation }): Promise<{ requestId: string }>;
  request(args: { method: "tari_getTransactionRequest"; params: { requestId: string } }): Promise<TariTransactionRequestSummary>;
  request(args: { method: "tari_submitTransactionRequest"; params: { requestId: string } }): Promise<unknown>;
  request(args: { method: "tari_requestViewAccess" }): Promise<{ granted: boolean }>;
  request(args: { method: "tari_getViewAccess" }): Promise<{ granted: boolean }>;
  request(args: { method: "tari_revokeViewAccess" }): Promise<null>;
  request(args: { method: "tari_getPrivateBalances" }): Promise<TariPrivateBalance[]>;
  request(args: { method: "tari_getShieldedOutputs"; params?: { resourceAddress?: string } }): Promise<TariShieldedOutputSummary[]>;
  request(args: { method: "tari_scanForPrivatePayments"; params?: { maxPages?: number } }): Promise<{ claimed: number; found: TariShieldedOutputSummary[] }>;
  /** Like `tari_scanForPrivatePayments`, but for one `resourceAddress` and not limited to outputs
   * from a native `StealthTransfer` instruction -- also finds a UTXO minted by custom template
   * logic inside a `CallFunction`/`CallMethod` (a voting template's ballot tokens, for instance).
   * More expensive per page (fetches each candidate transaction's full result), so keep
   * `maxPages`/`pageSize` small. Pass `limit` when the resource is known to mint at most that many
   * outputs per account (a ballot: exactly one) to stop the walk as soon as it's satisfied -- and
   * check `tari_getShieldedOutputs` first: an output the wallet already knows about needs no scan
   * at all. */
  request(args: {
    method: "tari_scanForResourceUtxos";
    params: { resourceAddress: string; maxPages?: number; pageSize?: number; limit?: number };
  }): Promise<{ claimed: number; found: TariShieldedOutputSummary[] }>;
  request(args: { method: "tari_claimPrivatePayment"; params: { resourceAddress: string; commitment: string } }): Promise<{ amount: string; memo?: string }>;
  request(args: { method: "tari_signOwnershipChallenge"; params: { resourceAddress: string; substateId: string; challenge: string } }): Promise<TariOwnershipProof>;
  request(args: { method: "tari_signWalletOwnershipChallenge"; params: { challenge: string } }): Promise<TariWalletOwnershipProof>;
  request(args: { method: "tari_disconnect" }): Promise<null>;
  request(args: { method: TariMethod; params?: unknown }): Promise<unknown>;

  on?(event: "accountsChanged", handler: (accounts: string[]) => void): () => void;
}

declare global {
  interface Window {
    /** May be undefined until `tari#initialized` fires. */
    tari?: TariProvider;
    /** The embedding wallet's provider specifically, when running inside one. */
    tariUniverse?: TariProvider;
    /** Every provider that announced itself on this page. */
    tariProviders?: TariProvider[];
  }
  interface WindowEventMap {
    "tari#initialized": Event;
  }
}

export {};
