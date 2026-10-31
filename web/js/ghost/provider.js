/**
 * The wallet-facing interface Ghost Gate supports, and the three adapters.
 *
 * Every adapter — Sapient, Tari Universe, Local walletd — implements the same surface, so the
 * page's flow code is written once and branches only on the *result* of `probe()`
 * (capabilities), never on which wallet the user picked:
 *
 *   probe()                — discovery + capability read; the per-wallet mode list
 *   approveAndBuildProof() — the user-approval + proof-construction step
 *   signChallenge()        — prove control of a proof artifact (credential mode)
 *   lookup()               — committed-result lookup by transaction id
 *
 * What no adapter is allowed to do, checked in review rather than by the type system: ask for a
 * seed phrase, a private key, a balance beyond what a proof requires, or a UTXO inventory for the
 * site. `signChallenge` and `approveAndBuildProof` prompt in the wallet's own UI — the page never
 * sees key material and never suppresses a prompt. Nothing here requests `tari_requestViewAccess`:
 * the credential flow needs a *spend* approval, which is its own prompt, and a view grant would
 * expose the whole private position for no proof benefit.
 */

import { PROOF_MODES, networkMatches, walletUsability } from "./capabilities.js";

/**
 * @typedef {Object} ProbeResult
 * @property {string} id
 * @property {string} label
 * @property {boolean} available            can this adapter be used on this page at all
 * @property {string|null} unavailableReason
 * @property {import("./capabilities.js").ProviderCapabilities|null} capabilities
 * @property {import("./capabilities.js").ProofModeInfo[]} modes
 * @property {string|null} unusableReason   reachable, but this *account* supports no mode
 */

/** @typedef {{ approveAndBuildProof: Function, signChallenge: Function, lookup: Function, probe: Function, id: string, label: string, modes: import("./capabilities.js").ProofModeInfo[] }} WalletProvider */

function unavailable(id, label, reason) {
  return { id, label, available: false, unavailableReason: reason, capabilities: null, modes: [], unusableReason: null };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/* ---------------------------------------------------------------------------------- */
/* The two window.tari wallets (Sapient, Tari Universe)                                */
/* ---------------------------------------------------------------------------------- */

/**
 * Sapient and Tari Universe speak the same `window.tari` contract; only discovery differs, so the
 * per-wallet code is a `discover()` function and everything else is shared.
 *
 * @param {string} id
 * @param {string} label
 * @param {() => { provider: Object|null, reason: string|null }} discover
 * @returns {WalletProvider}
 */
export function windowTariProvider(id, label, discover) {
  // The gate resource the proof is for; the page sets it before the flow starts.
  let resource = null;

  function get() {
    const found = discover();
    if (!found.provider) throw new Error(found.reason || "the wallet is not reachable from this page");
    return found.provider;
  }

  return {
    id,
    label,
    // A browser wallet never offers Mode A. That is not a missing capability bit — it is the
    // soundness argument in PROVIDER_COMPATIBILITY.md §2 — so it is stated here rather than
    // derived from `tari_getCapabilities`, which would let a capable-looking wallet imply a proof
    // mode it cannot honour.
    modes: [PROOF_MODES.credential],
    async probe() {
      let found;
      try {
        found = discover();
      } catch (e) {
        return unavailable(id, label, String(e && e.message ? e.message : e));
      }
      if (!found.provider) {
        return unavailable(id, label, found.reason || "no Tari wallet answered on this page");
      }
      let caps = null;
      try {
        caps = await found.provider.request({ method: "tari_getCapabilities" });
      } catch (e) {
        if (e && e.code === 4100) {
          // The extension is present but this site is not authorized yet: the real Sapient
          // refuses capability reads before tari_requestAccounts (the mock ones answered
          // freely, which is exactly why 4100 only showed up in physical testing). The wallet
          // is AVAILABLE — it just needs the user's connect click. Never treat this as a
          // missing wallet or as a missing capability.
          return {
            id, label,
            available: true,
            unavailableReason: null,
            capabilities: null,
            modes: [],
            unusableReason: "the wallet is not connected to this site yet — press Connect wallet to authorize it",
          };
        }
        return {
          id, label,
          available: false,
          unavailableReason: `tari_getCapabilities failed (${e && e.code ? `code ${e.code}` : e})`,
          capabilities: null, modes: [], unusableReason: null,
        };
      }
      const usability = walletUsability(caps);
      return {
        id, label,
        available: true,
        unavailableReason: null,
        capabilities: caps,
        modes: usability.modes,
        unusableReason: usability.usable ? null : usability.reason,
      };
    },
    /**
     * Mode B, step by step, with the wallet's own prompts doing the approving.
     *
     * `tari_createTransactionRequest` over `tari_signAndSubmitTransaction` because the request
     * survives a page reload (the docs' own guidance) and because the approval stays attached to
     * an operation the wallet understands (`shield`), not to raw instructions it cannot interpret.
     */
    async approveAndBuildProof(mode, req) {
      const p = get();
      resource = req.resourceAddress;

      const { requestId } = await p.request({
        method: "tari_createTransactionRequest",
        params: {
          kind: "shield",
          resourceAddress: req.resourceAddress,
          // ≥ the gate threshold; any extra headroom is the user's choice, disclosed on the
          // wallet's own approval screen, which is where the "public and permanent" warning lives.
          amount: req.amount,
          minimumValuePromise: req.minimumValuePromise,
          maxFee: req.maxFee,
        },
      });

      // Poll until the wallet has an answer. Statuses: pending/approved/submitting/submitted/
      // rejected/failed; a rejected or failed request is a normal outcome, reported as one. The
      // loop is bounded (the second-pass audit caught the unbounded `for(;;)`, which let a hung
      // wallet extension pin the page at one request per second forever): ten minutes, then an
      // error that tells the user the request id so the wallet's own history still has it.
      let summary;
      const deadline = Date.now() + 10 * 60 * 1000;
      for (;;) {
        summary = await p.request({ method: "tari_getTransactionRequest", params: { requestId } });
        if (summary.status !== "pending" && summary.status !== "submitting") break;
        if (Date.now() > deadline) {
          throw new Error(
            `the wallet did not settle request ${requestId} within ten minutes; check the wallet's ` +
            "history before trying again",
          );
        }
        await sleep(1000);
      }
      if (summary.status !== "approved" && summary.status !== "submitted") {
        throw new Error(
          `the wallet ${summary.status} the proof transaction${summary.error ? `: ${summary.error}` : ""}`,
        );
      }

      const result = await p.request({ method: "tari_submitTransactionRequest", params: { requestId } });
      // Contract shape: { transactionId, commitment, substateId, minimumValuePromise }.
      if (!result || !result.substateId) {
        throw new Error("the wallet returned no substateId, so there is no proof artifact to verify");
      }
      return result;
    },
    /**
     * The ownership signature over the site's challenge. `resourceAddress` names the gate's
     * resource — the wallet re-derives the output's one-time key from it, and the bridge re-checks
     * everything against chain state.
     *
     * `resourceAddress` may be passed explicitly by the RESUME flow: signing over an output that
     * already exists on chain must not depend on a shield having been built in this page session
     * (the module-scoped `resource` is only set by `approveAndBuildProof`). An explicit resource
     * is still the caller's duty to get right — the bridge re-checks it against the gate anyway.
     */
    async signChallenge(substateId, challenge, resourceAddressOverride) {
      const p = get();
      const use = resourceAddressOverride || resource;
      if (!use) throw new Error("no proof has been built yet, so there is nothing to sign over");
      return p.request({
        method: "tari_signOwnershipChallenge",
        params: { resourceAddress: use, substateId, challenge },
      });
    },
    /**
     * Low-level passthrough for the Lab's connection-only ceremony: account/network reads,
     * capability discovery, and the read-only wallet-ownership signature. Nothing here moves
     * funds, and nothing it returns is a proof — the bridge always re-checks facts server-side.
     */
    async request(method, params) {
      return get().request({ method, params });
    },
    async lookup(transactionId) {
      return get().request({ method: "tari_getTransactionResult", params: { transactionId } });
    },
  };
}

/** Sapient injects into every page; if nothing answered, the honest answer is "not installed". */
export function sapientProvider() {
  return windowTariProvider("sapient", "Sapient", () => {
    const w = typeof window === "undefined" ? null : window;
    if (w && w.tari && w.tari.isTariWallet) return { provider: w.tari, reason: null };
    return {
      provider: null,
      reason:
        "No Tari wallet answered on this page. Install the Sapient extension, or open this dApp " +
        "inside Tari Universe at universe.tari.mw.",
    };
  });
}

/**
 * Tari Universe serves its provider only to dApps embedded in its own iframe (`isEmbedded`). In a
 * plain tab every call rejects by design, so the honest probe result says exactly that rather than
 * hanging or retrying.
 */
export function universeProvider() {
  return windowTariProvider("universe", "Tari Universe", () => {
    const w = typeof window === "undefined" ? null : window;
    const p = w && w.tari && w.tari.isTariWallet ? w.tari : null;
    if (!p) {
      return {
        provider: null,
        reason:
          "Not running inside Tari Universe. Open this dApp from its app catalogue at " +
          "universe.tari.mw; in a plain tab its provider is unreachable by design.",
      };
    }
    if (!p.isEmbedded) {
      return {
        provider: null,
        reason:
          "A Tari wallet is present but this page is not running inside it. Open this dApp from " +
          "Tari Universe's app catalogue instead of a browser tab.",
      };
    }
    return { provider: p, reason: null };
  });
}

/* ---------------------------------------------------------------------------------- */
/* Local walletd, through the bridge                                                   */
/* ---------------------------------------------------------------------------------- */

/**
 * The only adapter offering Mode A, because the trusted local bridge drives the user's own wallet
 * daemon — the property browser providers do not have. Credential mode is deliberately not offered
 * here: the walletd path builds statements directly and has no `shield`-style request kind, and
 * inventing one client-side would be exactly the forged-statement shape the compatibility doc
 * rules out.
 *
 * @param {string} bridgeBase e.g. "http://127.0.0.1:7799"
 * @returns {WalletProvider}
 */
export function walletdProvider(bridgeBase) {
  const base = String(bridgeBase || "").replace(/\/$/, "");
  async function api(method, path, body) {
    const res = await fetch(base + path, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error || `${method} ${path} -> ${res.status}`);
    return json;
  }
  return {
    id: "walletd",
    label: "Local walletd",
    modes: [PROOF_MODES.consensus],
    async probe() {
      try {
        const status = await api("GET", "/wallet/status");
        if (status.reachable !== true) {
          return unavailable("walletd", "Local walletd", status.error || "the local wallet daemon is not reachable");
        }
        // Capability-shaped so the UI's one renderer covers all three wallets. The `false`s are
        // the point: they keep the per-wallet mode list honest instead of implying this backend
        // could also do credential proofs.
        return {
          id: "walletd",
          label: "Local walletd",
          available: true,
          unavailableReason: null,
          capabilities: {
            privateSpend: false,
            minimumValuePromise: false,
            ownershipProof: false,
            transactionResultLookup: true,
            walletAddress: false,
          },
          modes: [PROOF_MODES.consensus],
          unusableReason: null,
        };
      } catch (e) {
        return unavailable("walletd", "Local walletd", String(e && e.message ? e.message : e));
      }
    },
    async approveAndBuildProof(_mode, req) {
      // The bridge's existing prove route: it holds the challenge book, binds the session, drives
      // walletd, and reports only the public receipt. `networkMatches` is checked by the bridge
      // itself; the page verifies nothing about the proof.
      const challenge = await api("POST", `/gate/${req.gateId}/challenge`, {});
      const proof = await api("POST", `/gate/${req.gateId}/prove`, {
        gate_id: req.gateId,
        challenge_nonce: challenge.challenge_nonce,
        session_commitment: challenge.session_commitment,
      });
      const status = await pollProofStatus(base, proof.proof_id);
      return { transactionId: status.transaction_id || "", result: status };
    },
    async signChallenge() {
      throw new Error("the walletd backend does not use ownership signatures; its proofs are consensus proofs");
    },
    async lookup(transactionId) {
      return api("GET", `/proof/${encodeURIComponent(transactionId)}/status`);
    },
  };
}

async function pollProofStatus(base, proofId, attempts = 30) {
  for (let i = 0; i < attempts; i++) {
    const res = await fetch(`${base}/proof/${encodeURIComponent(proofId)}/status`);
    const json = await res.json();
    if (json.state === "accepted" || json.state === "rejected" || json.state === "failed") return json;
    await sleep(1000);
  }
  throw new Error("timed out waiting for the proof to settle");
}
