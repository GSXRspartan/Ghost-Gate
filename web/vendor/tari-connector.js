/**
 * window.tari — the dApp side of the Tari Universe wallet bridge.
 *
 * Exposes the *same* interface as the Sapient browser extension, so a dApp written for one works
 * unmodified in the other and never has to detect which wallet it has:
 *
 *   <script src="https://universe.tari.mw/tari-connector.js"></script>
 *   <script>
 *     const [address] = await window.tari.request({ method: "tari_requestAccounts" });
 *     const balances  = await window.tari.request({ method: "tari_getBalances" });
 *     const caps      = await window.tari.request({ method: "tari_getCapabilities" });
 *     if (caps.stealthWithdraw) { … }   // feature-detect, never wallet-detect
 *
 *     // The private side is a separate permission, with its own prompt:
 *     const { granted } = await window.tari.requestViewAccess();
 *     if (granted) await window.tari.getPrivateBalances();
 *
 *     // …and private spends go through create -> approve -> submit:
 *     await window.tari.requestTransaction({ kind: "shield", resourceAddress, amount: "1000000" });
 *
 *     // Proof of funds — a shareable, publicly verifiable "this wallet can cover 100000":
 *     const proof = await window.tari.proveFunds(resourceAddress, "100000");
 *     await window.tari.verifyFunds(proof.substateId, "100000");  // -> { ok, meets }
 *   </script>
 *
 * Why a script rather than an injected object: a browser extension injects its provider from a
 * content script, which a web page cannot do. The wallet runs your dApp in a cross-origin iframe,
 * so it cannot reach into this page — and that isolation is exactly what stops a dApp reading the
 * wallet's storage. So the provider lives here and forwards every call to the wallet by
 * postMessage.
 *
 * Outside the wallet (opened directly in a tab) `window.tari.isAvailable` is false and every call
 * rejects, so a dApp can degrade rather than hang.
 */
(function () {
  "use strict";

  var PROTOCOL = "tari-dapp-bridge/1";
  var embedded = window.parent !== window;

  var pending = Object.create(null);
  var counter = 0;
  var listeners = Object.create(null);

  function nextId() {
    counter += 1;
    return "tari-" + Date.now().toString(36) + "-" + counter;
  }

  function request(method, params) {
    if (!embedded) {
      return Promise.reject(
        new Error("Tari wallet unavailable: this page is not running inside Tari Universe"),
      );
    }
    return new Promise(function (resolve, reject) {
      var id = nextId();
      pending[id] = { resolve: resolve, reject: reject };
      // Targeted at "*" deliberately and only here: the dApp cannot know the wallet's origin ahead
      // of time, and the payload is a request the wallet must still authorise. Replies are the
      // other direction and ARE origin-checked, below.
      window.parent.postMessage(
        { protocol: PROTOCOL, id: id, method: method, params: params || {} },
        "*",
      );
    });
  }

  window.addEventListener("message", function (event) {
    var data = event.data;
    if (!data || data.protocol !== PROTOCOL) return;

    // Only the wallet frame that embedded this page may answer.
    if (event.source !== window.parent) return;

    if (data.event) {
      var handlers = listeners[data.event] || [];
      for (var i = 0; i < handlers.length; i++) {
        try {
          handlers[i](data.data);
        } catch (e) {
          /* a dApp listener that throws must not break the bridge */
        }
      }
      return;
    }

    var entry = pending[data.id];
    if (!entry) return;
    delete pending[data.id];
    if (data.error) {
      var err = new Error(data.error.message || "Request failed");
      err.code = data.error.code;
      entry.reject(err);
    } else {
      entry.resolve(data.result);
    }
  });

  /**
   * The provider, shaped exactly like the Sapient extension's (`src/content/inject.ts`):
   * `{ isTariWallet: true, request({ method, params }) }`, with the same `tari_*` method names.
   *
   * That sameness is the whole point — a dApp calls `window.tari.request(...)` and never has to
   * know whether it is talking to the extension or to the wallet it is embedded in. The named
   * helpers below are sugar over the identical calls, not a second API.
   */
  var provider = {
    isTariWallet: true,
    /** Extra, and safe to ignore: true only when running inside a wallet's iframe. */
    isEmbedded: embedded,
    info: { name: "Tari Universe", rdns: "mw.tari.universe", embedded: true },

    request: function (args) {
      return request((args && args.method) || "", (args && args.params) || {});
    },

    // Sugar. Each is exactly the `request` call a dApp could make itself.
    requestAccounts: function () { return request("tari_requestAccounts"); },
    getAccounts: function () { return request("tari_getAccounts"); },
    getNetwork: function () { return request("tari_getNetwork"); },
    getBalances: function () { return request("tari_getBalances"); },
    getCapabilities: function () { return request("tari_getCapabilities"); },
    getSubstate: function (substateId, version) {
      return request("tari_getSubstate", { substateId: substateId, version: version == null ? null : version });
    },
    getTransactionResult: function (transactionId) {
      return request("tari_getTransactionResult", { transactionId: transactionId });
    },
    signAndSubmitTransaction: function (params) {
      return request("tari_signAndSubmitTransaction", params);
    },
    disconnect: function () { return request("tari_disconnect"); },

    /**
     * The bech32m wallet address, which is what a stealth output's `destination` decodes as — what
     * you need to pay this account *privately*. Not the component address `requestAccounts` returns,
     * and not derivable from it. Safe to hold: it carries only public keys.
     */
    getWalletAddress: function () { return request("tari_getWalletAddress"); },

    // ---- Private view access -----------------------------------------------------------------
    //
    // Reading the user's private balance is a separate permission from connecting, with its own
    // prompt. Connecting reveals one public address; this reveals what they hold in shielded
    // outputs, which nothing else on-chain can see. It is read-only — it never lets a dApp spend.
    //
    // Ask for it when a feature needs it, not at connect time: a prompt the user meets in the
    // middle of a flow they started is one they can actually answer.

    /** Resolves { granted: false } if declined — a refused optional permission is an answer, not an
     * error to retry. Already-granted is a no-op that never prompts. */
    requestViewAccess: function () { return request("tari_requestViewAccess"); },
    getViewAccess: function () { return request("tari_getViewAccess"); },
    /** Give the grant back when you are done with the flow that needed it. */
    revokeViewAccess: function () { return request("tari_revokeViewAccess"); },

    // ---- Private balance (requires the grant above) --------------------------------------------

    /** Per-resource totals over the account's unspent stealth outputs — the authoritative "what can
     * be spent privately right now", since it is exactly what the wallet's coin selection draws
     * from. */
    getPrivateBalances: function () { return request("tari_getPrivateBalances"); },
    /** The individual outputs behind those totals, newest first. Each is spent whole, so the shape
     * of a balance decides what a single payment can be covered by. Never includes a blinding mask
     * or key material. */
    getShieldedOutputs: function (resourceAddress) {
      return request("tari_getShieldedOutputs", resourceAddress ? { resourceAddress: resourceAddress } : {});
    },
    /** View-key scan for incoming private payments. Costs real network round trips — a
     * user-initiated refresh, not something to poll. */
    scanForPrivatePayments: function (maxPages) {
      return request("tari_scanForPrivatePayments", maxPages == null ? {} : { maxPages: maxPages });
    },
    /** Redeems a private payment you were told about out of band, by commitment — the recipient
     * side of a sendPrivately result's `recipientCommitment`. Local bookkeeping; submits nothing. */
    claimPrivatePayment: function (resourceAddress, commitment) {
      return request("tari_claimPrivatePayment", { resourceAddress: resourceAddress, commitment: commitment });
    },
    /** Like scanForPrivatePayments, but for one specific resourceAddress and not limited to outputs
     * from a native StealthTransfer instruction — it also finds a UTXO minted by custom template
     * logic inside a CallFunction/CallMethod (a voting template's ballot tokens, for instance).
     * Costs more per page than scanForPrivatePayments (it fetches each candidate transaction's full
     * result), so maxPages/pageSize default to a small lookback. */
    scanForResourceUtxos: function (resourceAddress, maxPages, pageSize, limit, transactionIds) {
      return request("tari_scanForResourceUtxos", {
        resourceAddress: resourceAddress, maxPages: maxPages, pageSize: pageSize, limit: limit, transactionIds: transactionIds,
      });
    },

    // ---- Transactions ------------------------------------------------------------------------
    //
    // create -> the user approves -> submit. `create` returns a requestId immediately rather than
    // blocking on the human, so a page that reloads mid-approval can poll by id and carry on; a
    // single blocking call loses the outcome entirely. Private spends (shield, unshield,
    // sendPrivately, htlcFund, htlcClaim, htlcRefund) are operation *kinds* here, because a real
    // stealth transfer needs a balance proof and per-input authorizations only the wallet can
    // produce — you ask it to build one, you never hand one over.

    /**
     * Proof of funds. Shields `amount` to the user's own wallet and marks the resulting output with
     * a public "worth at least `minimumValuePromise`" claim, committed into its range proof.
     *
     * Resolves to `{ transactionId, commitment, substateId, minimumValuePromise }`. `substateId` is
     * the shareable artifact: anyone can fetch it and read `minimum_value_promise` off the output,
     * with no cooperation from the wallet, no signature and no live session. Defaults the promise to
     * the full amount, which is the usual "prove I can cover N" case.
     *
     * Two things to design around: it proves *one output* is worth >= N, not that the account holds
     * >= N in total (so shield the whole amount into a single output), and spending that output
     * destroys the proof — a verifier must re-check the substate is still unspent when they care,
     * not merely that it once existed.
     */
    proveFunds: function (resourceAddress, amount, minimumValuePromise) {
      return provider.requestTransaction({
        kind: "shield",
        resourceAddress: resourceAddress,
        amount: String(amount),
        minimumValuePromise: String(minimumValuePromise == null ? amount : minimumValuePromise),
      });
    },

    /**
     * Verifies a proof-of-funds substate id: fetches the output and reports the promise it carries.
     * Needs no permission beyond a connection — the data is public on-chain, so a verifier is only
     * reading the chain through whatever wallet they happen to have.
     *
     * Resolves `{ ok, minimumValuePromise, meets }` where `meets` answers the question you actually
     * asked ("is it at least `required`?"). `ok: false` means the output is gone — spent, or never
     * there — which is the case a naive check misses: a proof that verified yesterday says nothing
     * about today.
     */
    verifyFunds: function (substateId, required) {
      return request("tari_getSubstate", { substateId: substateId, version: null }).then(function (substate) {
        // A stealth output substate is `{ Utxo: { output: UtxoOutput | null, is_frozen } }`; `output`
        // is null once spent. `UtxoOutput` is `{ output: OutputBody, auth, tag }` — OutputBody is
        // where `minimum_value_promise` actually lives (SubstateValue in ootle-ts-bindings).
        var utxo = substate && substate.substate && substate.substate.Utxo;
        var output = utxo && utxo.output && utxo.output.output;
        var promise = output && output.minimum_value_promise;
        if (promise == null) return { ok: false, minimumValuePromise: null, meets: false };
        var value = BigInt(promise);
        return {
          ok: true,
          minimumValuePromise: value.toString(),
          meets: required == null ? true : value >= BigInt(required),
        };
      }, function () {
        // A missing substate is the expected negative result (spent or never existed), not an
        // exceptional one — a verifier asking "does this still hold?" wants an answer, not a throw.
        return { ok: false, minimumValuePromise: null, meets: false };
      });
    },

    /**
     * Proves the connected account currently controls the stealth output at `substateId` — e.g. a
     * `proveFunds` output — by asking the wallet to Schnorr-sign `challenge` with the output's
     * one-time spend key. Spends nothing.
     *
     * `challenge` should be something the verifier generated themselves and can recognize; signing
     * static text proves nothing about when or for whom it was signed. Resolves
     * `{ publicKey, publicNonce, signature }` (hex) — `publicKey` must equal the substate's own
     * on-chain `auth.Key` for the proof to mean anything; a verifier checks that plus the signature
     * itself independently (proper Ristretto/Schnorr verification — beyond what this bridge script
     * carries — see the paylink reference dApp's verify code at /paylink).
     */
    signOwnershipChallenge: function (resourceAddress, substateId, challenge) {
      return request("tari_signOwnershipChallenge", { resourceAddress: resourceAddress, substateId: substateId, challenge: challenge });
    },

    /**
     * Proves the connected account holds its own `otl_…` wallet address — a generic identity proof,
     * not tied to any particular output. Simpler than `signOwnershipChallenge` when you just want
     * "prove you control this address", not "prove you control this specific proof-of-funds output".
     *
     * Resolves `{ walletAddress, publicNonce, signature }` (hex). Verify against the owner key
     * decoded from the address *you* already have in mind (e.g. via a Ristretto/bech32m decoder —
     * beyond what this bridge script carries), never against `walletAddress` taken at face value.
     */
    signWalletOwnershipChallenge: function (challenge) {
      return request("tari_signWalletOwnershipChallenge", { challenge: challenge });
    },

    createTransactionRequest: function (operation) { return request("tari_createTransactionRequest", operation); },
    getTransactionRequest: function (requestId) { return request("tari_getTransactionRequest", { requestId: requestId }); },
    submitTransactionRequest: function (requestId) { return request("tari_submitTransactionRequest", { requestId: requestId }); },

    /**
     * The whole create -> approve -> submit cycle in one call, for when the page is happy to stay
     * alive for it. Prefer the three steps individually if your page can reload mid-flow: the
     * request id survives that and this promise does not.
     */
    requestTransaction: function (operation, pollIntervalMs) {
      var interval = pollIntervalMs || 500;
      return request("tari_createTransactionRequest", operation).then(function (created) {
        return new Promise(function (resolve, reject) {
          (function poll() {
            request("tari_getTransactionRequest", { requestId: created.requestId }).then(function (summary) {
              if (summary.status === "approved") {
                request("tari_submitTransactionRequest", { requestId: created.requestId }).then(resolve, reject);
                return;
              }
              if (summary.status === "submitted") { resolve(summary.result); return; }
              if (summary.status === "rejected" || summary.status === "failed") {
                reject(new Error(summary.error || "The transaction request was not approved"));
                return;
              }
              setTimeout(poll, interval);
            }, reject);
          })();
        });
      });
    },

    on: function (event, handler) {
      (listeners[event] = listeners[event] || []).push(handler);
      return function () {
        listeners[event] = (listeners[event] || []).filter(function (h) { return h !== handler; });
      };
    },
  };

  /**
   * Publishing the provider.
   *
   * Inside a wallet's iframe the embedding wallet IS the wallet for this page — it holds the keys
   * and draws the approval prompts — so it claims `window.tari` even if an extension injected its
   * own provider into the frame first. A dApp should never have to pick.
   *
   * The assignment is defensive because an extension may have defined the property non-writable,
   * in which case a bare assignment throws under "use strict" and would take this whole script
   * with it. `window.tariUniverse` and `window.tariProviders` are always populated as a fallback
   * for anything that still cannot reach `window.tari`.
   */
  function publish(name, value, force) {
    try {
      var existing = Object.getOwnPropertyDescriptor(window, name);
      if (existing && !existing.configurable && !existing.writable && !existing.set) return false;
      if (existing && !force) return false;
      Object.defineProperty(window, name, { value: value, configurable: true, writable: true });
      return true;
    } catch (e) {
      try {
        window[name] = value;
        return true;
      } catch (e2) {
        return false;
      }
    }
  }

  publish("tariUniverse", provider, true);
  // Embedded: take the name. Not embedded: never displace an extension that got here first.
  publish("tari", provider, embedded);

  try {
    var registry = Array.isArray(window.tariProviders) ? window.tariProviders : [];
    registry.push(provider);
    window.tariProviders = registry;
  } catch (e) {
    /* a frozen window still gets the announcement event below */
  }

  try {
    window.dispatchEvent(new CustomEvent("tari:announceProvider", { detail: provider }));
  } catch (e) {
    /* older engines get the globals above regardless */
  }
  window.dispatchEvent(new Event("tari#initialized"));
})();
