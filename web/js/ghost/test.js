/**
 * Capability and provider tests, run with `node --test`.
 *
 * These are contract-driven: the mocks mirror Tari's documented dApp contract, including the
 * two divergences found in Sapient's source (its capability extras, and its dual accountsChanged
 * delivery). Nothing here talks to a live wallet — no browser or extension exists in this
 * environment — so a green run means "the adapters behave per the contract", never "Sapient works
 * on my machine". The live checklist lives in docs/MANUAL_TEST.md.
 *
 * The provider module reads `window`, so the harness installs a fake one before importing it.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { PROOF_MODES, browserProviderGateCompatibility, inspectMinotariSendDeepLink, supportedProofModes, walletUsability, networkMatches, parseAmount, formatAmount, networkVerdict, describeProviderError } from "./capabilities.js";
import { sapientProvider, universeProvider, walletdProvider } from "./provider.js";

/** Installs a minimal fake window with a provider object, returns an uninstaller. */
function withWindow(provider, extra = {}) {
  globalThis.window = {
    location: { origin: "http://127.0.0.1:7799" },
    tari: provider,
    ...extra,
  };
  return () => {
    delete globalThis.window;
  };
}

/* ------------------------------------------------------------------ */
/* capabilities.js — the mode mapping                                  */
/* ------------------------------------------------------------------ */

test("a fully capable local account offers exactly the credential mode", () => {
  const caps = {
    privateSpend: true,
    minimumValuePromise: true,
    ownershipProof: true,
    walletOwnershipProof: true,
    transactionRequests: true,
  };
  const modes = supportedProofModes(caps);
  assert.equal(modes.length, 1);
  assert.equal(modes[0].mode, "credential");
  // A browser wallet must never report the consensus mode, no matter how capable it looks.
  assert(!modes.some((m) => m.mode === "consensus"));
});

test("a daemon-relayed account (no stealth signing) supports no mode and says why", () => {
  const caps = {
    privateSpend: true, // the daemon path can move revealed funds
    minimumValuePromise: false,
    ownershipProof: false,
  };
  const { usable, reason, modes } = walletUsability(caps);
  assert.equal(usable, false);
  assert.equal(modes.length, 0);
  assert.match(reason, /minimumValuePromise/);
  assert.match(reason, /daemon-relayed/, "the reason names the situation the user is actually in");
});

test("a wallet that answers nothing fails closed with a reason, not silently", () => {
  const { usable, reason } = walletUsability(null);
  assert.equal(usable, false);
  assert.match(reason, /did not report capabilities/);
});

test("an L2 browser provider cannot be offered to a native Minotari L1 XTM gate", () => {
  const blocked = browserProviderGateCompatibility({ proof_kind: "minotari_xtm" });
  assert.equal(blocked.ok, false);
  assert.match(blocked.reason, /Minotari L1 XTM/i);
  assert.match(blocked.reason, /window\.tari/i);
  assert.equal(browserProviderGateCompatibility({ proof_kind: "ootle" }).ok, true);
  assert.equal(browserProviderGateCompatibility({ proofKind: "xtm" }).ok, false);
});

test("synthetic Minotari send links are diagnostic only, never gate authorization", () => {
  const parsed = inspectMinotariSendDeepLink(
    "tari://mainnet/transactions/send?tariAddress=abc123&amount=1234567&note=synthetic",
  );
  assert.equal(parsed.ok, true);
  assert.equal(parsed.network, "mainnet");
  assert.equal(parsed.amountMicro, "1234567");
  assert.equal(parsed.canAuthorizeGate, false);
  assert.match(parsed.reason, /payment-review intent/i);
  assert.equal(inspectMinotariSendDeepLink("tari://mainnet/transactions/send?tariAddress=x&amount=-1").ok, false);
  assert.equal(inspectMinotariSendDeepLink("https://example.test/transactions/send?tariAddress=x").ok, false);
});

test("the network check compares Ootle bytes, tolerating name case", () => {
  const names = { esmeralda: 0x26, igor: 0x24, localnet: 0x10 };
  assert.equal(networkMatches("Esmeralda", names, 0x26).ok, true);
  assert.equal(networkMatches("esmeralda ", names, 0x26).ok, true);
  assert.equal(networkMatches("mainnet", names, 0x26).ok, false);
  assert.equal(networkMatches(undefined, names, 0x26).byte, null);
  // The Universe trap: tari_getNetwork returns the Ootle network, never the L1 one. A gate bound
  // to the Ootle byte must not be "verified" against an L1 network name.
  assert.equal(networkMatches("esmeralda", names, 0x10).ok, false);
});

test("networkVerdict names the mismatch and keeps the gate as the blocker", () => {
  const v = networkVerdict("esmeralda", 0x10);
  assert.equal(v.ok, false);
  assert.equal(v.byte, 0x26);
  assert.match(v.verdict, /mismatch/i);
  assert.match(v.verdict, /blocked by the gate/);
  assert.match(networkVerdict("esmeralda", 0x26).verdict, /the gate's own network/i);
  assert.match(networkVerdict(null, 0x10).verdict, /did not report a network/i);
  assert.match(networkVerdict("moonnet", 0x10).verdict, /not a cohort this gate can bind to/i);
});

test("probe with the real Sapient's 4100: the wallet is available, just not connected", () => {
  // The physical Sapient refuses capability reads before an authorized account request. The
  // mock ones answered freely, which is exactly why 4100 only showed up in physical testing.
  const strict = {
    isTariWallet: true,
    request(args) {
      if (args.method === "tari_getCapabilities") {
        return Promise.reject(Object.assign(new Error("not connected"), { code: 4100 }));
      }
      return Promise.resolve([]);
    },
  };
  const undo = withWindow(strict);
  try {
    const probe = sapientProvider().probe().then((p) => {
      assert.equal(p.available, true, "the extension is present — it must not read as 'no wallet'");
      assert.equal(p.capabilities, null);
      assert.equal(p.modes.length, 0);
      assert.match(p.unusableReason, /not connected/i);
      assert.match(p.unusableReason, /Connect wallet/i);
    });
    return probe;
  } finally {
    undo();
  }
});

test("no provider on the page: unavailable with the honest install reason", () => {
  const undo = withWindow(null);
  try {
    return sapientProvider().probe().then((p) => {
      assert.equal(p.available, false);
      assert.match(p.unavailableReason, /No Tari wallet answered/i);
    });
  } finally {
    undo();
  }
});

test("describeProviderError names 4001, 4100, 4200, locked and generic distinctly", () => {
  const rejected = describeProviderError({ code: 4001, message: "user rejected" });
  assert.equal(rejected.cls, "warn");
  assert.match(rejected.text, /declined/i);

  const unauthorized = describeProviderError({ code: 4100, message: "not connected" });
  assert.equal(unauthorized.cls, "bad");
  assert.match(unauthorized.text, /not connected/i);
  assert.match(unauthorized.text, /Connect or reconnect/i);
  assert.doesNotMatch(unauthorized.text, /capabilities/i, "4100 must never claim missing capabilities");

  const unsupported = describeProviderError({ code: 4200, message: "unsupported" });
  assert.equal(unsupported.cls, "bad");
  assert.match(unsupported.text, /does not support/i);

  const locked = describeProviderError({ message: "wallet is locked" });
  assert.equal(locked.cls, "warn");
  assert.match(locked.text, /locked/i);

  const generic = describeProviderError({ message: "something odd" });
  assert.equal(generic.cls, "bad");
  assert.match(generic.text, /something odd/);
});

test("describeProviderError treats JSON-RPC internal and method-not-found errors distinctly", () => {
  const internal = describeProviderError({ code: -32603, message: "boom" });
  assert.equal(internal.cls, "bad");
  assert.match(internal.text, /internal error/i);
  assert.match(internal.text, /boom/, "the wallet's own message is kept visible");
  assert.doesNotMatch(internal.text, /declined/i, "an internal error is not the user's decline");

  const noMethod = describeProviderError({ code: -32601, message: "no such method" });
  assert.equal(noMethod.cls, "bad");
  assert.match(noMethod.text, /does not support/i);
});

test("insufficient funds guidance derives the human threshold from gate metadata", () => {
  const detail = describeProviderError(
    { code: -32603, message: "InsufficientFunds: Required: 100000000, Available: 50000000" },
    { thresholdRaw: "100000000", divisibility: 6, symbol: "tTARI" },
  );
  assert.match(detail.text, /Reveal at least 100 tTARI in a qualifying output and try again/);
  assert.doesNotMatch(detail.text, /Unshield more/);
});

test("amounts parse as strings or bigints and never as floats", () => {
  assert.equal(parseAmount("400000").toString(), "400000");
  assert.equal(parseAmount(400000n)?.toString(), "400000");
  assert.equal(parseAmount("4e5"), null, "exponent notation is not an amount the wallets accept");
  assert.equal(parseAmount(0.5), null);
  assert.equal(parseAmount("9007199254740993").toString(), "9007199254740993", "beyond Number.MAX_SAFE_INTEGER");
});

test("display formatting uses the resource's own divisibility, never an assumed 6", () => {
  assert.equal(formatAmount("10000", 2), "100");
  assert.equal(formatAmount("10000", 6), "0.01");
  assert.equal(formatAmount("400000", 0), "400000");
  assert.equal(formatAmount("1000000", 2), "10000");
});

test("the real 10-tTARI gate threshold renders as 10, and a missing receipt threshold never renders as 'null'", () => {
  // Regression (master status §14): the credential receipt's required_minimum reached the
  // page as null/undefined on the physical Esmeralda proof, and the UI rendered "null tTARI".
  // 10_000_000 raw at divisibility 6 is exactly 10 tTARI.
  assert.equal(formatAmount("10000000", 6), "10");
  assert.equal(formatAmount(10000000, 6), "10");
  // formatAmount itself refuses missing evidence: it returns null for a missing threshold,
  // never the string "null". The page renders an honest "unknown" note in that case.
  assert.equal(formatAmount(null, 6), null);
  assert.equal(formatAmount(undefined, 6), null);
  assert.equal(formatAmount("", 6), null);
});

/* ------------------------------------------------------------------ */
/* Sapient — the extension provider                                    */
/* ------------------------------------------------------------------ */

function sapientCapabilities(account = "local") {
  const isLocal = account === "local";
  return {
    exactInputSelection: true,
    stealthWithdraw: isLocal,
    stealthRedeem: isLocal,
    stealthRedeemPrivateFee: isLocal,
    htlcFund: isLocal,
    scriptPathSpend: isLocal,
    privateSpend: true,
    shieldFunds: true, // Sapient's own extension beyond the shared spec; read and ignored
    privateBalanceView: true,
    privateScan: isLocal,
    privateViewGranted: false,
    transactionResultLookup: true,
    transactionRequests: true,
    walletAddress: true,
    minimumValuePromise: isLocal,
    ownershipProof: isLocal,
    walletOwnershipProof: isLocal,
    confidentialDeposit: isLocal,
    supportsPrivateFees: isLocal,
    dryRunIsLocal: false,
  };
}

function fakeTari({ caps, rejectMethods = [] } = {}) {
  const calls = [];
  const provider = {
    isTariWallet: true,
    isEmbedded: false,
    async request({ method, params }) {
      calls.push({ method, params });
      if (rejectMethods.includes(method)) {
        const e = new Error("Method unsupported by this wallet");
        e.code = 4200;
        throw e;
      }
      switch (method) {
        case "tari_getCapabilities":
          return caps;
        case "tari_createTransactionRequest":
          return { requestId: "req_1" };
        case "tari_getTransactionRequest":
          return { status: "approved", note: "" };
        case "tari_submitTransactionRequest":
          return { transactionId: "tx_1", commitment: "ab", substateId: "utxo_res_2c71", minimumValuePromise: "10000" };
        case "tari_signOwnershipChallenge":
          assert.ok(params.resourceAddress, "the gate resource must be sent");
          assert.equal(params.substateId, "utxo_res_2c71");
          assert.ok(params.challenge, "the site's challenge string must be sent verbatim");
          return { publicKey: "pk", publicNonce: "r", signature: "s" };
        case "tari_getTransactionResult":
          return { status: "Accepted" };
        default:
          throw Object.assign(new Error("unmocked method " + method), { code: 4200 });
      }
    },
  };
  return { provider, calls };
}

test("sapient probe: a local account gets exactly credential mode", async () => {
  const { provider } = fakeTari({ caps: sapientCapabilities("local") });
  const undo = withWindow(provider);
  try {
    const probe = await sapientProvider().probe();
    assert.equal(probe.available, true);
    assert.deepEqual(probe.modes.map((m) => m.mode), ["credential"]);
    assert.equal(probe.unusableReason, null);
  } finally {
    undo();
  }
});

test("sapient probe: a daemon-relayed account is shown as unsupported, not hidden", async () => {
  const { provider } = fakeTari({ caps: sapientCapabilities("daemon") });
  const undo = withWindow(provider);
  try {
    const probe = await sapientProvider().probe();
    assert.equal(probe.available, true, "the wallet answered; the account is what fails");
    assert.equal(probe.modes.length, 0);
    assert.match(probe.unusableReason, /Missing: minimumValuePromise, ownershipProof/);
  } finally {
    undo();
  }
});

test("no wallet on the page: the probe reports the install/open path", async () => {
  const undo = withWindow(null);
  try {
    const probe = await sapientProvider().probe();
    assert.equal(probe.available, false);
    assert.match(probe.unavailableReason, /Install the Sapient extension/);
  } finally {
    undo();
  }
});

test("credentials flow: shield -> poll -> submit -> sign, in that order, with the right params", async () => {
  const { provider, calls } = fakeTari({ caps: sapientCapabilities("local") });
  const undo = withWindow(provider);
  try {
    const p = sapientProvider();
    const built = await p.approveAndBuildProof("credential", {
      resourceAddress: "resource_7",
      amount: "10000",
      minimumValuePromise: "10000",
      maxFee: "5000",
    });
    assert.equal(built.substateId, "utxo_res_2c71");
    assert.equal(built.minimumValuePromise, "10000");

    const kinds = calls.map((c) => c.method);
    assert.deepEqual(kinds, [
      "tari_createTransactionRequest",
      "tari_getTransactionRequest",
      "tari_submitTransactionRequest",
    ]);
    const createParams = calls[0].params;
    assert.equal(createParams.kind, "shield");
    assert.equal(createParams.minimumValuePromise, "10000", "the gate threshold is the promise");
    assert.equal(createParams.amount, "10000");
    assert.equal(createParams.maxFee, "5000");

    const ownership = await p.signChallenge("utxo_res_2c71", "challenge-abc");
    assert.deepEqual(ownership, { publicKey: "pk", publicNonce: "r", signature: "s" });
    // The signing call names the gate's resource — the wallet re-derives the output's key from it.
    const signCall = calls.at(-1);
    assert.equal(signCall.params.resourceAddress, "resource_7");
  } finally {
    undo();
  }
});

test("resume flow: signChallenge accepts an explicit resource without any shield having run", async () => {
  const { provider, calls } = fakeTari({ caps: sapientCapabilities("local") });
  const undo = withWindow(provider);
  try {
    const p = sapientProvider();
    // No approveAndBuildProof: the output already exists on chain (the RESUME path signs over
    // it directly, naming the gate's resource explicitly).
    const ownership = await p.signChallenge("utxo_res_2c71", "challenge-abc", "resource_gate");
    assert.deepEqual(ownership, { publicKey: "pk", publicNonce: "r", signature: "s" });
    const signCall = calls.at(-1);
    assert.equal(signCall.method, "tari_signOwnershipChallenge");
    assert.equal(signCall.params.resourceAddress, "resource_gate", "the explicit resource is used");
    assert.equal(signCall.params.substateId, "utxo_res_2c71");
    assert.equal(signCall.params.challenge, "challenge-abc");
  } finally {
    undo();
  }
});

test("resume flow: no build and no explicit resource refuses honestly instead of guessing", async () => {
  const { provider } = fakeTari({ caps: sapientCapabilities("local") });
  const undo = withWindow(provider);
  try {
    const p = sapientProvider();
    await assert.rejects(
      () => p.signChallenge("utxo_res_2c71", "challenge-abc"),
      (e) => /no proof has been built yet/.test(e.message),
    );
  } finally {
    undo();
  }
});

test("a wallet rejection (4001) surfaces as a declined request, not an error", async () => {
  const { provider } = fakeTari({ caps: sapientCapabilities("local") });
  const original = provider.request.bind(provider);
  provider.request = async (args) => {
    if (args.method === "tari_createTransactionRequest") {
      throw Object.assign(new Error("User rejected"), { code: 4001 });
    }
    return original(args);
  };
  const undo = withWindow(provider);
  try {
    const p = sapientProvider();
    await assert.rejects(
      () => p.approveAndBuildProof("credential", { resourceAddress: "r", amount: "1", minimumValuePromise: "1" }),
      (e) => e.code === 4001,
    );
  } finally {
    undo();
  }
});

test("a zero-balance Sapient account cannot turn connection capability into eligibility", async () => {
  // This mirrors the real adversarial visitor path: the extension can be present, local, on the
  // right network and able to sign, while still being unable to construct the required 10 tTARI
  // output. The adapter must neither submit nor sign a made-up credential after that refusal.
  const { provider, calls } = fakeTari({ caps: sapientCapabilities("local") });
  const original = provider.request.bind(provider);
  provider.request = async (args) => {
    if (args.method === "tari_createTransactionRequest") {
      calls.push({ method: args.method, params: args.params });
      throw Object.assign(new Error("insufficient eligible tTARI for this request"), { code: -32603 });
    }
    return original(args);
  };
  const undo = withWindow(provider);
  try {
    const p = sapientProvider();
    const probe = await p.probe();
    assert.deepEqual(probe.modes.map((mode) => mode.mode), ["credential"], "capability is not a balance verdict");
    await assert.rejects(
      () => p.approveAndBuildProof("credential", {
        resourceAddress: "resource_gate", amount: "10000000", minimumValuePromise: "10000000", maxFee: "0",
      }),
      /insufficient eligible tTARI/,
    );
    assert.deepEqual(calls.map((call) => call.method), ["tari_getCapabilities", "tari_createTransactionRequest"]);
    assert(!calls.some((call) => call.method === "tari_submitTransactionRequest"));
    assert(!calls.some((call) => call.method === "tari_signOwnershipChallenge"));
  } finally {
    undo();
  }
});

test("a wallet that returns no substateId is an error, never a silent skip", async () => {
  const { provider } = fakeTari({ caps: sapientCapabilities("local") });
  const original = provider.request.bind(provider);
  provider.request = async (args) => {
    if (args.method === "tari_submitTransactionRequest") return { transactionId: "tx_1" };
    return original(args);
  };
  const undo = withWindow(provider);
  try {
    await assert.rejects(
      () => sapientProvider().approveAndBuildProof("credential", { resourceAddress: "r", amount: "1", minimumValuePromise: "1" }),
      /no substateId/,
    );
  } finally {
    undo();
  }
});

test("sapient extras in capabilities do not create modes", async () => {
  // supportsPrivateFees / shieldFunds are real Sapient extensions; neither is a Ghost Gate mode.
  const caps = { ...sapientCapabilities("local"), supportsPrivateFees: true, shieldFunds: true };
  const undo = withWindow({ isTariWallet: true, isEmbedded: false, async request() { return caps; } });
  try {
    const probe = await sapientProvider().probe();
    assert.deepEqual(probe.modes.map((m) => m.mode), ["credential"]);
  } finally {
    undo();
  }
});

/* ------------------------------------------------------------------ */
/* Tari Universe — the embedded provider                               */
/* ------------------------------------------------------------------ */

test("universe in a plain tab: unreachable by design, with the explanation", async () => {
  const undo = withWindow(null);
  try {
    const probe = await universeProvider().probe();
    assert.equal(probe.available, false);
    assert.match(probe.unavailableReason, /app catalogue/);
  } finally {
    undo();
  }
});

test("universe with a non-embedded provider (extension present): says to open inside the wallet", async () => {
  const { provider } = fakeTari({ caps: sapientCapabilities("local") });
  const undo = withWindow(provider);
  try {
    const probe = await universeProvider().probe();
    assert.equal(probe.available, false);
    assert.match(probe.unavailableReason, /not running inside it/);
  } finally {
    undo();
  }
});

test("universe embedded: the same contract, the same mode", async () => {
  const { provider } = fakeTari({ caps: sapientCapabilities("local") });
  const undo = withWindow(provider, { tari: { ...provider, isEmbedded: true } });
  try {
    const probe = await universeProvider().probe();
    assert.equal(probe.available, true);
    assert.deepEqual(probe.modes.map((m) => m.mode), ["credential"]);
  } finally {
    undo();
  }
});

/* ------------------------------------------------------------------ */
/* Local walletd — the developer backend                               */
/* ------------------------------------------------------------------ */

function withFetch(routes) {
  const original = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const path = String(input).replace(/^https?:\/\/[^/]+/, "");
    const key = `${init.method || "GET"} ${path}`;
    const handler = routes[key];
    if (!handler) return { ok: false, status: 404, json: async () => ({ error: `no route ${key}` }) };
    return handler();
  };
  return () => {
    globalThis.fetch = original;
  };
}

test("walletd probe: consensus mode only, and never credential", async () => {
  const undo = withFetch({
    "GET /wallet/status": () =>
      ({ ok: true, status: 200, json: async () => ({ reachable: true, has_default_account: true, network: 16, network_name: "localnet" }) }),
  });
  try {
    const probe = await walletdProvider("http://127.0.0.1:7799").probe();
    assert.equal(probe.available, true);
    assert.deepEqual(probe.modes.map((m) => m.mode), ["consensus"]);
    assert.equal(probe.capabilities.ownershipProof, false, "credential mode is deliberately not offered here");
  } finally {
    undo();
  }
});

test("walletd unreachable: the card shows the reason, and the consensus mode list is empty", async () => {
  const undo = withFetch({
    "GET /wallet/status": () => ({ ok: false, status: 503, json: async () => ({ error: "no wallet daemon is connected" }) }),
  });
  try {
    const probe = await walletdProvider("http://127.0.0.1:7799").probe();
    assert.equal(probe.available, false);
    assert.match(probe.unavailableReason, /no wallet daemon is connected/);
  } finally {
    undo();
  }
});

test("the walletd flow uses the existing bridge routes and reports the receipt verbatim", async () => {
  const undo = withFetch({
    "GET /wallet/status": () => ({ ok: true, status: 200, json: async () => ({ reachable: true }) }),
    "POST /gate/g1/challenge": () =>
      ({ ok: true, status: 200, json: async () => ({ challenge_nonce: "aa", session_commitment: "bb" }) }),
    "POST /gate/g1/prove": () => ({ ok: true, status: 202, json: async () => ({ proof_id: "p1" }) }),
    "GET /proof/p1/status": () =>
      ({ ok: true, status: 200, json: async () => ({ state: "accepted", transaction_id: "tx9", attested_minimum: 10000, input_count: 1 }) }),
  });
  try {
    const p = walletdProvider("http://127.0.0.1:7799");
    const { result } = await p.approveAndBuildProof("consensus", { gateId: "g1" });
    assert.equal(result.state, "accepted");
    assert.equal(result.attested_minimum, 10000);
  } finally {
    undo();
  }
});

/* ------------------------------------------------------------------ */
/* The matrix, as executable statements                                */
