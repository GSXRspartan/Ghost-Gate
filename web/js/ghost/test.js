/**
 * Capability and provider tests, run with `node --test`.
 *
 * These are contract-driven: the mocks mirror the pinned `web/vendor/tari-dapp.d.ts`, including the
 * two divergences found in Sapient's source (its capability extras, and its dual accountsChanged
 * delivery). Nothing here talks to a live wallet — no browser or extension exists in this
 * environment — so a green run means "the adapters behave per the contract", never "Sapient works
 * on my machine". The live checklist lives in docs/MANUAL_TEST.md.
 *
 * The provider module reads `window`, so the harness installs a fake one before importing it.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { PROOF_MODES, supportedProofModes, walletUsability, networkMatches, parseAmount, formatAmount } from "./capabilities.js";
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
/* ------------------------------------------------------------------ */

test("the game page declares preview labelling and no persisted unlocks", async () => {
  // Static checks over the game sources: the three labels must exist, and the unlock state that
  // opens a door must be in-memory only (no localStorage writes for unlocks).
  const { readFile } = await import("node:fs/promises");
  const html = await readFile(new URL("../../game/index.html", import.meta.url), "utf8");
  const js = await readFile(new URL("../../game/sanctum.js", import.meta.url), "utf8");
  assert.match(html, /PREVIEW MODE/);
  assert.match(js, /session\.unlocked/, "real unlocks live in memory only");
  assert.doesNotMatch(
    js,
    /localStorage\.setItem\([^)]*unlock/i,
    "unlocks must never be persisted",
  );
  assert.match(js, /store\.puzzles/, "cosmetic puzzle progress is persisted, labelled");
  assert.match(js, /session\.provider\.id === "walletd"/, "consensus path via the walletd adapter");
  assert.match(js, /credential/, "browser wallets use the verified credential path");
});

test("the title screen offers both an explicit preview and a wallet path", async () => {
  // The startup regression was a title screen buried under an overlay; the entry choices must also
  // be unambiguous, so both paths are named on the title itself.
  const { readFile } = await import("node:fs/promises");
  const html = await readFile(new URL("../../game/index.html", import.meta.url), "utf8");
  assert.match(html, /id="btn-preview"/, "a preview entry point exists");
  assert.match(html, /id="btn-enter"/, "a wallet entry point exists");
  assert.match(html, /Connect a wallet/i, "the wallet path says what it does");
  assert.match(html, /Enter Preview/i, "the preview path is named Enter Preview");
});

test("the stylesheet makes the hidden attribute authoritative", async () => {
  // The reported startup bug: #proof-overlay/#relic-overlay set `display: grid`, which overrides the
  // UA's `[hidden] { display: none }`, so the dialogs rendered over the title on first paint.
  const { readFile } = await import("node:fs/promises");
  const css = await readFile(new URL("../../game/game.css", import.meta.url), "utf8");
  assert.match(
    css,
    /\[hidden\]\s*\{\s*display:\s*none\s*!important/,
    "the hidden attribute must win over author display rules",
  );
});

test("a transfer-only wallet is refused with a burn-free explanation", () => {
  // A wallet that can burn/bridge but not prove must never look like an unlock path, and the user
  // must be told plainly that Ghost Gate does not burn anything.
  const caps = {
    privateSpend: false,
    minimumValuePromise: false,
    ownershipProof: false,
    walletOwnershipProof: false,
    transactionRequests: true,
    burnAndBridgeIncoming: true,
    burnAndBridgeOutgoing: true,
  };
  const u = walletUsability(caps);
  assert.equal(u.usable, false, "a transfer-only wallet is not usable for proofs");
  assert.deepEqual(u.modes, [], "no proof mode is offered");
  assert.match(u.reason, /transfer or bridge funds/i);
  assert.match(u.reason, /never requires a burn/i);
});

/* ------------------------------------------------------------------ */
/* The Lost Epoch — clue/solution consistency, proven from the data      */
/* ------------------------------------------------------------------ */

// story.js is DOM-free on purpose, so the game's own rules can be tested directly.
const { CHAPTER1_CASE, chapter1Violations, CHAPTER2_DIAL, chapter2Evaluate, CHAPTER3_STAGES, chapter3Expectation } = await import("../../game/story.js");

test("chapter I: exactly one stone violates the witnesses, and the UI names the same one", () => {
  // The operator's original bug: the accepted order disagreed with the displayed clue. This test
  // pins the whole case down: every stone the UI presents is checked against every rule the
  // witnesses state, so a clue edit that desyncs the answer fails here instead of in someone's
  // evening.
  const verdicts = CHAPTER1_CASE.stones.map((s) => ({ id: s.id, v: chapter1Violations(s.id) }));
  const guilty = verdicts.filter((x) => x.v.length > 0);
  assert.equal(guilty.length, 1, "exactly one stone is altered");
  assert.equal(guilty[0].id, CHAPTER1_CASE.forgedId, "the guilty stone is the one the UI reveals");
  // The forgery is provable two independent ways: borrowed sigil AND impossible epoch.
  assert.equal(guilty[0].v.length, 2, "the altered stone violates exactly two rules");
  assert.deepEqual(guilty[0].v.map((x) => x.rule).sort(), ["bell", "registry"]);
  // The honest stones are consistent with EVERY witness — wrong accusations always get a reason.
  for (const { id, v } of verdicts) {
    if (id !== CHAPTER1_CASE.forgedId) assert.equal(v.length, 0, `${id} must be fully consistent`);
  }
});

test("chapter II: the dial has exactly one solution and the decoys each fail legibly", () => {
  const rotations = CHAPTER2_DIAL.rings.map((r) => r.length);
  const solutions = [];
  for (let a = 0; a < rotations[0]; a++)
    for (let b = 0; b < rotations[1]; b++)
      for (let c = 0; c < rotations[2]; c++) {
        const r = chapter2Evaluate([a, b, c]);
        if (r.solved) solutions.push([a, b, c]);
      }
  assert.equal(solutions.length, 1, "exactly one window reconstructs the Lost Epoch");
  const [a, b, c] = solutions[0];
  const f = chapter2Evaluate([a, b, c]).fragments;
  assert.deepEqual(f.map((x) => x.h), CHAPTER2_DIAL.span, "heights ascend exactly as the span requires");
  assert.equal(f[1].parent, f[0].id, "the middle block's parent is the foundation");
  assert.equal(f[2].parent, f[1].id, "the tip's parent is the middle");
  assert.ok(f.every((x) => !x.corrupt), "nothing under the Phantom's mark is in the spine");
  // The dial RESTS at offsets [0,0,0]; that resting state must not already be the answer, or the
  // puzzle solves itself the moment the chamber opens (a real bug this test caught).
  assert.equal(chapter2Evaluate([0, 0, 0]).solved, false, "the resting dial must not be solved");
});

test("chapter III: stages escalate and the reverse rule flips the expectation", () => {
  assert.equal(CHAPTER3_STAGES.length, 4, "four audits");
  for (let i = 1; i < CHAPTER3_STAGES.length; i++) {
    const prev = CHAPTER3_STAGES[i - 1], cur = CHAPTER3_STAGES[i];
    assert.ok(cur.length >= prev.length, "sequences never shrink");
    assert.ok(cur.decoys >= prev.decoys, "interference never eases off");
  }
  const seq = [3, 1, 0, 2];
  assert.equal(chapter3Expectation(seq, 0, false), 3, "forward: first press is the first echo");
  assert.equal(chapter3Expectation(seq, 0, true), 2, "reverse: first press is the LAST echo");
  assert.equal(chapter3Expectation(seq, 3, true), 3, "reverse: last press is the FIRST echo");
  assert.equal(chapter3Expectation(seq, 4, false), null, "nothing is expected past the end");
});

test("the compatibility matrix holds: no wallet implies both modes", () => {
  const sapientLocal = walletUsability(sapientCapabilities("local")).modes.map((m) => m.mode);
  const sapientDaemon = walletUsability(sapientCapabilities("daemon")).modes.map((m) => m.mode);
  const walletd = ["consensus"];
  const all = [...sapientLocal, ...sapientDaemon, ...walletd];
  assert.equal(all.filter((m) => m === "consensus").length, 1, "only walletd offers the consensus mode");
  assert.equal(all.filter((m) => m === "credential").length, 1, "only Sapient local accounts offer the credential mode");
  assert(!PROOF_MODES.consensus.requires.length, "the consensus mode is not gated on a capability bit");
});
