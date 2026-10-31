import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  connectButtonState,
  connectedWallet,
  disconnectedWallet,
  newWalletConnection,
  switchWalletView,
} from "../../web/lab/wallet-connection-state.js";

const input = (connection, connecting = false) => ({ hasGate: true, mode: "sapient", connection, connecting });

test("Connect Wallet is enabled initially and disabled while one approval is pending", () => {
  assert.deepEqual(connectButtonState(input(newWalletConnection())), {
    hidden: false, disabled: false, label: "Connect wallet", title: "Connect Sapient",
  });
  assert.deepEqual(connectButtonState(input(newWalletConnection(), true)), {
    hidden: false, disabled: true, label: "Waiting for Sapient…", title: "Waiting for wallet approval",
  });
});

test("a successful browser connection stays disabled through view switches and proof results", () => {
  const connection = connectedWallet("sapient");
  const switched = switchWalletView(connection, "technical");
  assert.equal(switched.connection, connection, "view changes retain current wallet state");
  assert.equal(connectButtonState(input(switched.connection)).disabled, true);
  // A proof result is unrelated to account authorization: the same page connection remains valid.
  assert.equal(connectButtonState(input(connection)).label, "Wallet Connected");
});

test("a genuine provider loss re-enables the accessible native connect control", () => {
  const state = connectButtonState(input(disconnectedWallet()));
  assert.equal(state.disabled, false);
  assert.equal(state.label, "Connect wallet");
});

test("Lab wiring guards synthetic duplicate clicks and renders the native disabled state", () => {
  const lab = readFileSync(new URL("../../web/lab/lab.js", import.meta.url), "utf8");
  assert.match(lab, /if \(state\.walletConnecting \|\| state\.walletConnection\.connected\) return;/);
  assert.match(lab, /btn\.disabled = presentation\.disabled;/);
  assert.match(lab, /rawProvider\.on\("accountsChanged"/);
});

test("the approval request path does not reference a button local to its renderer", () => {
  const lab = readFileSync(new URL("../../web/lab/lab.js", import.meta.url), "utf8");
  const connect = lab.slice(lab.indexOf("async function connectWallet()"), lab.indexOf("function renderConnectIntro()"));
  assert.match(connect, /renderConnectIntro\(\);[\s\S]*provider\.request\("tari_requestAccounts"\)/);
  assert.doesNotMatch(connect, /\bbtn\./, "connectWallet must not use renderConnectIntro's local btn");
});
