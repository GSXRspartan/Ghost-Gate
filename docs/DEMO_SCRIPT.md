# Ghost Gate demo script

Two paths. **Path A** runs fully offline in any browser — no localnet, no wallet, no network.
**Path B** runs the full consensus demo and needs the Ootle localnet up. Pick based on who you are
demoing to and how much time you have.

---

## Path A — Privacy Lab (offline, ~5 minutes)

Works with nothing installed except the repo and a browser.

### 1. Start the bridge

```bash
./scripts/start_vault.sh
```

Wait for the line:

```
Ghost Gate bridge listening on http://127.0.0.1:7799
```

### 2. Open the lab

Navigate to:

```
http://127.0.0.1:7799/lab
```

You will see a dark page with a single green gate. No wallet is connected, no network is
contacted.

### 3. Walk the flow

The lab has three sections. Talk through them in this order:

**a) "What you can do now"** — shows the current policy in the registry: threshold, divisibility,
   resource, and the admin controls (1/3/10 gates, exact-tTARI conversion, test lane). Nothing here
   is a mock — this is what the registry actually holds.

**b) "Choose how you will prove"** — press **Connect proof session**. The bridge issues a real
   challenge: a nonce, a gate binding, a timestamp. The lab shows the nonce and the binding in a
   green box. Note the **Refresh beacon** switch — leave it on for now.

**c) "What happens without the proof"** — press **Visitor without proof**. The lab shows what an
   unauthenticated visitor sees: the door stays closed, no balance is requested, no amount is ever
   asked for. This is the negative path: fail closed.

**d) "Simulate consensus"** — press **Accept proof (simulated)**. The lab calls the real bridge
   access logic against the real registry. A session token is issued, shown as `gg-tok-…`. Note
   that the token says **"enough"** — it does not show an amount. That is the whole point: the
   access session proves sufficiency, never value.

**e) "Inspect the trace"** — at the bottom, the audit log shows each decision with timestamps. Note
   the pattern: the visitor's refusal is logged as *denied*, not as *failed*, and no balance or
   identity is recorded anywhere in the trace.

### 4. Show the timing-privacy property

Toggle the **Refresh beacon** switch off. The lab stops beaconing and the trace stops appending.
Point out: this is not anonymity — the session is still correlatable if the operator wants to —
but it is a real, documented privacy property: the operator can stop *future* correlation without
erasing the past. `docs/PRIVACY_MODEL.md` calls this out by name.

### 5. Show that the lab uses the real code

Point out the file `crates/ghost-gate-bridge/assets/lab/` — the lab HTML/JS calls the same
`/access/check` route as the game and the admin dashboard, against the same registry. There is no
parallel mock path.

---

## Path B — Full consensus demo (~15 minutes, localnet required)

### 0. Check the localnet is healthy first

```bash
./scripts/await_localnet.sh --once
```

You need the line confirming the instance ports are alive. If not, wait — do not start the localnet
yourself; it belongs to the shared atomic-swap session.

### 1. Start the bridge and patched walletd

```bash
./scripts/start_vault.sh --with-localnet
```

This starts the bridge on `7799` and the MVP-patched walletd with the Ghost Gate extension on the
standard wallet port.

### 2. Start the admin plane

```bash
RUSTUP_TOOLCHAIN=1.97.1 \
CARGO_TARGET_DIR=/home/pdark/gg-ootle-target \
CARGO_BUILD_JOBS=3 \
cargo run -p ghost-gate-admin
```

Note the one-time bootstrap token printed to stdout. Open `http://127.0.0.1:7811/admin` and use it
to register the first administrator credential (passkey or wallet key). Then create an application
and set a gate with threshold **exactly 10 tTARI** (divisibility 6, so raw threshold
`10_000_000`).

### 3. Run the first real proof

```bash
./scripts/first_real_proof.sh
```

This walks the whole path: localnet → patched walletd → deploy the GhostGate component → wire the
bridge. It prints each step and stops with a clear error if any step fails. On success you get a
real access session token minted by consensus.

### 4. Verify the negative paths

Run the visitor denial and the tamper check:

- Open the lab at `http://127.0.0.1:7799/lab` and press **Visitor without proof** — the trace shows the refusal.
- Tamper with the registry file while the bridge is running — the bridge logs the corruption and
  continues on the last known good binding (fail closed).
- Re-submit the same proof twice — the second submission is refused as a replay.

### 5. What to say at the end

Point at the access session token in the browser and the audit log in the terminal:

> "This token says *enough*. It never says *how much*. The threshold was enforced by consensus on
> the Ootle network, the amount stayed inside the range proof, and neither the site nor the
> operator saw a balance. That is the property."

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Lab page loads but the green box is empty | Bridge not started, or wrong port | Re-run `./scripts/start_vault.sh`; check the console for the listening line |
| `await_localnet.sh` says not ready | Shared localnet still building | Wait; do not start or stop it yourself |
| Admin page 403s on every write | Session expired | Re-login with the admin credential |
| Proof accepted but no token | Registry file missing or corrupt | Check `crates/ghost-gate-bridge/data/`; the bridge should log the corruption and stay fail-closed |
| Replay refused on a fresh proof | The bridge kept the old session alive past its window | The refresh beacon expiry is documented in `docs/PRIVACY_MODEL.md`; wait for the beacon window or restart the bridge |
