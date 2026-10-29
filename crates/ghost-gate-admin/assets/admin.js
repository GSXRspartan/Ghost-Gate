/**
 * Ghost Gate administrator dashboard.
 *
 * Security posture of this file: it holds NO secrets. The session lives in an HttpOnly cookie the
 * server set; the CSRF token lives only in this module's memory for the life of the page. Nothing
 * here touches localStorage. Every privileged action is a fetch the SERVER authorises; the
 * dashboard cannot grant itself anything.
 */

const $ = (id) => document.getElementById(id);
let csrf = null;
let actor = null;
let stepupValid = false;
const ORIGIN = window.location.origin;

function set(status, isError) {
  const el = $("admin-status");
  el.textContent = status;
  el.style.cssText = isError
    ? "border:2px solid #c00;background:#fee;color:#900;padding:8px 12px;border-radius:6px;margin:8px 0;font-weight:600"
    : "border:none;background:none;color:inherit;padding:0;margin:0;font-weight:normal";
}
function fail(id, msg) {
  const el = $(id);
  el.hidden = false;
  el.textContent = msg;
}
function clearFail(id) {
  const el = $(id);
  el.hidden = true;
  el.textContent = "";
}
function appMsg(app, msg, isError) {
  const el = $(`msg-${app.applicationId}`);
  if (!el) { set(msg, isError); return; }
  el.textContent = msg;
  el.style.cssText = isError
    ? "border:2px solid #c00;background:#fee;color:#900;padding:8px 12px;border-radius:6px;margin:8px 0;font-weight:600"
    : "color:#0a0;padding:4px 0;margin:4px 0;font-weight:600";
  el.hidden = false;
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (csrf && opts.mutating) headers["X-GG-CSRF"] = csrf;
  const res = await fetch(path, {
    method: opts.method || (opts.body ? "POST" : "GET"),
    headers,
    body: opts.body || undefined,
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

/* ------------------------- base64url helpers (no deps) ------------------------- */
function b64u(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64uDecode(s) {
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/* ------------------------------ WebAuthn ------------------------------ */
async function passkeyRegister(challengeB64) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: b64uDecode(challengeB64),
      rp: { name: "Ghost Gate", id: new URL(ORIGIN).hostname },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "ghost-gate-admin", displayName: "Ghost Gate Administrator" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      timeout: 120_000,
      attestation: "none",
    },
  });
  const response = cred.response;
  const clientData = new Uint8Array(response.clientDataJSON);
  // Parse the attestation object for authData + credential id.
  const attObj = new Uint8Array(response.attestationObject);
  const authData = extractAuthDataFromAttestation(attObj);
  return {
    method: "passkey",
    challenge: challengeB64,
    webauthn: {
      client_data_b64: b64u(clientData),
      authenticator_data_b64: b64u(authData),
      credential_id_b64: b64u(new Uint8Array(cred.rawId)),
      attestation_object_b64: b64u(attObj),
    },
  };
}

/** Minimal CBOR walk to pull authData out of an attestation object (client side only — the
 * server re-verifies everything from raw bytes; this is just what WebAuthn's API hands us). */
function extractAuthDataFromAttestation(att) {
  // attestationObject = { fmt, authData, attStmt }; find authData byte string.
  // Walk: 0xA3, then three key/value pairs. Keys: "fmt"(text), "attStmt"(map), "authData"(bytes).
  let i = 1;
  for (let k = 0; k < 3; k++) {
    const keyLen = att[i] & 0x1f;
    const key = new TextDecoder().decode(att.slice(i + 1, i + 1 + keyLen));
    i += 1 + keyLen;
    if (key === "fmt") {
      const l = att[i] & 0x1f;
      i += 1 + l;
    } else if (key === "attStmt") {
      i += skipCbor(att, i);
    } else if (key === "authData") {
      const lenByte = att[i];
      let len, hdr;
      if (lenByte === 0x58) { len = att[i + 1]; hdr = 2; }
      else if (lenByte === 0x59) { len = (att[i + 1] << 8) | att[i + 2]; hdr = 3; }
      else { len = lenByte & 0x1f; hdr = 1; }
      return att.slice(i + hdr, i + hdr + len);
    }
  }
  throw new Error("no authData in attestation object");
}
function skipCbor(b, i) {
  const first = b[i];
  const major = first >> 5, info = first & 0x1f;
  if (major === 4) {
    let off = 1;
    for (let n = 0; n < info; n++) off += skipCbor(b, i + off);
    return off;
  }
  if (major === 5) {
    let off = 1;
    for (let n = 0; n < 2 * info; n++) off += skipCbor(b, i + off);
    return off;
  }
  if (major === 2 || major === 3) {
    let len = info, hdr = 1;
    if (info === 24) { len = b[i + 1]; hdr = 2; }
    if (info === 25) { len = (b[i + 1] << 8) | b[i + 2]; hdr = 3; }
    if (info === 26) { len = (b[i + 1] << 24) | (b[i + 2] << 16) | (b[i + 3] << 8) | b[i + 4]; hdr = 5; }
    return hdr + len;
  }
  return 1;
}

async function passkeyLogin(challengeB64, allowCredentials) {
  // Target the specific registered credential. Without allowCredentials a non-discoverable
  // Windows Hello credential cannot be found on the platform authenticator and the browser falls
  // back to asking for a roaming USB security key. The "internal"/"hybrid" transport hints steer
  // the browser to the platform authenticator (Windows Hello) rather than a USB key.
  const allow = (allowCredentials || []).map((c) => ({
    type: "public-key",
    id: b64uDecode(c.id),
    transports: ["internal", "hybrid"],
  }));
  const publicKey = {
    challenge: b64uDecode(challengeB64),
    rpId: new URL(ORIGIN).hostname,
    userVerification: "required",
    timeout: 120_000,
  };
  if (allow.length) {
    publicKey.allowCredentials = allow;
  }
  const cred = await navigator.credentials.get({ publicKey });
  const r = cred.response;
  return {
    method: "passkey",
    challenge: challengeB64,
    credentialId: b64u(new Uint8Array(cred.rawId)),
    webauthn: {
      client_data_b64: b64u(new Uint8Array(r.clientDataJSON)),
      authenticator_data_b64: b64u(new Uint8Array(r.authenticatorData)),
      signature_b64: b64u(new Uint8Array(r.signature)),
      credential_id_b64: b64u(new Uint8Array(cred.rawId)),
    },
  };
}

/* ------------------------------ boot ------------------------------ */
async function boot() {
  const b = await api("/admin/api/bootstrap");
  // Passkeys need a registrable domain as the RP ID; an IP literal is refused by the browser with a
  // bare "SecurityError: This is an invalid domain". Say so plainly, and point at the method that
  // does work here, instead of letting the operator meet a cryptic failure.
  const hostIsIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(location.hostname) || location.hostname.includes(":");
  const passkeyNote = $("passkey-note");
  if (hostIsIp) {
    passkeyNote.hidden = false;
    passkeyNote.innerHTML =
      "Passkeys are not available on an IP address — WebAuthn requires a domain as the relying party. " +
      `This dashboard is open at <code>${esc(location.hostname)}</code>. Start the admin plane with ` +
      "<code>GG_ADMIN_HOSTNAME=localhost</code> (or your real domain) and use that address, " +
      "or sign in with a wallet key now.";
    $("reg-passkey").disabled = true;
    $("login-passkey").disabled = true;
  } else {
    passkeyNote.hidden = true;
  }
  if (!b.json.authenticated && !b.json.bootstrapRequired) {
    $("login-panel").hidden = false;
  }
  if (b.json.bootstrapRequired) {
    $("bootstrap-panel").hidden = false;
    set("Registration open (first administrator).");
  } else {
    set("Registration closed.");
  }
  const s = await api("/admin/api/state");
  if (s.status === 200) {
    csrf = s.json.csrf;
    actor = s.json.actor;
    stepupValid = s.json.stepupValid;
    enterDashboard(s.json);
  }
}

function enterDashboard(state) {
  $("bootstrap-panel").hidden = true;
  $("login-panel").hidden = true;
  $("dashboard").hidden = false;
  // Keep the module state in sync whenever the dashboard renders — including after a login, which
  // reaches here through refresh(). Without this the signed-in credential kind (actor) stayed unset
  // until a full page reload, so step-up defaulted to the wallet-key ceremony for a passkey admin.
  actor = state.actor;
  if (state.csrf) { csrf = state.csrf; }
  $("actor-line").textContent = `Signed in as ${state.actor}`;
  stepupValid = state.stepupValid;
  renderStepup();
  renderApps(state);
  renderSessions(state);
  renderAudit();
}

function renderStepup() {
  $("stepup-line").textContent = stepupValid
    ? "Fresh approval: policy changes allowed."
    : "No fresh approval: policy changes are LOCKED until you step up.";
  $("btn-stepup").classList.toggle("ghost", stepupValid);
}

/* ------------------------------ applications ------------------------------ */
function renderApps(state) {
  const host = $("apps-list");
  host.replaceChildren();
  for (const app of state.applications) {
    const card = document.createElement("div");
    card.className = "gate-card";
    card.dataset.app = app.applicationId;
    const head = document.createElement("div");
    head.className = "row";
    const title = document.createElement("strong");
    title.textContent = `${app.displayName} (${app.applicationId})`;
    const badge = document.createElement("span");
    badge.className = "badge " + (app.production ? "" : "test");
    badge.textContent = app.production ? "production" : "test deployment";
    const top = document.createElement("span");
    top.className = "badge";
    top.textContent = app.topology;
    const owner = document.createElement("span");
    owner.className = "hint";
    owner.textContent = app.ownedByYou ? "owned by you" : `owned by ${app.owner}`;
    head.append(title, badge, top, owner);
    card.append(head);

    const ttl = document.createElement("p");
    ttl.className = "hint";
    ttl.textContent = `Default session: ${humanTtl(app.defaultSessionTtlSecs)} · limit ${app.maxGates} gates · revision ${app.revision}`;
    card.append(ttl);

    // Gates table.
    const table = document.createElement("table");
    table.innerHTML = "<tr><th>Gate</th><th>Name</th><th>Threshold</th><th>Mode</th><th>Max tier</th><th>Session</th><th>Used on</th><th>Grants</th><th>State</th><th></th></tr>";
    for (const g of app.gates) {
      const tr = document.createElement("tr");
      const th = g.thresholdRaw;
      const human = ghostFormat(th, g.divisibility);
      tr.dataset.gateId = g.gateId;
      tr.innerHTML = `
        <td class="mono">${esc(g.gateId)}</td>
        <td>${esc(g.name)}</td>
        <td title="${esc(th)} raw units">${esc(human)} ${esc(g.symbol)}</td>
        <td>${esc(g.proofMode)}${g.activatable ? "" : " (draft — " + esc(g.blockedReason || "unsupported") + ")"}</td>
        <td><span class="badge ${g.proofMode === "consensus" ? "tier-prod" : g.proofMode === "credential" ? "tier-testnet" : "tier-dev"}">${g.proofMode === "consensus" ? "production" : g.proofMode === "credential" ? "testnet" : "dev"}</span></td>
        <td>${g.sessionTtlOverrideSecs ? humanTtl(g.sessionTtlOverrideSecs) : "default"}</td>
        <td>${esc(g.useMode === "both" ? "site + Telegram" : g.useMode === "telegram" ? "Telegram only" : "site only")}</td>
        <td class="mono">${esc((g.grants || []).join(", ")) || "—"}</td>
        <td>${g.publishedVersion ? `<span class="published">published v${g.publishedVersion}</span>` : '<span class="draft">draft</span>'} ${g.enabled ? '<span class="badge enabled">enabled</span>' : ""} ${g.testLane ? '<span class="badge test">test lane</span>' : ""}</td>
        <td></td>`;
      table.append(tr);
    }
    card.append(table);

    // Gate editor (add / rename / reorder / remove).
    if (app.ownedByYou) {
      const editor = document.createElement("div");
      editor.className = "stacked";
      const componentField = editorField(app, "gate-component", "Gate component address (component_…)");
      editor.append(
        editorField(app, "gate-id", "Gate ID (stable, unique)"),
        editorField(app, "gate-name", "Display name"),
        editorField(app, "gate-resource", "Resource address (resource_…)"),
        editorField(app, "gate-symbol", "Symbol (display only)"),
        editorField(app, "gate-div", "Divisibility"),
        editorField(app, "gate-amount", "Human amount (e.g. 10 or 100000)"),
        componentField,
      );
      const componentNote = document.createElement("small");
      componentNote.className = "field-note";
      componentNote.textContent = "Credential gates verify off-chain and do not use a component.";
      componentNote.style.display = "none";
      componentField.append(componentNote);
      const mode = document.createElement("label");
      mode.textContent = "Proof mode";
      const sel = document.createElement("select");
      sel.innerHTML = `<option value="consensus">Consensus (wallet daemon)</option><option value="credential">Credential (browser wallet)</option><option value="xtm">Native L1 XTM (draft only — cannot activate yet)</option>`;
      sel.id = `mode-${app.applicationId}`;
      const updateComponentVisibility = () => {
        const isCredential = sel.value === "credential";
        const input = componentField.querySelector("input");
        if (input) { input.disabled = isCredential; if (isCredential) input.value = ""; }
        componentNote.style.display = isCredential ? "" : "none";
      };
      sel.addEventListener("change", updateComponentVisibility);
      mode.append(sel);
      editor.append(mode);
      updateComponentVisibility();
      const challengeDomain = editorField(app, "challenge-domain", "Relying-site / challenge domain");
      const challengeInput = challengeDomain.querySelector("input");
      challengeInput.value = app.gates[0]?.challengeDomain || `${app.applicationId}.localhost`;
      challengeInput.placeholder = "private-app.localhost or https://host.example";
      const challengeNote = document.createElement("small");
      challengeNote.className = "field-note";
      challengeNote.textContent = "Published exactly: use *.localhost for private local use, or the exact lowercase HTTPS origin for hosted access.";
      challengeDomain.append(challengeNote);
      editor.append(challengeDomain);
      const ttlSel = document.createElement("label");
      ttlSel.textContent = "Session override";
      const ts = document.createElement("select");
      ts.innerHTML = `<option value="">default</option><option value="3600">1 hour</option><option value="43200">12 hours</option><option value="86400">1 day</option><option value="259200">3 days</option><option value="604800">7 days</option><option value="1209600">14 days</option><option value="2592000">30 days</option>`;
      ts.id = `ttl-${app.applicationId}`;
      ttlSel.append(ts);
      editor.append(ttlSel);
      const grantsLabel = document.createElement("label");
      grantsLabel.textContent = "Grants (lower tiers this gate opens, comma-separated — hierarchical apps only)";
      const gi = document.createElement("input");
      gi.id = `grants-${app.applicationId}`;
      grantsLabel.append(gi);
      editor.append(grantsLabel);
      const testLane = document.createElement("label");
      const tlc = document.createElement("input");
      tlc.type = "checkbox";
      tlc.id = `testlane-${app.applicationId}`;
      testLane.append(tlc, "Test lane (never authorises production sessions)");
      editor.append(testLane);
      // Which surface this gate may authorize. A token policy is not a front door: the same
      // threshold can be enforced on the website and deliberately not used for Telegram invites.
      const scopeLabel = document.createElement("label");
      scopeLabel.textContent = "Where this gate may be used";
      const scope = document.createElement("select");
      scope.id = `scope-${app.applicationId}`;
      scope.innerHTML =
        '<option value="website">Website only</option>' +
        '<option value="telegram">Telegram membership only</option>' +
        '<option value="both">Website and Telegram</option>';
      scopeLabel.append(scope);
      editor.append(scopeLabel);
      // Tier wiring: a checkbox per other gate in this application. Save writes the whole gate back
      // with the chosen grant set — an explicit, auditable action rather than a hidden side effect.
      const tiers = document.createElement("div");
      tiers.className = "stacked";
      const tiersLabel = document.createElement("label");
      tiersLabel.textContent = "Tiers — which gates this gate opens (save immediately after changing)";
      tiers.append(tiersLabel);
      if (app.gates.length === 0) {
        const none = document.createElement("p");
        none.className = "hint";
        none.textContent = "No gates yet — add the gates first, then wire the tiers.";
        tiers.append(none);
      }
      for (const g of app.gates) {
        // A per-gate row of "opens this other gate" checkboxes; each change saves immediately.
        const row = document.createElement("label");
        row.className = "tier-row";
        row.textContent = `${g.gateId} opens:`;
        for (const target of app.gates) {
          if (target.gateId === g.gateId) continue;
          const lbl = document.createElement("label");
          lbl.className = "tier-check";
          const box = document.createElement("input");
          box.type = "checkbox";
          box.checked = (g.grants || []).includes(target.gateId);
          box.onchange = () => wireTiers(app, g.gateId, box);
          lbl.append(box, ` ${target.gateId}`);
          row.append(lbl);
        }
        tiers.append(row);
      }
      editor.append(tiers);
      // Pre-populate the editor from the first existing gate so edits work without re-typing.
      if (app.gates.length > 0) {
        const g = app.gates[0];
        // The editor has not been appended to #apps-list yet. Query within the detached editor,
        // rather than through document.getElementById(), so every existing-gate field is filled
        // after a save/refresh. (The relying-site input already has a direct reference above.)
        const s = (id, v) => {
          const el = editor.querySelector(`#${CSS.escape(id)}`);
          if (el && v != null) el.value = String(v);
        };
        s(`gate-id-${app.applicationId}`, g.gateId);
        s(`gate-name-${app.applicationId}`, g.name);
        s(`gate-resource-${app.applicationId}`, g.resourceAddress);
        s(`gate-symbol-${app.applicationId}`, g.symbol);
        s(`gate-div-${app.applicationId}`, g.divisibility);
        // Do not use Number here: token amounts are u128 raw units.  ghostFormat is the
        // dashboard's exact BigInt formatter, so an existing published gate can be rendered
        // without rounding or throwing before the card is appended to the page.
        s(`gate-amount-${app.applicationId}`, ghostFormat(g.thresholdRaw, g.divisibility));
        s(`gate-component-${app.applicationId}`, g.componentAddress || "");
        s(`mode-${app.applicationId}`, g.proofMode);
        s(`ttl-${app.applicationId}`, g.sessionTtlOverrideSecs || "");
        s(`grants-${app.applicationId}`, (g.grants || []).join(", "));
        s(`scope-${app.applicationId}`, g.useMode || "website");
        const tlc2 = $(`testlane-${app.applicationId}`);
        if (tlc2) tlc2.checked = !!g.testLane;
        updateComponentVisibility();
      }
      const buttons = document.createElement("div");
      buttons.className = "gate-actions";
      const add = document.createElement("button");
      add.className = "btn primary";
      add.textContent = app.gates.length > 0 ? "Save gate" : "Add gate";
      add.onclick = () => addGate(app);
      const publish = document.createElement("button");
      publish.className = "btn";
      publish.textContent = "Publish gate";
      publish.onclick = () => publishGate(app);
      const remove = document.createElement("button");
      remove.className = "btn ghost";
      remove.textContent = "Remove a gate";
      remove.onclick = () => removeGate(app);
      const reorder = document.createElement("button");
      reorder.className = "btn ghost";
      reorder.textContent = "Reorder (save current table order)";
      reorder.onclick = () => reorderGates(app);
      const deleteApp = document.createElement("button");
      deleteApp.className = "btn ghost";
      deleteApp.style.cssText = "color:#c00;border-color:#c00";
      deleteApp.textContent = "Delete application";
      deleteApp.onclick = async () => {
        if (!confirm(`Permanently delete "${app.applicationId}" and all its gates? This cannot be undone.`)) return;
        const r = await api("/admin/api/app/delete", { mutating: true, body: JSON.stringify({ applicationId: app.applicationId }) });
        if (r.status === 200) { await refresh(); set(`Application ${app.applicationId} deleted.`); }
        else set(r.json.error || String(r.status), true);
      };
      buttons.append(add, publish, remove, reorder, deleteApp);
      editor.append(buttons);
      const msg = document.createElement("p");
      msg.className = "hint";
      msg.id = `msg-${app.applicationId}`;
      editor.append(msg);
      card.append(editor);
    }
    host.append(card);
  }
}

function editorField(app, key, label) {
  const l = document.createElement("label");
  l.textContent = label;
  const i = document.createElement("input");
  i.id = `${key}-${app.applicationId}`;
  l.append(i);
  return l;
}

function humanTtl(secs) {
  const h = secs / 3600;
  if (h < 24) return `${h} hour${h === 1 ? "" : "s"}`;
  const d = h / 24;
  return `${d} day${d === 1 ? "" : "s"}`;
}
function short(s, n) { return String(s).length > n ? String(s).slice(0, n) + "…" : s; }
// Everything an operator typed (gate names, ids, addresses, reasons) comes back out of the API as
// data and goes into these tables. It is escaped at the point of insertion: a gate named
// `<img onerror=...>` must render as those characters, not execute.
function esc(v) {
  return String(v === undefined || v === null ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function ghostFormat(raw, div) {
  // Exact display: strings only, no floats.
  const rawStr = String(raw);
  if (!div) return rawStr;
  const scale = 10n ** BigInt(div);
  const bi = BigInt(rawStr);
  const int = bi / scale;
  let frac = (bi % scale).toString().padStart(div, "0").replace(/0+$/, "");
  return frac ? `${int}.${frac}` : int.toString();
}

/* ------------------------------ actions ------------------------------ */
async function addGate(app) {
  const div = Number($(`gate-div-${app.applicationId}`).value || "6");
  const amount = $(`gate-amount-${app.applicationId}`).value.trim();
  const id = $(`gate-id-${app.applicationId}`).value.trim();
  const mode = $(`mode-${app.applicationId}`).value;
  const isDraft = mode === "xtm";
  // Exact conversion happens on the server; we send the human amount AND let the server compute
  // the raw units, so no dashboard float arithmetic can ever be authoritative.
  const conv = await api("/admin/api/convert", { body: JSON.stringify({ amount, divisibility: div }) });
  if (conv.status !== 200 || conv.json.raw === undefined) {
    fail(`msg-${app.applicationId}`, conv.json.error || "the amount is not representable exactly");
    return;
  }
  const gate = {
    gateId: id,
    name: $(`gate-name-${app.applicationId}`).value.trim() || id,
    resourceAddress: $(`gate-resource-${app.applicationId}`).value.trim(),
    symbol: $(`gate-symbol-${app.applicationId}`).value.trim() || "tTARI",
    divisibility: div,
    thresholdRaw: String(conv.json.raw), // a STRING: exact, no float rounding
    proofMode: mode,
    challengeDomain: $(`challenge-domain-${app.applicationId}`).value.trim(),
    sessionTtlOverrideSecs: $(`ttl-${app.applicationId}`).value ? Number($(`ttl-${app.applicationId}`).value) : null,
    // Grants are wired by the tier editor below, not here: a gate that opens a tier which does not
    // exist yet is refused by the server (correctly), so adding gates one at a time must not have to
    // pre-declare the hierarchy. The field is still honoured for gates that DO exist.
    grants: $(`grants-${app.applicationId}`).value.split(",").map((x) => x.trim()).filter((id) => app.gates.some((g) => g.gateId === id)),
    enabled: !isDraft,
    testLane: $(`testlane-${app.applicationId}`).checked,
    useMode: $(`scope-${app.applicationId}`).value,
    componentAddress: $(`gate-component-${app.applicationId}`).value.trim() || null,
  };
  const r = await api("/admin/api/gate/set", { mutating: true, body: JSON.stringify({ applicationId: app.applicationId, gate }) });
  if (r.status === 200) { await refresh(); appMsg(app, `Gate ${id} saved.`); }
  else appMsg(app, r.json.error || String(r.status), true);
}

/// Write a gate back with a new grant set. The server validates the whole app after the change, so
/// an unknown target is refused rather than half-applied.
async function wireTiers(app, gateId, box) {
  const card = document.querySelector(`#apps-list .gate-card[data-app="${CSS.escape(app.applicationId)}"]`);
  if (!card) return;
  const grants = [...card.querySelectorAll(".tier-check input[type=checkbox]")]
    .filter((b) => b.checked)
    .map((b) => b.parentElement.textContent.trim());
  const gate = app.gates.find((g) => g.gateId === gateId);
  if (!gate) return;
  const r = await api("/admin/api/gate/set", {
    mutating: true,
    body: JSON.stringify({
      applicationId: app.applicationId,
      gate: {
        gateId: gate.gateId,
        name: gate.name,
        resourceAddress: gate.resourceAddress,
        symbol: gate.symbol,
        divisibility: gate.divisibility,
        thresholdRaw: String(gate.thresholdRaw),
        proofMode: gate.proofMode,
        challengeDomain: gate.challengeDomain,
        sessionTtlOverrideSecs: gate.sessionTtlOverrideSecs || null,
        grants,
        enabled: gate.enabled,
        testLane: gate.testLane,
        useMode: gate.useMode || "website",
        componentAddress: gate.componentAddress || null,
      },
    }),
  });
  if (r.status === 200) { await refresh(); appMsg(app, `${gateId} tiers saved.`); }
  else { appMsg(app, r.json.error || String(r.status), true); await refresh(); }
}

async function publishGate(app) {
  const gateId = $(`gate-id-${app.applicationId}`).value.trim();
  if (!gateId) { fail(`msg-${app.applicationId}`, "Type the gate id to publish."); return; }
  const r = await api("/admin/api/policy/publish", { mutating: true, body: JSON.stringify({ applicationId: app.applicationId, gateId, reason: "published from the dashboard" }) });
  if (r.status === 200) { await refresh(); appMsg(app, `Published ${gateId}. The bridge picks it up on the next request.`); }
  else appMsg(app, r.json.error || String(r.status), true);
}

async function removeGate(app) {
  const gateId = $(`gate-id-${app.applicationId}`).value.trim();
  if (!gateId) { fail(`msg-${app.applicationId}`, "Type the gate id to remove."); return; }
  const r = await api("/admin/api/gate/remove", { mutating: true, body: JSON.stringify({ applicationId: app.applicationId, gateId }) });
  if (r.status === 200) { await refresh(); appMsg(app, `Removed ${gateId}.`); }
  else appMsg(app, r.json.error || String(r.status), true);
}

async function reorderGates(app) {
  // Read the order from THIS application's table only. (Collecting across every card would send
  // another application's gate ids, and the server would rightly refuse.) Row order is the operator's
  // displayed order — the table here is rendered in the server's order, so a move means: take the
  // gate named in the field and move it to the position the prompt asks for.
  const card = document.querySelector(`#apps-list .gate-card[data-app="${CSS.escape(app.applicationId)}"]`);
  const rows = card ? [...card.querySelectorAll("table tr[data-gate-id]")] : [];
  const current = rows.map((r) => r.dataset.gateId);
  const gateId = $(`gate-id-${app.applicationId}`).value.trim();
  if (!gateId || !current.includes(gateId)) {
    fail(`msg-${app.applicationId}`, "Type the id of a gate in THIS application to move.");
    return;
  }
  const target = rows.findIndex((r) => r.dataset.gateId === gateId);
  const dir = window.prompt(`Move "${gateId}" to which position (1..${current.length})?`, String(target + 1));
  if (dir === null) return;
  const index = Math.max(0, Math.min(current.length - 1, Number(dir) - 1));
  const mine = current.slice();
  mine.splice(target, 1);
  mine.splice(index, 0, gateId);
  const r = await api("/admin/api/gate/reorder", { mutating: true, body: JSON.stringify({ applicationId: app.applicationId, order: mine }) });
  if (r.status === 200) { await refresh(); appMsg(app, "Order saved (cosmetic — order never grants anything)."); }
  else appMsg(app, r.json.error || String(r.status), true);
}

// Returns the /admin/api/state reply so callers can branch on what the SERVER now says (the
// step-up flow must re-read state, not trust its own memory of the window).
async function refresh() {
  const s = await api("/admin/api/state");
  if (s.status === 200) enterDashboard(s.json);
  return s;
}

/* ------------------------------ sessions & audit ------------------------------ */
function renderSessions(state) {
  const host = $("sessions-list");
  host.replaceChildren();
  if (!state.sessions.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "No verified sessions yet.";
    host.append(p);
    return;
  }
  const table = document.createElement("table");
  table.innerHTML = "<tr><th>Token</th><th>App</th><th>Proven gate</th><th>Achieved tier</th><th>Grants</th><th>Expires</th><th>State</th><th></th></tr>";
  for (const s of state.sessions) {
    const tr = document.createElement("tr");
    // The tier this session ACTUALLY achieved from its verified evidence — not a gate's maximum
    // supported tier. A development-tier session authorises nothing, so it is flagged plainly.
    const tier = s.trustTier || "development";
    const tierClass = tier === "production" ? "tier-prod" : tier === "operator-trusted-testnet" ? "tier-testnet" : "tier-dev";
    const tierLabel = tier === "production" ? "production" : tier === "operator-trusted-testnet" ? "testnet" : "dev — no access";
    tr.innerHTML = `
      <td class="mono">${esc(s.tokenPrefix)}…</td>
      <td class="mono">${esc(s.applicationId)}</td>
      <td>${esc(s.provenGate)}</td>
      <td><span class="badge ${tierClass}" title="${esc(s.evidenceKind || "none")}">${tierLabel}</span></td>
      <td class="mono">${esc((s.granted || []).join(", "))}</td>
      <td>${new Date(s.expiresUnix * 1000).toLocaleString()}</td>
      <td>${s.revoked ? '<span class="bad">revoked</span>' : Date.now() / 1000 > s.expiresUnix ? '<span class="bad">expired</span>' : '<span class="ok">live</span>'}</td>
      <td></td>`;
    if (!s.revoked) {
      const btn = document.createElement("button");
      btn.className = "btn small ghost";
      btn.textContent = "Revoke";
      btn.onclick = async () => {
        const r = await api("/admin/api/session/revoke", { mutating: true, body: JSON.stringify({ tokenPrefix: s.tokenPrefix, reason: "revoked from the dashboard" }) });
        set(r.status === 200 ? "Revoked. The bridge honours it on the next check." : r.json.error || String(r.status));
        await refresh();
      };
      tr.lastChild.append(btn);
    }
    table.append(tr);
  }
  host.append(table);
}

async function renderAudit() {
  const a = await api("/admin/api/audit");
  const host = $("audit-list");
  host.replaceChildren();
  const table = document.createElement("table");
  table.innerHTML = "<tr><th>When</th><th>Actor</th><th>Action</th><th>App/Gate</th><th>Versions</th><th>Outcome</th><th>Detail</th></tr>";
  for (const e of (a.json.tail || [])) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${new Date(e.unix * 1000).toLocaleString()}</td>
      <td class="mono">${esc(short(e.actor, 20))}</td>
      <td>${esc(e.action)}</td>
      <td class="mono">${esc(e.applicationId || "—")}${e.gate_id ? "/" + esc(e.gate_id) : ""}</td>
      <td class="mono">${e.old_version != null ? "v" + e.old_version + " → " : ""}${e.new_version != null ? "v" + e.new_version : ""}</td>
      <td>${e.outcome === "Accepted" ? '<span class="ok">accepted</span>' : '<span class="bad">refused</span>'}</td>
      <td class="hint">${esc(e.detail)}</td>`;
    table.append(tr);
  }
  host.append(table);
}

/* ------------------------------ wire-up ------------------------------ */
$("btn-new-app").onclick = () => { $("new-app-form").hidden = !$("new-app-form").hidden; };
$("new-app-go").onclick = async () => {
  const r = await api("/admin/api/app/create", { mutating: true, body: JSON.stringify({
    applicationId: $("new-app-id").value.trim(),
    displayName: $("new-app-name").value.trim() || $("new-app-id").value.trim(),
    topology: $("new-app-topology").value,
    defaultSessionTtl: Number($("new-app-ttl").value),
    production: $("new-app-production").value === "true",
    network: $("new-app-network").value,
    genesisHash: $("new-app-genesis").value.trim(),
  })});
  if (r.status === 200) { await refresh(); set(`Application ${r.json.created} created.`); }
  else set(r.json.error || String(r.status), true);
};
/* ------------------------------ step-up ------------------------------ */
// The method to step up with is the SERVER's knowledge about the signed-in credential (the actor),
// never a guess: a wallet-prefixed actor signs a wallet challenge, a passkey-prefixed actor runs
// the same WebAuthn ceremony sign-in runs. The dashboard carries no authority of its own either
// way; the server always re-verifies the ceremony and refreshes the window.
function actorKind() {
  if (!actor) return null;
  if (actor.startsWith("passkey:")) return "passkey";
  if (actor.startsWith("wallet:")) return "wallet";
  return null;
}

// Step-up is server-authoritative: after the ceremony we re-read /admin/api/state and render what
// the SERVER says about the window, rather than trusting the login reply.
async function applyStepupResult(r) {
  if (r.status !== 200) {
    set(`Step-up refused: ${r.json.error || String(r.status)} — policy changes stay locked.`);
    await refresh();
    return;
  }
  const s = await refresh();
  if (s.status !== 200) { set("Step-up accepted, but the dashboard could not re-read its state."); return; }
  set(stepupValid
    ? "Step-up accepted: fresh approval is in force; policy changes are allowed."
    : "The step-up ceremony was accepted but the fresh-approval window is not open.");
}

async function passkeyStepup() {
  const c = await api("/admin/api/auth/challenge", { body: JSON.stringify({ kind: "login", method: "passkey" }) });
  if (c.status !== 200) { set(`Step-up refused: ${c.json.error || String(c.status)}`); return; }
  // Exactly the flow the sign-in button uses (passkeyLogin), plus stepup: true. The server
  // requires user verification (Windows Hello) for a step-up and refuses without it.
  const payload = await passkeyLogin(c.json.challenge, c.json.allowCredentials);
  const r = await api("/admin/api/auth/login", { body: JSON.stringify({ ...payload, stepup: true }) });
  await applyStepupResult(r);
}

async function walletStepup() {
  const c = await api("/admin/api/auth/challenge", { body: JSON.stringify({ kind: "login", method: "wallet" }) });
  const sig = window.prompt(
    "Step-up: sign this challenge with your registered wallet key and paste the signature hex.\n" +
    "Challenge: " + c.json.challenge, "");
  if (!sig) return;
  const pk = window.prompt("Your registered public key hex:", "");
  if (!pk) return;
  const r = await api("/admin/api/auth/login", { body: JSON.stringify({
    method: "wallet", challenge: c.json.challenge, publicKey: pk.trim(),
    signature: sig.trim(), publicNonce: window.prompt("Public nonce hex:", "") || "",
    stepup: true,
  })});
  await applyStepupResult(r);
}

$("btn-stepup").onclick = async () => {
  // Choose the ceremony from the signed-in credential's kind. If the actor is not loaded yet (e.g.
  // immediately after a login with no page reload), re-read state first: a passkey administrator
  // must never silently fall back to the wallet-key step-up path just because the actor was unknown.
  if (!actorKind()) { await refresh(); }
  const kind = actorKind();
  if (kind === "passkey") {
    try {
      await passkeyStepup();
    } catch (e) {
      if (/NotAllowedError/i.test(String(e))) {
        // The user dismissed Windows Hello (or it timed out): a normal, non-failure outcome.
        set("Step-up cancelled before Windows Hello completed — policy changes stay locked until you step up.");
        return;
      }
      // The same translation the sign-in button gives for an unusable RP ID.
      const msg = /invalid domain|SecurityError/i.test(String(e))
        ? "The passkey ceremony did not complete. If the dashboard address is not a domain, passkeys " +
          "cannot run at all — open it through GG_ADMIN_HOSTNAME=localhost (or your domain) and sign in again."
        : String(e);
      set(`Step-up refused: ${msg} — policy changes stay locked.`);
      await refresh();
    }
    return;
  }
  await walletStepup();
};
$("btn-logout").onclick = async () => {
  await api("/admin/api/auth/logout", { mutating: true, body: "{}" });
  location.reload();
};

/* Passkey flows */
$("reg-passkey").onclick = async () => {
  clearFail("bootstrap-error");
  const c = await api("/admin/api/auth/challenge", { body: JSON.stringify({ kind: "register", method: "passkey" }) });
  try {
    const payload = await passkeyRegister(c.json.challenge);
    payload.label = $("reg-label").value || "admin";
    payload.bootstrapToken = $("bootstrap-token").value;
    const r = await api("/admin/api/auth/register", { body: JSON.stringify(payload) });
    if (r.status === 200) { csrf = r.json.csrf; await refresh(); }
    else fail("bootstrap-error", r.json.error || String(r.status));
  } catch (e) {
    // A WebAuthn SecurityError usually means the RP ID is not a registrable domain (an IP address).
    // Translate it, because "invalid domain" tells a non-technical operator nothing actionable.
    const msg = /invalid domain|SecurityError/i.test(String(e))
      ? "This browser refused the passkey ceremony: the relying party must be a domain, not an IP address. Use the wallet-key method, or open the dashboard through GG_ADMIN_HOSTNAME."
      : String(e);
    fail("bootstrap-error", msg);
  }
};
$("login-passkey").onclick = async () => {
  clearFail("login-error");
  const c = await api("/admin/api/auth/challenge", { body: JSON.stringify({ kind: "login", method: "passkey" }) });
  try {
    const payload = await passkeyLogin(c.json.challenge, c.json.allowCredentials);
    const r = await api("/admin/api/auth/login", { body: JSON.stringify(payload) });
    if (r.status === 200) { csrf = r.json.csrf; await refresh(); }
    else fail("login-error", r.json.error || String(r.status));
  } catch (e) {
    const msg = /invalid domain|SecurityError/i.test(String(e))
      ? "This browser refused the passkey ceremony: the relying party must be a domain, not an IP address. Use the wallet-key method, or open the dashboard through GG_ADMIN_HOSTNAME."
      : String(e);
    fail("login-error", msg);
  }
};

/* Wallet flows (the dashboard collects the signature; the SERVER verifies it). */
$("reg-wallet").onclick = () => { $("wallet-register").hidden = !$("wallet-register").hidden; };
$("wallet-register-go").onclick = async () => {
  const c = await api("/admin/api/auth/challenge", { body: JSON.stringify({ kind: "register", method: "wallet" }) });
  const r = await api("/admin/api/auth/register", { body: JSON.stringify({
    method: "wallet", challenge: c.json.challenge,
    publicKey: $("wallet-pk").value.trim(),
    signature: $("wallet-sig").value.trim(),
    publicNonce: window.prompt("Public nonce hex:", "") || "",
    label: $("reg-label").value || "admin",
    bootstrapToken: $("bootstrap-token").value,
  })});
  if (r.status === 200) { csrf = r.json.csrf; await refresh(); }
  else fail("bootstrap-error", r.json.error || String(r.status));
};
$("login-wallet").onclick = () => { $("wallet-login").hidden = !$("wallet-login").hidden; };
$("wallet-login-go").onclick = async () => {
  const c = await api("/admin/api/auth/challenge", { body: JSON.stringify({ kind: "login", method: "wallet" }) });
  const r = await api("/admin/api/auth/login", { body: JSON.stringify({
    method: "wallet", challenge: c.json.challenge,
    publicKey: $("wallet-login-pk").value.trim(),
    signature: $("wallet-login-sig").value.trim(),
    publicNonce: window.prompt("Public nonce hex:", "") || "",
    stepup: false,
  })});
  if (r.status === 200) { csrf = r.json.csrf; await refresh(); }
  else fail("login-error", r.json.error || String(r.status));
};

boot();
