import { backendState, canonical } from "./backend-state.js";
import { json } from "./contracts.js";

const encoder = new TextEncoder();

async function sha256(value) {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function validText(value, maximum = 512) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function publicRecord(row) {
  return {
    backendState: row.backend_state ? JSON.parse(row.backend_state) : null,
    nonce: row.nonce, tenant: row.tenant, gateId: row.gate_id, relyingSite: row.relying_site,
    network: row.network, resourceAddress: row.resource_address, thresholdRaw: row.threshold_raw,
    policyVersion: row.policy_version, expiresUnix: row.expires_unix, state: row.state,
    proofJobId: row.proof_job_id, authorizationId: row.authorization_id,
    sessionExpiresUnix: row.session_expires_unix || null, revoked: Boolean(row.revoked),
  };
}

/**
 * One modern SQLite-backed Durable Object per tenant/gate/nonce. The Worker is its sole caller.
 * The DO, not D1 and not a Rust process, owns hosted replay and session transitions. Browser
 * secrets are compared as hashes and never appear in response payloads or logs.
 */
export class ReplayCoordinator {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    // `sql.exec` is the SQLite API for new Durable Objects. DDL is idempotent, which makes
    // object eviction/reconstruction safe and keeps v1 records forward-migratable.
    this.state.storage.sql.exec(`CREATE TABLE IF NOT EXISTS replay_records (
      nonce TEXT PRIMARY KEY, tenant TEXT NOT NULL, gate_id TEXT NOT NULL, relying_site TEXT NOT NULL,
      visitor_session_hash TEXT NOT NULL, network INTEGER NOT NULL, resource_address TEXT NOT NULL,
      threshold_raw TEXT NOT NULL, policy_version TEXT NOT NULL, expires_unix INTEGER NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('issued', 'submitted', 'authorized', 'revoked')),
      proof_job_id TEXT, verification_id TEXT, proof_digest TEXT, authorization_id TEXT,
      access_token_hash TEXT, session_expires_unix INTEGER, revoked INTEGER NOT NULL DEFAULT 0,
      created_unix INTEGER NOT NULL, updated_unix INTEGER NOT NULL
    )`);
    if (![...this.state.storage.sql.exec("PRAGMA table_info(replay_records)")].some(c => c.name === "backend_state")) {
      this.state.storage.sql.exec("ALTER TABLE replay_records ADD COLUMN backend_state TEXT");
    }
  }

  authorized(request) {
    return Boolean(this.env.GG_COORDINATOR_TOKEN)
      && request.headers.get("authorization") === `Bearer ${this.env.GG_COORDINATOR_TOKEN}`;
  }

  row() {
    return [...this.state.storage.sql.exec("SELECT * FROM replay_records LIMIT 1")][0] || null;
  }

  bindingMatches(row, body, visitorHash) {
    return row.tenant === body.tenant && row.gate_id === body.gateId
      && row.relying_site === body.relyingSite && row.network === body.network
      && row.resource_address === body.resourceAddress && row.threshold_raw === body.thresholdRaw
      && row.policy_version === body.policyVersion && row.visitor_session_hash === visitorHash;
  }

  async fetch(request) {
    if (!this.authorized(request)) return json(403, { error: "GG: coordinator caller is not authorized" });
    let body;
    try { body = await request.json(); } catch { return json(400, { error: "GG: invalid coordinator body" }); }
    if (!validText(body?.visitorSession, 256)) return json(400, { error: "GG: visitor session is missing" });
    const visitorHash = await sha256(body.visitorSession);
    // Complete all asynchronous work before reading the row and making a state transition.
    const tokenHash = validText(body?.sessionToken, 256) ? await sha256(body.sessionToken) : null;
    const action = new URL(request.url).pathname.split("/").filter(Boolean).pop();
    let current;
    try { current = await backendState(this.env, body); }
    catch { return json(503, { authorized: false, error: "GG: fresh backend authorization required" }); }
    const now = Math.floor(Date.now() / 1000);
    const row = this.row();
    if (row && (!row.backend_state || canonical(current) !== row.backend_state)) {
      // Permanent retirement, including a halt revision observed after manual recovery.
      this.state.storage.sql.exec("UPDATE replay_records SET revoked=1, state='revoked' WHERE nonce=?", row.nonce);
      return json(409, { authorized: false, error: "GG: backend authorization changed; fresh proof required" });
    }

    if (action === "issue") {
      if (row) return json(409, { error: "GG: replay identity already exists" });
      if (!validText(body?.nonce, 128) || !validText(body?.tenant) || !validText(body?.gateId)
        || !validText(body?.relyingSite) || !validText(body?.resourceAddress) || !validText(body?.thresholdRaw)
        || !validText(body?.policyVersion) || !Number.isInteger(body?.network)
        || !Number.isInteger(body?.expiresUnix) || body.expiresUnix <= now) {
        return json(400, { error: "GG: incomplete server-created replay binding" });
      }
      this.state.storage.sql.exec(`INSERT INTO replay_records
        (nonce,tenant,gate_id,relying_site,visitor_session_hash,network,resource_address,threshold_raw,policy_version,expires_unix,state,revoked,created_unix,updated_unix)
        VALUES (?,?,?,?,?,?,?,?,?,?, 'issued', 0, ?, ?)`,
        body.nonce, body.tenant, body.gateId, body.relyingSite, visitorHash, body.network,
        body.resourceAddress, body.thresholdRaw, body.policyVersion, body.expiresUnix, now, now);
      this.state.storage.sql.exec("UPDATE replay_records SET backend_state=? WHERE nonce=?", canonical(current), body.nonce);
      return json(201, { state: "issued", nonce: body.nonce, expiresUnix: body.expiresUnix });
    }

    if (!row) return json(404, { error: "GG: replay identity is unknown" });
    if (!this.bindingMatches(row, body, visitorHash)) return json(409, { error: "GG: challenge binding mismatch" });
    if (row.expires_unix <= now && action !== "access" && action !== "revoke") return json(409, { error: "GG: challenge has expired" });

    if (action === "reserve") {
      if (!validText(body?.proofJobId, 128) || !/^[0-9a-f]{64}$/i.test(body?.proofDigest || "")) {
        return json(400, { error: "GG: proof job identity or digest is missing" });
      }
      if (row.state === "issued") {
        this.state.storage.sql.exec("UPDATE replay_records SET state='submitted', proof_job_id=?, proof_digest=?, updated_unix=? WHERE nonce=? AND state='issued'", body.proofJobId, body.proofDigest, now, row.nonce);
        return json(200, { state: "reserved", proofJobId: body.proofJobId, challenge: publicRecord({ ...row, state: "submitted", proof_job_id: body.proofJobId, proof_digest: body.proofDigest }) });
      }
      if (row.state === "submitted" && row.proof_digest === body.proofDigest) {
        // The job identity is durable. Retrying the *same* browser evidence is safe after a
        // Worker/verifier timeout, and deterministic verifier identities make authorize idempotent.
        return json(200, { state: "reserved", idempotent: true, proofJobId: row.proof_job_id, challenge: publicRecord(row) });
      }
      if (row.state === "submitted") return json(409, { error: "GG: a different proof is already reserved for this challenge" });
      return json(409, { error: "GG: challenge authorization is final" });
    }

    if (action === "release") {
      if (row.state !== "submitted" || row.proof_job_id !== body.proofJobId) return json(409, { error: "GG: submitted proof cannot be released" });
      // Only a definite verifier REJECTED result is releasable. UNKNOWN and transport failures
      // remain submitted so they cannot be turned into a duplicate wallet/on-chain proof.
      this.state.storage.sql.exec("UPDATE replay_records SET state='issued', proof_job_id=NULL, verification_id=NULL, proof_digest=NULL, updated_unix=? WHERE nonce=?", now, row.nonce);
      return json(200, { state: "issued" });
    }

    if (action === "authorize") {
      if (!validText(body?.verificationId, 256) || !validText(body?.proofDigest, 256)
        || !validText(body?.authorizationId, 256) || !validText(body?.sessionToken, 256)
        || !Number.isInteger(body?.sessionExpiresUnix) || body.sessionExpiresUnix <= now || body.sessionExpiresUnix > now + current.sessionTtlSecs) {
        return json(400, { error: "GG: incomplete verified authorization" });
      }
      if (row.state === "submitted" && row.proof_job_id === body.proofJobId && row.proof_digest === body.proofDigest) {
        this.state.storage.sql.exec(`UPDATE replay_records SET state='authorized', verification_id=?, proof_digest=?, authorization_id=?,
          access_token_hash=?, session_expires_unix=?, updated_unix=? WHERE nonce=? AND state='submitted'`,
          body.verificationId, body.proofDigest, body.authorizationId, tokenHash, body.sessionExpiresUnix, now, row.nonce);
        return json(200, { state: "authorized", authorizationId: body.authorizationId, sessionExpiresUnix: body.sessionExpiresUnix });
      }
      return json(409, { error: "GG: challenge authorization is final" });
    }

    if (action === "status") return json(200, { ...publicRecord(row), authorized: row.state === "authorized" && !row.revoked });

    if (action === "access" || action === "revoke") {
      if (!validText(body?.sessionToken, 256)) return json(401, { authorized: false, error: "GG: session is missing" });
      const live = row.state === "authorized" && !row.revoked && row.session_expires_unix > now
        && row.access_token_hash === tokenHash;
      if (action === "access") return json(live ? 200 : 401, { authorized: live, expiresUnix: live ? row.session_expires_unix : 0 });
      if (!live) return json(401, { authorized: false, error: "GG: session is not active" });
      this.state.storage.sql.exec("UPDATE replay_records SET revoked=1, state='revoked', updated_unix=? WHERE nonce=?", now, row.nonce);
      return json(200, { revoked: true });
    }
    return json(404, { error: "GG: coordinator route not found" });
  }
}
