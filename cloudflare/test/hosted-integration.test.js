import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import worker from "../src/worker.js";
import { ReplayCoordinator } from "../src/replay-coordinator.js";

test("Worker + SQLite coordinator + real Rust credential verifier enforce reset and trust", { skip: !process.env.GG_HOSTED_TEST_BINARY }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "gg-wire-"));
  const rust = input => {
    writeFileSync(join(dir,"input.json"), JSON.stringify(input));
    const r = spawnSync(process.env.GG_HOSTED_TEST_BINARY, ["--exact", "server::tests::hosted_protocol_fixture", "--nocapture"], {
      env: { ...process.env, GG_HOSTED_TEST_INPUT:join(dir,"input.json"), GG_HOSTED_TEST_OUTPUT:join(dir,"output.json") }, encoding:"utf8" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    return JSON.parse(readFileSync(join(dir,"output.json"), "utf8"));
  };
  const gate = {tenant:"default", gateId:"g1", relyingSite:"https://gate.example", network:16,
    resourceAddress:"resource_" + "07".repeat(32), thresholdRaw:"10000", policyVersion:"v1"};
  // Rust fixture uses the repository's local-network binding; its byte is checked end to end.
  const env = { GG_GATE_CATALOG:JSON.stringify([gate]), GG_COORDINATOR_TOKEN:"secret", GG_VERIFIER_ORIGIN:"https://backend.example", GG_VERIFIER_TOKEN:"token", GG_VERIFIER_REQUEST_KEY:"req", GG_VERIFIER_RESPONSE_KEY:"resp" };
  const dbs = [];
  const objects = new Map();
  env.REPLAY_COORDINATOR = { idFromName:n=>n, get(id) {
    if (!objects.has(id)) {
      const db = new DatabaseSync(":memory:"); dbs.push(db);
      const sql = { exec(q,...args) {
        if (/^\s*CREATE /i.test(q)) {db.exec(q);return [];}
        const stmt=db.prepare(q);
        return /^\s*(SELECT |PRAGMA )/i.test(q) ? stmt.all(...args) : (stmt.run(...args),[]);
      }};
      objects.set(id,new ReplayCoordinator({storage:{sql}},env));
    }
    return {fetch:(url,init)=>objects.get(id).fetch(new Request(url,init))};
  }};
  const originalFetch = globalThis.fetch;
  let generation=1, halted=false, revision="", trusted=true, unavailable=false, changeAfterVerify=false;
  globalThis.fetch = async (_url,init) => {
    if(unavailable) throw Error("tunnel down");
    const r=rust({body:JSON.parse(init.body), signature:init.headers["x-gg-verifier-request-signature"],generation,halted,revision,trusted});
    if (changeAfterVerify && JSON.parse(init.body).proof.credential) { generation++; changeAfterVerify=false; }
    return new Response(r.body,{status:r.status,headers:r.headers});
  };
  const call = (action,body,cookie="__Host_gg_visitor=visitor") => worker.fetch(new Request(`https://gate.example/api/tenants/default/gates/g1/${action}`, {
    method:body === undefined ? "GET":"POST", headers:{origin:gate.relyingSite,cookie,"content-type":"application/json"}, ...(body === undefined?{}:{body:JSON.stringify(body)}) }),env);
  const issue = async () => {const r=await call("challenge",{});assert.equal(r.status,201,await r.clone().text());return (await r.json()).challenge.nonce;};
  const prove = async nonce => call("proof",{nonce,proof:rust({buildProof:nonce})});
  try {
    const nonce=await issue();
    const result=await prove(nonce); assert.equal(result.status,200,await result.clone().text());
    const cookie="__Host_gg_visitor=visitor; " + result.headers.getSetCookie().map(s=>s.split(";")[0]).join("; ");
    assert.equal((await call("protected",undefined,cookie)).status,200);
    unavailable=true; assert.equal((await call("session",undefined,cookie)).status,503);unavailable=false;
    halted=true; assert.equal((await call("session",undefined,cookie)).status,503);halted=false;revision="halt-reviewed";
    assert.equal((await call("session",undefined,cookie)).status,409);
    const pending=await issue(); generation=2;
    assert.equal((await prove(pending)).status,409);
    const fresh=await issue();const next=await prove(fresh);assert.equal(next.status,200,await next.clone().text());
    const nextCookie="__Host_gg_visitor=visitor; " + next.headers.getSetCookie().map(s=>s.split(";")[0]).join("; ");
    assert.equal((await call("revoke",{},nextCookie)).status,200);
    assert.equal((await call("session",undefined,nextCookie)).status,401);
    const racing=await issue();changeAfterVerify=true;
    assert.equal((await prove(racing)).status,409,"generation change after VERIFIED but before redemption blocks session");
    trusted=false;assert.equal((await call("challenge",{})).status,503);
  } finally {globalThis.fetch=originalFetch;for(const db of dbs)db.close();rmSync(dir,{recursive:true});}
});
