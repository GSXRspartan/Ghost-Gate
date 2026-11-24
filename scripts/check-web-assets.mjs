#!/usr/bin/env node
/**
 * Guards two regressions that previously reached the Lab silently:
 *
 *   1. duplicate top-level declarations in browser JavaScript (e.g. `const gate`
 *      declared twice in web/lab/lab.js) — caught with `node --check` per file;
 *   2. missing module assets in the served import graph (e.g. claim.js importing
 *      telegram/join-endpoints.js and telegram/trusted-url.js without the bridge
 *      serving them) — caught by serving web/ over loopback HTTP and fetching
 *      every HTML entrypoint, its script/link references and every transitive
 *      ES-module import.
 *
 * This is a smoke test, not a claim that a real wallet proof succeeded.
 */
import { createServer } from "node:http";
import { readFile, readdir, stat } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join, extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const webRoot = join(repoRoot, "web");
const scanRoots = [
  webRoot,
  join(repoRoot, "cloudflare", "src"),
  join(repoRoot, "cloudflare", "test"),
];
const skipped = new Set(["node_modules", ".git", ".wrangler", "target", "temp", "artifacts", "staging-web"]);

async function walk(dir, out = []) {
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    if (skipped.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) await walk(full, out);
    else if ([".js", ".mjs"].includes(extname(entry.name))) out.push(full);
  }
  return out;
}

function checkSyntax(file) {
  const source = readFileSync(file, "utf8");
  const result = spawnSync(process.execPath, ["--input-type=module", "--check"], {
    input: source,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(`syntax check failed for ${file}:\n${result.stderr || result.stdout}`);
  }
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".d.ts": "text/plain; charset=utf-8",
};

function staticServer() {
  const server = createServer(async (req, res) => {
    let pathname;
    try { pathname = decodeURIComponent(new URL(req.url, "http://loopback").pathname); }
    catch { res.writeHead(400).end("bad path"); return; }
    if (pathname === "/") pathname = "/index.html";
    const target = resolve(webRoot, `.${pathname}`);
    if (target !== webRoot && !target.startsWith(webRoot + sep)) {
      res.writeHead(403).end("outside web root");
      return;
    }
    let file = target;
    try {
      const info = await stat(file);
      if (info.isDirectory()) file = join(file, "index.html");
      const body = await readFile(file);
      res.writeHead(200, { "Content-Type": MIME[extname(file)] || "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404, { "Content-Type": "text/plain" }).end("not found: " + pathname);
    }
  });
  return new Promise((accept) => server.listen(0, "127.0.0.1", () => accept(server)));
}

function htmlReferences(html) {
  const found = new Set();
  const tags = /<(?:script|link)\b[^>]*>/gi;
  for (const tag of html.match(tags) || []) {
    const attr = /\b(?:src|href)\s*=\s*["']([^"']+)["']/i.exec(tag);
    if (!attr) continue;
    const value = attr[1].trim();
    if (value && !/^(?:https?:|data:|#)/i.test(value)) found.add(value);
  }
  return found;
}

function moduleImports(source) {
  const found = new Set();
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.startsWith("//") || line.startsWith("*")) continue;
    const staticImport = /^import\b(?:[^"']*?\bfrom\b\s*)?["']([^"']+)["']/.exec(line);
    if (staticImport) found.add(staticImport[1]);
    for (const match of line.matchAll(/\bimport\(\s*["']([^"']+)["']\s*\)/g)) found.add(match[1]);
  }
  return found;
}

async function main() {
  const failures = [];
  let checked = 0;

  const files = [];
  for (const root of scanRoots) await walk(root, files);
  for (const file of files) {
    try { checkSyntax(file); checked++; }
    catch (e) { failures.push(e.message); }
  }
  console.log(`PASS syntax: ${checked} JavaScript files parsed`);

  const server = await staticServer();
  const base = `http://127.0.0.1:${server.address().port}`;
  const visited = new Set();
  const errors = [];

  async function fetchAsset(pathname) {
    const url = new URL(pathname, base);
    const response = await fetch(url);
    const body = await response.text();
    if (!response.ok) errors.push(`${pathname} -> HTTP ${response.status}`);
    return { response, body };
  }

  async function visitModule(pathname) {
    if (visited.has(pathname)) return;
    visited.add(pathname);
    const { response, body } = await fetchAsset(pathname);
    if (!response.ok) return;
    for (const spec of moduleImports(body)) {
      let target;
      try { target = new URL(spec, new URL(pathname, base)).pathname; }
      catch { errors.push(`${pathname}: unresolvable import ${spec}`); continue; }
      if (!target.startsWith("/")) continue;
      await visitModule(target);
    }
  }

  const entries = ["/index.html", "/lab/", "/mainnet/", "/telegram/join"];
  const markers = {
    "/index.html": "GHOST GATE",
    "/lab/": "id=\"lab-root\"",
    "/mainnet/": "mainnet 0x00",
    "/telegram/join": "gg-trusted-bridges",
  };
  try {
    for (const entry of entries) {
      const { response, body } = await fetchAsset(entry);
      if (!response.ok) continue;
      if (!body.includes(markers[entry])) errors.push(`${entry}: expected marker missing`);
      for (const ref of htmlReferences(body)) {
        const target = new URL(ref, new URL(entry, base)).pathname;
        if (extname(target) === ".js" || extname(target) === ".mjs") await visitModule(target);
        else await fetchAsset(target);
      }
    }
  } finally {
    server.close();
  }

  console.log(`PASS smoke: ${entries.length} entry pages, ${visited.size} JS modules reachable`);
  if (errors.length) failures.push("asset/import graph:\n  " + errors.join("\n  "));
  if (failures.length) {
    console.error("FAIL\n" + failures.join("\n"));
    process.exitCode = 1;
  } else {
    console.log("PASS web-assets: no duplicate declarations, no missing imports");
  }
}

await main();
