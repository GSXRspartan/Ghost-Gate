#!/usr/bin/env node
/**
 * Local HTTPS termination proxy for the experimental GGBP-1 Lab.
 *
 * Tari Universe's embedded dApp browser requires an HTTPS origin. This proxy serves
 * https://127.0.0.1:<port> with a locally generated self-signed certificate and forwards every
 * request to the plain-HTTP Ghost Gate bridge on loopback. It is local-only: it binds 127.0.0.1
 * and exists so the embedded browser can reach the non-authorizing GGBP-1 test page.
 *
 * Usage:
 *   node scripts/ggbp1-https-proxy.js --port 7443 --target http://127.0.0.1:7801 \
 *        --cert <pem> --key <pem>
 */
"use strict";

const https = require("https");
const http = require("http");
const fs = require("fs");

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const port = parseInt(arg("port", "7443"), 10);
const target = new URL(arg("target", "http://127.0.0.1:7801"));
const certPath = arg("cert", "");
const keyPath = arg("key", "");

if (!certPath || !keyPath) {
  console.error("ggbp1-https-proxy: --cert and --key are required");
  process.exit(1);
}
let tls;
try {
  tls = { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) };
} catch (e) {
  console.error(`ggbp1-https-proxy: cannot read certificate: ${e.message}`);
  process.exit(1);
}

const server = https.createServer(tls, (req, res) => {
  const upstream = http.request(
    {
      hostname: target.hostname,
      port: target.port,
      path: req.url,
      method: req.method,
      headers: { ...req.headers, host: `${target.hostname}:${target.port}` },
    },
    (up) => {
      res.writeHead(up.statusCode, up.headers);
      up.pipe(res);
    },
  );
  upstream.on("error", (e) => {
    if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(`GG: GGBP-1 HTTPS proxy could not reach the bridge: ${e.message}`);
  });
  req.pipe(upstream);
});

server.listen(port, "127.0.0.1", () => {
  console.log(`GGBP-1 HTTPS lab on https://127.0.0.1:${port}/lab -> ${target.origin} (local only)`);
});
