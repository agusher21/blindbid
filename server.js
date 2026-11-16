"use strict";

/**
 * Local dev server for BlindBid.
 *
 *   npm start            -> http://localhost:3000
 *   PORT=8080 npm start  -> http://localhost:8080
 *
 * Routes:
 *   GET  /                    demo UI (public/index.html)
 *   GET  /health, /healthz    {"ok":true} liveness check
 *   GET  /api/circuit-info    circuit + verification-key fingerprint
 *   GET  /api/auction?ticket=...  auction status
 *   GET  /examples/<file>     canned payloads for the demo
 *   POST /api/auction         create an auction (returns a signed ticket)
 *   POST /api/bid             submit a sealed bid (commitment + proof)
 *   POST /api/reveal          reveal a bid (bid + salt + bid receipt)
 *   POST /api/settle          settle a closed auction from its reveals
 *
 * Environment:
 *   AGENT_SECRET       HMAC secret. When unset the server runs in DEMO MODE
 *                      (HMAC not enforced; tickets and receipts are signed
 *                      with a public demo key) — fine for the demo, never
 *                      for a registered production agent.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const { handleRequest, demoMode } = require("./lib/http-handler");
const { getCircuitInfo } = require("./lib/auction");

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "public");

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

function serveStatic(req, res) {
  let urlPath = decodeURIComponent(req.url.split("?")[0]);
  if (urlPath === "/") urlPath = "/index.html";
  const filePath = path.normalize(path.join(PUBLIC_DIR, urlPath));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "forbidden" }));
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
      return;
    }
    res.writeHead(200, { "content-type": CONTENT_TYPES[path.extname(filePath)] || "application/octet-stream" });
    res.end(data);
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    const pathname = url.pathname;
    if (req.method === "GET" && (pathname === "/health" || pathname === "/healthz")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, demoMode: demoMode(process.env) }));
      return;
    }
    if (req.method === "GET" && pathname === "/api/circuit-info") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(getCircuitInfo()));
      return;
    }
    if (
      (req.method === "POST" &&
        (pathname === "/api/auction" || pathname === "/api/bid" || pathname === "/api/reveal" || pathname === "/api/settle")) ||
      (req.method === "GET" && pathname === "/api/auction")
    ) {
      const rawBody = req.method === "POST" ? await readBody(req) : "";
      const query = Object.fromEntries(url.searchParams.entries());
      const out = await handleRequest({
        method: req.method,
        path: pathname,
        query,
        rawBody,
        headers: req.headers,
        env: process.env,
      });
      res.writeHead(out.status, out.headersOut);
      res.end(JSON.stringify(out.json));
      return;
    }
    if (req.method === "GET") {
      serveStatic(req, res);
      return;
    }
    res.writeHead(405, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "method not allowed" }));
  } catch (err) {
    // Fail closed: an unexpected error is a REJECT, never an approval.
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ decision: "REJECT", reason: `internal error: ${err.message}` }));
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`BlindBid listening on http://localhost:${PORT}`);
    // eslint-disable-next-line no-console
    console.log(
      demoMode(process.env)
        ? "DEMO MODE: AGENT_SECRET is not set, HMAC is not enforced and tickets use the public demo key. Set AGENT_SECRET for a registered agent."
        : "HMAC enforcement ON (AGENT_SECRET is set)."
    );
  });
}

// Vercel's Node.js server runtime requires the default export to be the
// server itself (a function or an http.Server), not an object wrapping it.
// Exporting { server } crashes every request with:
//   "Invalid export found in module .../server.cjs. The default export
//    must be a function or server."
module.exports = server;
