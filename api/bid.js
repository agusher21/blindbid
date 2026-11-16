"use strict";

/**
 * Vercel serverless entrypoint: POST /api/bid
 *
 * The raw body is required for HMAC verification, so the default Vercel
 * body parser is disabled (see `config` below) and the stream is read
 * manually. All decision logic lives in lib/http-handler.js, shared with
 * the local dev server.
 */

const { handleRequest } = require("../lib/http-handler");

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).setHeader("content-type", "application/json");
    res.send(JSON.stringify({ decision: "REJECT", reason: "method not allowed, use POST" }));
    return;
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks).toString("utf8");

  const out = await handleRequest({
    method: "POST",
    path: "/api/bid",
    rawBody,
    headers: req.headers,
    env: process.env,
  });
  res.status(out.status);
  for (const [k, v] of Object.entries(out.headersOut || {})) res.setHeader(k, v);
  res.send(JSON.stringify(out.json));
};

module.exports.config = { api: { bodyParser: false } };
