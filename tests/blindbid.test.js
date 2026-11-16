"use strict";

/**
 * End-to-end tests for the BlindBid sealed-bid auction agent.
 *
 *   npm run setup   (once — generates the circuit artifacts + examples)
 *   npm test
 *
 * Spawns the real server on a local port with a test HMAC secret, then
 * exercises every decision path over HTTP:
 *   create -> bid (valid ACCEPT; out-of-range / tampered commitment /
 *   vk substitution / fake proof / after close -> REJECT) -> reveal
 *   (valid ACCEPT; wrong salt / before close -> REJECT) -> settle
 *   (valid -> winner bob 920; duplicate bidder / tampered reveal /
 *   before close -> REJECT); bad, stale, or missing HMAC -> 401.
 *
 * The HMAC secret below is a TEST-ONLY value. It is never a production
 * secret and is safe to keep in this file.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const PORT = 3458;
const BASE = `http://127.0.0.1:${PORT}`;
const TEST_SECRET = "test-secret-for-ci-only";

const auctionLib = require(path.join(ROOT, "lib", "auction"));

let serverProc;

function hmacSign(secret, timestampSeconds, rawBody) {
  return crypto.createHmac("sha256", secret).update(`${timestampSeconds}.${rawBody}`, "utf8").digest("hex");
}

async function post(pathname, body, { sign = true, stale = false, secret = TEST_SECRET } = {}) {
  const rawBody = JSON.stringify(body);
  const headers = { "content-type": "application/json" };
  if (sign) {
    const ts = Math.floor(Date.now() / 1000) - (stale ? 3600 : 0);
    headers["x-agentgames-timestamp"] = String(ts);
    headers["x-agentgames-signature"] = hmacSign(secret, ts, rawBody);
  }
  const res = await fetch(`${BASE}${pathname}`, { method: "POST", headers, body: rawBody });
  const json = await res.json();
  return { status: res.status, json, signed: sign ? res.headers.get("x-agentgames-signature") : null };
}

function example(name) {
  return resignExample(JSON.parse(fs.readFileSync(path.join(ROOT, "public", "examples", name), "utf8")));
}

// The canned examples were generated with the public DEMO ticket key, but
// this suite runs the server with TEST_SECRET — so re-sign every ticket and
// receipt in the payload with TEST_SECRET before sending. The auction
// config, commitments, bids, salts, and proofs are untouched; only the
// signatures are re-keyed (which is exactly what the agent does at runtime).
function resignExample(obj) {
  const copy = JSON.parse(JSON.stringify(obj));
  const resign = (node) => {
    if (!node || typeof node !== "object") return;
    if (node.auction && typeof node.signature === "string") {
      // auction ticket
      node.signature = auctionLib.signTicket(TEST_SECRET, node.auction);
    } else if (
      node.bidder &&
      node.commitment &&
      Number.isInteger(node.bidAt) &&
      typeof node.signature === "string"
    ) {
      // bid receipt
      const core = { auctionId: node.auctionId, bidder: node.bidder, commitment: node.commitment, bidAt: node.bidAt };
      node.signature = auctionLib.signBidReceipt(TEST_SECRET, core);
    } else if (
      node.bidder &&
      Number.isInteger(node.bid) &&
      node.commitment &&
      typeof node.signature === "string"
    ) {
      // reveal receipt
      const core = { auctionId: node.auctionId, bidder: node.bidder, bid: node.bid, commitment: node.commitment };
      node.signature = auctionLib.signRevealReceipt(TEST_SECRET, core);
    }
    for (const v of Object.values(node)) resign(v);
  };
  resign(copy);
  return copy;
}

async function waitForHealth(timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("server did not become healthy in time");
}

before(async () => {
  serverProc = spawn("node", ["server.js"], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(PORT), AGENT_SECRET: TEST_SECRET },
    stdio: "ignore",
  });
  await waitForHealth();
});

after(() => {
  if (serverProc) serverProc.kill();
});

// A fresh live auction for the HTTP flow tests (closes 60s from now).
function liveAuction() {
  return {
    auctionId: `live-${Date.now()}`,
    item: "Test lot",
    minBid: 100,
    maxBid: 1000,
    closeAt: Date.now() + 60000,
  };
}

async function createLiveAuction() {
  const auction = liveAuction();
  const { status, json } = await post("/api/auction", auction);
  assert.equal(status, 200);
  assert.equal(json.decision, "ACCEPT");
  return json.ticket;
}

test("health + healthz + circuit-info endpoints", async () => {
  const health = await (await fetch(`${BASE}/health`)).json();
  assert.equal(health.ok, true);
  const healthz = await (await fetch(`${BASE}/healthz`)).json();
  assert.equal(healthz.ok, true);
  const info = await (await fetch(`${BASE}/api/circuit-info`)).json();
  assert.equal(info.protocol, "groth16");
  assert.equal(info.curve, "bn128");
  assert.deepEqual(info.publicSignals, ["inRange", "commitment", "minBid", "maxBid"]);
  assert.equal(typeof info.vkFingerprintSha256, "string");
  assert.equal(info.vkFingerprintSha256.length, 64);
});

test("create auction: valid -> ACCEPT with a signed ticket; invalid -> REJECT", async () => {
  const ticket = await createLiveAuction();
  assert.equal(typeof ticket.signature, "string");
  assert.equal(ticket.auction.item, "Test lot");

  const bad = await post("/api/auction", { auctionId: "x", item: "y", minBid: 1000, maxBid: 100, closeAt: Date.now() + 60000 });
  assert.equal(bad.json.decision, "REJECT");
  assert.match(bad.json.reason, /minBid must be/);

  const past = await post("/api/auction", { auctionId: "x", item: "y", minBid: 100, maxBid: 1000, closeAt: Date.now() - 1000 });
  assert.equal(past.json.decision, "REJECT");
  assert.match(past.json.reason, /closeAt must be in the future/);
});

test("auction status: open before close, rejects a tampered ticket", async () => {
  const ticket = await createLiveAuction();
  const res = await fetch(`${BASE}/api/auction?ticket=${encodeURIComponent(JSON.stringify(ticket))}`);
  const json = await res.json();
  assert.equal(res.status, 200);
  assert.equal(json.decision, "ACCEPT");
  assert.equal(json.state, "open");

  const tampered = JSON.parse(JSON.stringify(ticket));
  tampered.auction.maxBid = 2000;
  const res2 = await fetch(`${BASE}/api/auction?ticket=${encodeURIComponent(JSON.stringify(tampered))}`);
  assert.equal((await res2.json()).decision, "REJECT");
});

test("valid bid -> ACCEPT with a signed receipt, and the response is HMAC-signed", async () => {
  const { status, json, signed } = await post("/api/bid", example("bid-valid.json"));
  assert.equal(status, 200);
  assert.equal(json.decision, "ACCEPT");
  assert.equal(typeof signed, "string");
  assert.equal(json.receipt.bidder, "alice");
  assert.equal(typeof json.receipt.signature, "string");
  assert.equal(json.checks.proofVerified, true);
  assert.equal(json.checks.inRangeSignal, true);
  assert.equal(json.checks.commitmentMatch, true);
  assert.equal(json.checks.boundsMatch, true);
});

test("out-of-range bid proof (inRange=0) -> REJECT", async () => {
  const { json } = await post("/api/bid", example("bid-out-of-range.json"));
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /inRange is 0/);
});

test("tampered commitment (claimed != proven) -> REJECT", async () => {
  const { json } = await post("/api/bid", example("bid-tampered-commitment.json"));
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /commitment/);
});

test("proof from a substituted verification key -> REJECT", async () => {
  const { json } = await post("/api/bid", example("bid-vk-substitution.json"));
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /verification/i);
});

test("fake proof (random values) -> REJECT", async () => {
  const { json } = await post("/api/bid", example("bid-fake-proof.json"));
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /verification/i);
});

test("bid after close -> REJECT", async () => {
  const { json } = await post("/api/bid", example("bid-after-close.json"));
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /closed/);
});

test("bid with a tampered ticket -> REJECT", async () => {
  const bid = example("bid-valid.json");
  bid.ticket.auction.maxBid = 2000;
  const { json } = await post("/api/bid", bid);
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /ticket signature/);
});

test("valid reveal -> ACCEPT with a signed reveal receipt", async () => {
  const { json } = await post("/api/reveal", example("reveal-valid.json"));
  assert.equal(json.decision, "ACCEPT");
  assert.equal(json.receipt.bidder, "alice");
  assert.equal(json.receipt.bid, 750);
  assert.equal(typeof json.receipt.signature, "string");
  assert.equal(json.checks.commitmentMatch, true);
});

test("reveal with the wrong salt -> REJECT", async () => {
  const { json } = await post("/api/reveal", example("reveal-wrong-salt.json"));
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /does not match commitment/);
});

test("reveal before close -> REJECT", async () => {
  const { json } = await post("/api/reveal", example("reveal-before-close.json"));
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /still open/);
});

test("reveal with a forged bid receipt -> REJECT", async () => {
  const rev = example("reveal-valid.json");
  rev.bidReceipt.signature = "00".repeat(32);
  const { json } = await post("/api/reveal", rev);
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /receipt signature/);
});

test("settle a closed auction -> winner bob 920, full ranking", async () => {
  const { json } = await post("/api/settle", example("settle-valid.json"));
  assert.equal(json.decision, "ACCEPT");
  assert.equal(json.winner, "bob");
  assert.equal(json.winningBid, 920);
  assert.deepEqual(json.ranking, [
    { bidder: "bob", bid: 920 },
    { bidder: "alice", bid: 750 },
    { bidder: "carol", bid: 610 },
  ]);
  assert.equal(typeof json.settlement.signature, "string");
});

test("settle with a duplicate bidder -> REJECT", async () => {
  const { json } = await post("/api/settle", example("settle-duplicate-bidder.json"));
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /duplicate bidder/);
});

test("settle with a tampered reveal -> REJECT", async () => {
  const { json } = await post("/api/settle", example("settle-tampered-reveal.json"));
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /rejected|does not match commitment/);
});

test("settle before close -> REJECT", async () => {
  // A live (still open) ticket with an otherwise valid reveal set.
  const ticket = await createLiveAuction();
  const demoBids = example("demo-bids.json");
  const bidAt = Date.now();
  const mkReceipts = (d) => {
    const core = { auctionId: ticket.auction.auctionId, bidder: d.bidder, commitment: d.commitment, bidAt };
    const bidReceipt = { ...core, signature: auctionLib.signBidReceipt(TEST_SECRET, core) };
    const rcore = { auctionId: ticket.auction.auctionId, bidder: d.bidder, bid: d.bid, commitment: d.commitment };
    const revealReceipt = { ...rcore, signature: auctionLib.signRevealReceipt(TEST_SECRET, rcore) };
    return { bidReceipt, revealReceipt, bid: d.bid, salt: d.salt };
  };
  const { json } = await post("/api/settle", { ticket, reveals: demoBids.bids.map(mkReceipts) });
  assert.equal(json.decision, "REJECT");
  assert.match(json.reason, /still open/);
});

test("full live flow over HTTP: create -> 3 bids -> wait -> 3 reveals -> settle", async () => {
  const ticket = await createLiveAuction();
  // Shorten the close for the test by minting a ticket that closes in ~2s.
  const quickAuction = { ...ticket.auction, closeAt: Date.now() + 2000 };
  const quickTicket = {
    auction: quickAuction,
    signature: auctionLib.signTicket(TEST_SECRET, quickAuction),
  };
  const demoBids = example("demo-bids.json");
  const receipts = {};
  for (const d of demoBids.bids) {
    const { json } = await post("/api/bid", {
      ticket: quickTicket,
      bidder: d.bidder,
      commitment: d.commitment,
      proof: d.proof,
      publicSignals: d.publicSignals,
    });
    assert.equal(json.decision, "ACCEPT", `bid for ${d.bidder}: ${json.reason}`);
    receipts[d.bidder] = json.receipt;
  }
  // Wait for the close.
  await new Promise((r) => setTimeout(r, 2500));
  const reveals = [];
  for (const d of demoBids.bids) {
    const { json } = await post("/api/reveal", {
      ticket: quickTicket,
      bidReceipt: receipts[d.bidder],
      bid: d.bid,
      salt: d.salt,
    });
    assert.equal(json.decision, "ACCEPT", `reveal for ${d.bidder}: ${json.reason}`);
    reveals.push({ bidReceipt: receipts[d.bidder], revealReceipt: json.receipt, bid: d.bid, salt: d.salt });
  }
  const { json } = await post("/api/settle", { ticket: quickTicket, reveals });
  assert.equal(json.decision, "ACCEPT");
  assert.equal(json.winner, "bob");
  assert.equal(json.winningBid, 920);
});

test("bad HMAC signature -> 401", async () => {
  const { status, json } = await post("/api/bid", example("bid-valid.json"), { secret: "wrong-secret" });
  assert.equal(status, 401);
  assert.equal(json.decision, "REJECT");
});

test("stale HMAC timestamp (>5 min) -> 401", async () => {
  const { status } = await post("/api/bid", example("bid-valid.json"), { stale: true });
  assert.equal(status, 401);
});

test("missing HMAC headers -> 401", async () => {
  const { status } = await post("/api/bid", example("bid-valid.json"), { sign: false });
  assert.equal(status, 401);
});
