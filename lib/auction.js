"use strict";

/**
 * BlindBid — core auction logic.
 *
 * The agent is STATELESS: it keeps no database. Every state transition is
 * carried by a signed receipt, so the agent runs correctly on serverless
 * (Vercel) where no instance owns the auction:
 *
 *   auction ticket  — the agent signs the auction config (item, min/max
 *                     bid, close time). A ticket proves the config was not
 *                     tampered with after creation.
 *   bid receipt     — the agent signs {auctionId, bidder, commitment,
 *                     bidAt} when a bid is accepted. It proves the bid was
 *                     registered BEFORE the close time.
 *   reveal receipt  — the agent signs {auctionId, bidder, bid,
 *                     commitment} when a reveal checks out. It proves the
 *                     revealed bid is the one that was committed.
 *   settlement      — the agent verifies every reveal receipt, recomputes
 *                     the winner from the revealed bids, and signs the
 *                     result. One bidder, one reveal: a duplicate bidder in
 *                     the reveal set invalidates the settlement (this is
 *                     where one-bid-per-bidder is enforced — a stateless
 *                     agent cannot enforce it at bid time, so it enforces
 *                     it at settlement, where all reveals are visible).
 *
 * All signatures are HMAC-SHA256 over a canonical (key-sorted) JSON
 * encoding, keyed by AGENT_SECRET when set, otherwise by a fixed DEMO key
 * (demo mode only — the demo key is public and must never be used for a
 * registered production agent).
 *
 * Circuit (circuits/blindbid.circom, Circom 2.2.3, Groth16/BN128):
 *   proves knowledge of a bid in [minBid, maxBid] hidden inside a
 *   Poseidon(bid, salt) commitment, without revealing the bid.
 *   Public signals, snarkjs output-then-public order:
 *   [inRange, commitment, minBid, maxBid].
 *
 * Fail closed everywhere: any malformed envelope, bad signature, stale
 * timestamp, failed proof, mismatched commitment, out-of-range bid, or
 * wrong auction phase is a REJECT, never an acceptance.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { hmacSha256Hex } = require("./hmac");
const { commitment } = require("./poseidon");

const VK_PATH = path.join(__dirname, "verification_key.json");
const vk = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));

const VK_FINGERPRINT = crypto
  .createHash("sha256")
  .update(JSON.stringify(vk))
  .digest("hex");

// Demo-only ticket/receipt key. Public by design; used only when
// AGENT_SECRET is not set (demo mode). A registered agent always sets
// AGENT_SECRET, which then keys every ticket and receipt.
const DEMO_TICKET_KEY = "blindbid-demo-ticket-key-v1";

function ticketSecret(env) {
  return (env && env.AGENT_SECRET) || DEMO_TICKET_KEY;
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isUint32(n) {
  return Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
}

/** Canonical JSON: object keys sorted recursively, for stable signing. */
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (isPlainObject(v)) {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

function signPayload(secret, kind, payload) {
  return hmacSha256Hex(secret, `${kind}|${canonical(payload)}`);
}

function verifyPayload(secret, kind, payload, signature) {
  if (typeof signature !== "string") return false;
  const expected = signPayload(secret, kind, payload);
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(signature, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Auction ticket
// ---------------------------------------------------------------------------

function signTicket(secret, auction) {
  return signPayload(secret, "blindbid-auction-v1", auction);
}

function verifyTicket(secret, auction, signature) {
  return verifyPayload(secret, "blindbid-auction-v1", auction, signature);
}

function validateAuctionShape(auction) {
  if (!isPlainObject(auction)) return "auction must be a JSON object";
  if (typeof auction.auctionId !== "string" || auction.auctionId.length === 0) {
    return "auction.auctionId must be a non-empty string";
  }
  if (typeof auction.item !== "string" || auction.item.length === 0) {
    return "auction.item must be a non-empty string";
  }
  if (!isUint32(auction.minBid)) return "auction.minBid must be a uint32";
  if (!isUint32(auction.maxBid)) return "auction.maxBid must be a uint32";
  if (auction.minBid >= auction.maxBid) return "auction.minBid must be < auction.maxBid";
  if (!Number.isInteger(auction.closeAt) || auction.closeAt <= 0) {
    return "auction.closeAt must be a unix-millisecond timestamp";
  }
  return null;
}

// ---------------------------------------------------------------------------
// Bid
// ---------------------------------------------------------------------------

function signBidReceipt(secret, receipt) {
  return signPayload(secret, "blindbid-bid-v1", receipt);
}

function verifyBidReceipt(secret, receipt, signature) {
  return verifyPayload(secret, "blindbid-bid-v1", receipt, signature);
}

function isValidProofShape(proof) {
  return (
    isPlainObject(proof) &&
    Array.isArray(proof.pi_a) &&
    Array.isArray(proof.pi_b) &&
    Array.isArray(proof.pi_c) &&
    proof.protocol === "groth16" &&
    proof.curve === "bn128"
  );
}

function fail(reason, checks = {}) {
  return { decision: "REJECT", reason, checks };
}

/**
 * Verify a sealed bid.
 * @param {object} bid — {ticket, bidder, commitment, proof, publicSignals}
 * @param {object} opts — {secret, nowMs}
 * @returns {Promise<{decision, reason, checks, receipt?, vkFingerprint?}>}
 */
async function verifyBid(bid, opts = {}) {
  const secret = opts.secret || DEMO_TICKET_KEY;
  const nowMs = opts.nowMs || Date.now();
  const checks = {
    shapeOk: false,
    ticketOk: false,
    auctionOpen: false,
    proofVerified: false,
    inRangeSignal: false,
    commitmentMatch: false,
    boundsMatch: false,
  };

  if (!isPlainObject(bid)) return fail("malformed bid: not a JSON object", checks);
  const { ticket } = bid;
  if (!isPlainObject(ticket)) return fail("malformed bid: missing ticket", checks);
  if (!isPlainObject(ticket.auction)) return fail("malformed bid: ticket.auction missing", checks);
  if (typeof ticket.signature !== "string") return fail("malformed bid: ticket.signature missing", checks);
  if (typeof bid.bidder !== "string" || bid.bidder.length === 0) {
    return fail("malformed bid: bidder must be a non-empty string", checks);
  }
  if (typeof bid.commitment !== "string" || bid.commitment.length === 0) {
    return fail("malformed bid: commitment must be a non-empty string", checks);
  }
  if (!isValidProofShape(bid.proof)) {
    return fail("malformed bid: proof must be a groth16/bn128 proof (pi_a, pi_b, pi_c)", checks);
  }
  if (!Array.isArray(bid.publicSignals) || bid.publicSignals.length !== 4) {
    return fail(
      "malformed bid: publicSignals must have exactly 4 elements [inRange, commitment, minBid, maxBid]",
      checks
    );
  }
  checks.shapeOk = true;

  // 1. The ticket must be genuine — the auction config was not tampered with.
  const shapeErr = validateAuctionShape(ticket.auction);
  if (shapeErr) return fail(`malformed bid: ${shapeErr}`, checks);
  if (!verifyTicket(secret, ticket.auction, ticket.signature)) {
    return fail("ticket signature invalid — auction config was tampered with", checks);
  }
  checks.ticketOk = true;

  // 2. The auction must still be open.
  if (nowMs >= ticket.auction.closeAt) {
    return fail("auction is closed — bids are no longer accepted", checks);
  }
  checks.auctionOpen = true;

  // 3. The proof must verify against the REGISTERED verification key.
  const publicSignals = bid.publicSignals.map((s) => String(s));
  let verified = false;
  try {
    verified = await snarkjs.groth16.verify(vk, publicSignals, bid.proof);
  } catch (err) {
    return fail(`proof verification failed: ${err.message}`, checks);
  }
  if (!verified) {
    return fail("proof failed verification against the registered verification key", checks);
  }
  checks.proofVerified = true;

  // 4. What was proven: inRange must be 1 — a proof with inRange 0 is a
  // true statement about an out-of-range bid, and it is rejected here.
  if (publicSignals[0] !== "1") {
    return fail(
      `public signal inRange is ${publicSignals[0]}, not 1 (bid is outside [minBid, maxBid])`,
      checks
    );
  }
  checks.inRangeSignal = true;

  // 5. The proven commitment must be the claimed commitment.
  if (publicSignals[1] !== bid.commitment) {
    return fail(
      `public commitment ${publicSignals[1]} does not match claimed commitment ${bid.commitment}`,
      checks
    );
  }
  checks.commitmentMatch = true;

  // 6. The proven bounds must be this auction's bounds.
  if (
    publicSignals[2] !== String(ticket.auction.minBid) ||
    publicSignals[3] !== String(ticket.auction.maxBid)
  ) {
    return fail(
      `public bounds [${publicSignals[2]}, ${publicSignals[3]}] do not match auction bounds [${ticket.auction.minBid}, ${ticket.auction.maxBid}]`,
      checks
    );
  }
  checks.boundsMatch = true;

  // Accepted: issue a signed bid receipt. It proves this bid was
  // registered before the close time.
  const receipt = {
    auctionId: ticket.auction.auctionId,
    bidder: bid.bidder,
    commitment: bid.commitment,
    bidAt: nowMs,
  };
  return {
    decision: "ACCEPT",
    reason: "proof verified against the registered key, inRange=1, commitment and bounds match, auction open",
    checks,
    receipt: { ...receipt, signature: signBidReceipt(secret, receipt) },
    vkFingerprint: VK_FINGERPRINT,
  };
}

// ---------------------------------------------------------------------------
// Reveal
// ---------------------------------------------------------------------------

function signRevealReceipt(secret, receipt) {
  return signPayload(secret, "blindbid-reveal-v1", receipt);
}

function verifyRevealReceipt(secret, receipt, signature) {
  return verifyPayload(secret, "blindbid-reveal-v1", receipt, signature);
}

/**
 * Verify a bid reveal.
 * @param {object} rev — {ticket, bidReceipt, bid, salt}
 * @param {object} opts — {secret, nowMs}
 */
async function verifyReveal(rev, opts = {}) {
  const secret = opts.secret || DEMO_TICKET_KEY;
  const nowMs = opts.nowMs || Date.now();
  const checks = {
    shapeOk: false,
    ticketOk: false,
    auctionClosed: false,
    receiptOk: false,
    receiptInTime: false,
    commitmentMatch: false,
    rangeOk: false,
  };

  if (!isPlainObject(rev)) return fail("malformed reveal: not a JSON object", checks);
  const { ticket } = rev;
  if (!isPlainObject(ticket)) return fail("malformed reveal: missing ticket", checks);
  if (!isPlainObject(ticket.auction)) return fail("malformed reveal: ticket.auction missing", checks);
  if (typeof ticket.signature !== "string") return fail("malformed reveal: ticket.signature missing", checks);
  if (!isPlainObject(rev.bidReceipt)) return fail("malformed reveal: missing bidReceipt", checks);
  if (typeof rev.bidReceipt.signature !== "string") {
    return fail("malformed reveal: bidReceipt.signature missing", checks);
  }
  if (!isUint32(rev.bid)) return fail("malformed reveal: bid must be a uint32", checks);
  if (!isUint32(rev.salt)) return fail("malformed reveal: salt must be a uint32", checks);
  checks.shapeOk = true;

  const shapeErr = validateAuctionShape(ticket.auction);
  if (shapeErr) return fail(`malformed reveal: ${shapeErr}`, checks);
  if (!verifyTicket(secret, ticket.auction, ticket.signature)) {
    return fail("ticket signature invalid — auction config was tampered with", checks);
  }
  checks.ticketOk = true;

  // Reveals happen only after the close.
  if (nowMs < ticket.auction.closeAt) {
    return fail("auction is still open — reveals are accepted only after the close time", checks);
  }
  checks.auctionClosed = true;

  // The bid receipt must be genuine and belong to this auction.
  const { bidReceipt } = rev;
  const receiptCore = {
    auctionId: bidReceipt.auctionId,
    bidder: bidReceipt.bidder,
    commitment: bidReceipt.commitment,
    bidAt: bidReceipt.bidAt,
  };
  if (
    typeof receiptCore.auctionId !== "string" ||
    typeof receiptCore.bidder !== "string" ||
    typeof receiptCore.commitment !== "string" ||
    !Number.isInteger(receiptCore.bidAt)
  ) {
    return fail("malformed reveal: bidReceipt is missing fields", checks);
  }
  if (!verifyBidReceipt(secret, receiptCore, bidReceipt.signature)) {
    return fail("bid receipt signature invalid — this bid was never registered", checks);
  }
  if (receiptCore.auctionId !== ticket.auction.auctionId) {
    return fail("bid receipt belongs to a different auction", checks);
  }
  checks.receiptOk = true;

  // The bid must have been registered before the close time — the receipt
  // is agent-signed, so bidAt cannot be backdated by the bidder.
  if (receiptCore.bidAt >= ticket.auction.closeAt) {
    return fail("bid receipt was issued after the close time — bid was not registered in time", checks);
  }
  checks.receiptInTime = true;

  // The revealed bid + salt must reproduce the committed commitment.
  const recomputed = await commitment(rev.bid, rev.salt);
  if (recomputed !== receiptCore.commitment) {
    return fail(
      `revealed bid ${rev.bid} with salt ${rev.salt} does not match commitment ${receiptCore.commitment}`,
      checks
    );
  }
  checks.commitmentMatch = true;

  // Defense in depth: the revealed bid must be in range (the proof already
  // showed this at bid time; check it again on the revealed value).
  if (rev.bid < ticket.auction.minBid || rev.bid > ticket.auction.maxBid) {
    return fail(
      `revealed bid ${rev.bid} is outside auction bounds [${ticket.auction.minBid}, ${ticket.auction.maxBid}]`,
      checks
    );
  }
  checks.rangeOk = true;

  const receipt = {
    auctionId: ticket.auction.auctionId,
    bidder: receiptCore.bidder,
    bid: rev.bid,
    commitment: receiptCore.commitment,
  };
  return {
    decision: "ACCEPT",
    reason: "reveal matches the registered commitment, bid in range, auction closed",
    checks,
    receipt: { ...receipt, signature: signRevealReceipt(secret, receipt) },
    vkFingerprint: VK_FINGERPRINT,
  };
}

// ---------------------------------------------------------------------------
// Settle
// ---------------------------------------------------------------------------

/**
 * Settle an auction from its reveals.
 * @param {object} settlement — {ticket, reveals: [{bidReceipt, revealReceipt, bid, salt}]}
 * @param {object} opts — {secret, nowMs}
 */
async function settleAuction(settlement, opts = {}) {
  const secret = opts.secret || DEMO_TICKET_KEY;
  const nowMs = opts.nowMs || Date.now();
  const checks = {
    shapeOk: false,
    ticketOk: false,
    auctionClosed: false,
    revealsOk: false,
    noDuplicates: false,
  };

  if (!isPlainObject(settlement)) return fail("malformed settlement: not a JSON object", checks);
  const { ticket } = settlement;
  if (!isPlainObject(ticket)) return fail("malformed settlement: missing ticket", checks);
  if (!isPlainObject(ticket.auction)) return fail("malformed settlement: ticket.auction missing", checks);
  if (typeof ticket.signature !== "string") {
    return fail("malformed settlement: ticket.signature missing", checks);
  }
  if (!Array.isArray(settlement.reveals) || settlement.reveals.length === 0) {
    return fail("malformed settlement: reveals must be a non-empty array", checks);
  }
  checks.shapeOk = true;

  const shapeErr = validateAuctionShape(ticket.auction);
  if (shapeErr) return fail(`malformed settlement: ${shapeErr}`, checks);
  if (!verifyTicket(secret, ticket.auction, ticket.signature)) {
    return fail("ticket signature invalid — auction config was tampered with", checks);
  }
  checks.ticketOk = true;

  if (nowMs < ticket.auction.closeAt) {
    return fail("auction is still open — settlement is possible only after the close time", checks);
  }
  checks.auctionClosed = true;

  // Re-verify every reveal from scratch (receipt signatures, commitment,
  // range, in-time registration).
  const verified = [];
  for (let i = 0; i < settlement.reveals.length; i++) {
    const entry = settlement.reveals[i];
    if (!isPlainObject(entry)) return fail(`malformed settlement: reveals[${i}] is not an object`, checks);
    const result = await verifyReveal(
      { ticket, bidReceipt: entry.bidReceipt, bid: entry.bid, salt: entry.salt },
      { secret, nowMs }
    );
    if (result.decision !== "ACCEPT") {
      return fail(`reveals[${i}] rejected: ${result.reason}`, checks);
    }
    // The reveal receipt must also be genuine and match this reveal.
    const rr = entry.revealReceipt;
    if (!isPlainObject(rr) || typeof rr.signature !== "string") {
      return fail(`malformed settlement: reveals[${i}].revealReceipt missing or unsigned`, checks);
    }
    const rrCore = { auctionId: rr.auctionId, bidder: rr.bidder, bid: rr.bid, commitment: rr.commitment };
    if (
      rrCore.auctionId !== ticket.auction.auctionId ||
      rrCore.bidder !== entry.bidReceipt.bidder ||
      rrCore.bid !== entry.bid ||
      rrCore.commitment !== entry.bidReceipt.commitment ||
      !verifyRevealReceipt(secret, rrCore, rr.signature)
    ) {
      return fail(`reveals[${i}] reveal receipt invalid or does not match the reveal`, checks);
    }
    verified.push({
      bidder: entry.bidReceipt.bidder,
      bid: entry.bid,
      commitment: entry.bidReceipt.commitment,
      bidAt: entry.bidReceipt.bidAt,
    });
  }
  checks.revealsOk = true;

  // One bid per bidder — enforced here, where all reveals are visible.
  const seen = new Set();
  for (const v of verified) {
    if (seen.has(v.bidder)) {
      return fail(`duplicate bidder ${v.bidder} in reveals — one bid per bidder`, checks);
    }
    seen.add(v.bidder);
  }
  checks.noDuplicates = true;

  // Winner: highest bid; ties go to the earliest registered bid, then to
  // the lexicographically smallest bidder id (fully deterministic).
  const ranking = [...verified].sort(
    (a, b) => b.bid - a.bid || a.bidAt - b.bidAt || (a.bidder < b.bidder ? -1 : a.bidder > b.bidder ? 1 : 0)
  );
  const winner = ranking[0];
  const settlementCore = {
    auctionId: ticket.auction.auctionId,
    winner: winner.bidder,
    winningBid: winner.bid,
    bids: ranking.length,
  };
  return {
    decision: "ACCEPT",
    reason: `auction settled — winner ${winner.bidder} with bid ${winner.bid}`,
    checks,
    winner: winner.bidder,
    winningBid: winner.bid,
    ranking: ranking.map((r) => ({ bidder: r.bidder, bid: r.bid })),
    settlement: { ...settlementCore, signature: signPayload(secret, "blindbid-settlement-v1", settlementCore) },
    vkFingerprint: VK_FINGERPRINT,
  };
}

// ---------------------------------------------------------------------------
// Auction creation + status
// ---------------------------------------------------------------------------

function createAuction(auction, opts = {}) {
  const secret = opts.secret || DEMO_TICKET_KEY;
  const err = validateAuctionShape(auction);
  if (err) return { decision: "REJECT", reason: err };
  if ((opts.nowMs || Date.now()) >= auction.closeAt) {
    return { decision: "REJECT", reason: "closeAt must be in the future" };
  }
  return {
    decision: "ACCEPT",
    reason: "auction created",
    ticket: { auction, signature: signTicket(secret, auction) },
  };
}

function auctionStatus(ticket, opts = {}) {
  const secret = opts.secret || DEMO_TICKET_KEY;
  const nowMs = opts.nowMs || Date.now();
  if (!isPlainObject(ticket) || !isPlainObject(ticket.auction) || typeof ticket.signature !== "string") {
    return { decision: "REJECT", reason: "malformed ticket" };
  }
  const err = validateAuctionShape(ticket.auction);
  if (err) return { decision: "REJECT", reason: err };
  if (!verifyTicket(secret, ticket.auction, ticket.signature)) {
    return { decision: "REJECT", reason: "ticket signature invalid" };
  }
  return {
    decision: "ACCEPT",
    auction: ticket.auction,
    state: nowMs >= ticket.auction.closeAt ? "closed" : "open",
    nowMs,
  };
}

function getCircuitInfo() {
  return {
    name: "BlindBid",
    protocol: "groth16",
    curve: "bn128",
    circuit: "circuits/blindbid.circom (Circom 2.2.3)",
    statement:
      "knowledge of a bid in [minBid, maxBid] hidden inside a Poseidon(bid, salt) commitment, without revealing the bid",
    publicSignals: ["inRange", "commitment", "minBid", "maxBid"],
    vkFingerprintSha256: VK_FINGERPRINT,
  };
}

module.exports = {
  createAuction,
  auctionStatus,
  verifyBid,
  verifyReveal,
  settleAuction,
  signTicket,
  verifyTicket,
  signBidReceipt,
  verifyBidReceipt,
  signRevealReceipt,
  verifyRevealReceipt,
  signPayload,
  verifyPayload,
  validateAuctionShape,
  canonical,
  getCircuitInfo,
  VK_FINGERPRINT,
  DEMO_TICKET_KEY,
  ticketSecret,
};
