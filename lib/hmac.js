"use strict";

/**
 * HMAC helpers for the Agent Games task interface.
 *
 * Incoming tasks are signed by the platform:
 *   signature = HMAC-SHA256(secret, timestamp + "." + rawBody)   (hex)
 *   headers: x-agentgames-signature, x-agentgames-timestamp
 * Timestamps more than 5 minutes old are rejected.
 *
 * Responses are signed the same way (header x-agent-games-signature,
 * per the Agent Games build guide) so the platform can confirm the
 * reply came from the registered agent.
 *
 * The secret comes from the AGENT_SECRET environment variable. When it is
 * not set the server runs in DEMO MODE: HMAC is not enforced and responses
 * are unsigned. Demo mode is clearly logged at startup and must never be
 * used with a registered production agent.
 */

const crypto = require("crypto");

const MAX_AGE_SECONDS = 300;

function hmacSha256Hex(secret, message) {
  return crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");
}

/** signature for `timestamp + "." + rawBody` (timestamp in seconds). */
function sign(secret, timestampSeconds, rawBody) {
  return hmacSha256Hex(secret, `${timestampSeconds}.${rawBody}`);
}

function timestampToMs(ts) {
  const n = Number(ts);
  if (!Number.isFinite(n)) return NaN;
  // Accept seconds (10 digits) or milliseconds (13 digits).
  return n > 1e12 ? n : n * 1000;
}

/**
 * Verify an incoming HMAC. Returns { ok: true } or { ok: false, reason }.
 * Uses a timing-safe comparison.
 */
function verifyHmac({ secret, timestamp, rawBody, signature, nowMs = Date.now() }) {
  if (!timestamp || !signature) {
    return { ok: false, reason: "missing HMAC signature or timestamp header" };
  }
  const tsMs = timestampToMs(timestamp);
  if (!Number.isFinite(tsMs)) {
    return { ok: false, reason: "invalid HMAC timestamp" };
  }
  const ageMs = nowMs - tsMs;
  if (ageMs > MAX_AGE_SECONDS * 1000) {
    return { ok: false, reason: "HMAC timestamp too old (>5 min)" };
  }
  if (ageMs < -60 * 1000) {
    return { ok: false, reason: "HMAC timestamp is in the future" };
  }
  const expected = sign(secret, timestamp, rawBody);
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(String(signature), "utf8");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: "HMAC signature mismatch" };
  }
  return { ok: true };
}

module.exports = { hmacSha256Hex, sign, verifyHmac, MAX_AGE_SECONDS };
