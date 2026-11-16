"use strict";

/**
 * HTTP handling for the BlindBid endpoints — shared by the local dev
 * server (server.js) and the Vercel serverless functions (api/*.js).
 *
 * Flow (fail closed at every step):
 *   1. If AGENT_SECRET is set, verify the HMAC over the RAW body before
 *      parsing anything (POST routes). Missing/bad/stale signature ->
 *      401 + REJECT. If it is not set, the server runs in DEMO MODE
 *      (HMAC not enforced).
 *   2. Parse JSON. Unparsable body -> 400 + REJECT.
 *   3. Run the auction decision (lib/auction.js).
 *   4. Reply with the decision JSON. When a secret is set, the response
 *      is HMAC-signed with the x-agentgames-signature /
 *      x-agentgames-timestamp headers, per the Agent Games build guide.
 *
 * Routes:
 *   POST /api/auction   create an auction, returns a signed ticket
 *   GET  /api/auction   status of an auction (?ticket=<url-encoded JSON>)
 *   POST /api/bid       submit a sealed bid (commitment + Groth16 proof)
 *   POST /api/reveal    reveal a bid (bid + salt, with the bid receipt)
 *   POST /api/settle    settle a closed auction from its reveals
 */

const { verifyHmac, sign } = require("./hmac");
const auction = require("./auction");

function demoMode(env) {
  return !env.AGENT_SECRET;
}

/**
 * @param {object} args — {method, path, query, rawBody, headers, env}
 * @returns {Promise<{status:number, json:object, headersOut:object}>}
 */
async function handleRequest({ method, path, query = {}, rawBody = "", headers = {}, env = {} }) {
  const secret = env.AGENT_SECRET || "";
  const ticketSecret = auction.ticketSecret(env);
  const lower = {};
  for (const [k, v] of Object.entries(headers || {})) lower[k.toLowerCase()] = v;

  const finish = (status, json) => {
    const body = JSON.stringify(json);
    const headersOut = { "content-type": "application/json" };
    if (secret) {
      const ts = Math.floor(Date.now() / 1000);
      headersOut["x-agentgames-signature"] = sign(secret, ts, body);
      headersOut["x-agentgames-timestamp"] = String(ts);
    }
    return { status, json, headersOut };
  };

  // 1. HMAC on POSTs (only enforced when a secret is configured).
  if (method === "POST" && secret) {
    const check = verifyHmac({
      secret,
      timestamp: lower["x-agentgames-timestamp"],
      rawBody,
      signature: lower["x-agentgames-signature"],
    });
    if (!check.ok) {
      return finish(401, { decision: "REJECT", reason: `unauthorized: ${check.reason}` });
    }
  }

  // 2. Route.
  try {
    if (method === "POST" && path === "/api/auction") {
      const body = JSON.parse(rawBody);
      const out = auction.createAuction(body, { secret: ticketSecret });
      return finish(out.decision === "ACCEPT" ? 200 : 400, out);
    }
    if (method === "GET" && path === "/api/auction") {
      if (!query.ticket) {
        return finish(400, { decision: "REJECT", reason: "missing ?ticket= query parameter" });
      }
      let ticket;
      try {
        ticket = JSON.parse(decodeURIComponent(query.ticket));
      } catch {
        return finish(400, { decision: "REJECT", reason: "ticket is not valid JSON" });
      }
      const out = auction.auctionStatus(ticket, { secret: ticketSecret });
      return finish(out.decision === "ACCEPT" ? 200 : 400, out);
    }
    if (method === "POST" && path === "/api/bid") {
      const body = JSON.parse(rawBody);
      const out = await auction.verifyBid(body, { secret: ticketSecret });
      return finish(200, out);
    }
    if (method === "POST" && path === "/api/reveal") {
      const body = JSON.parse(rawBody);
      const out = await auction.verifyReveal(body, { secret: ticketSecret });
      return finish(200, out);
    }
    if (method === "POST" && path === "/api/settle") {
      const body = JSON.parse(rawBody);
      const out = await auction.settleAuction(body, { secret: ticketSecret });
      return finish(200, out);
    }
    return finish(404, { decision: "REJECT", reason: `unknown route ${method} ${path}` });
  } catch (err) {
    if (err instanceof SyntaxError) {
      return finish(400, { decision: "REJECT", reason: "invalid JSON body" });
    }
    // Fail closed: an unexpected error is a REJECT, never an acceptance.
    return finish(500, { decision: "REJECT", reason: `internal error: ${err.message}` });
  }
}

module.exports = { handleRequest, demoMode };
