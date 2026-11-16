"use strict";

/**
 * Build validation — what `npm run build` runs (including on Vercel).
 *
 * No circuit compilation happens here (no circom needed at deploy time).
 * It validates the committed artifacts instead:
 *   1. lib/verification_key.json exists and parses as a Groth16 vk.
 *   2. All canned examples exist in public/examples/.
 *   3. The agent decides each canned example correctly through the same
 *      lib functions the endpoints use (valid -> ACCEPT, the tampered
 *      cases -> REJECT, settle-valid -> winner bob 920).
 *   4. The HTTP handler, the Vercel function modules, and the server load.
 *
 * Exits non-zero on any failure so a bad deploy never ships.
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const DEMO_SECRET = require(path.join(ROOT, "lib", "auction")).DEMO_TICKET_KEY;

const EXPECTED_BID = {
  "bid-valid.json": "ACCEPT",
  "bid-out-of-range.json": "REJECT",
  "bid-tampered-commitment.json": "REJECT",
  "bid-vk-substitution.json": "REJECT",
  "bid-fake-proof.json": "REJECT",
  "bid-after-close.json": "REJECT",
};

const EXPECTED_REVEAL = {
  "reveal-valid.json": "ACCEPT",
  "reveal-wrong-salt.json": "REJECT",
  "reveal-before-close.json": "REJECT",
};

const EXPECTED_SETTLE = {
  "settle-valid.json": "ACCEPT",
  "settle-duplicate-bidder.json": "REJECT",
  "settle-tampered-reveal.json": "REJECT",
};

async function main() {
  // eslint-disable-next-line no-console
  console.log("Validating committed artifacts...");
  const vkPath = path.join(ROOT, "lib", "verification_key.json");
  if (!fs.existsSync(vkPath)) {
    throw new Error(`Missing ${vkPath} — run \`npm run setup\` first.`);
  }
  const vk = JSON.parse(fs.readFileSync(vkPath, "utf8"));
  if (vk.protocol !== "groth16" || vk.curve !== "bn128" || !vk.vk_alpha_1) {
    throw new Error("verification_key.json does not look like a Groth16/BN128 verification key.");
  }
  // eslint-disable-next-line no-console
  console.log("  verification_key.json: OK (groth16/bn128)");

  const auction = require(path.join(ROOT, "lib", "auction"));
  const example = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, "public", "examples", name), "utf8"));

  for (const [name, expected] of Object.entries(EXPECTED_BID)) {
    const p = path.join(ROOT, "public", "examples", name);
    if (!fs.existsSync(p)) throw new Error(`Missing canned example: ${p}`);
    const result = await auction.verifyBid(example(name), { secret: DEMO_SECRET });
    if (result.decision !== expected) {
      throw new Error(`Example ${name}: expected ${expected}, got ${result.decision} (${result.reason})`);
    }
    // eslint-disable-next-line no-console
    console.log(`  ${name}: ${result.decision} (expected ${expected}) — ${result.reason}`);
  }
  for (const [name, expected] of Object.entries(EXPECTED_REVEAL)) {
    const p = path.join(ROOT, "public", "examples", name);
    if (!fs.existsSync(p)) throw new Error(`Missing canned example: ${p}`);
    const result = await auction.verifyReveal(example(name), { secret: DEMO_SECRET });
    if (result.decision !== expected) {
      throw new Error(`Example ${name}: expected ${expected}, got ${result.decision} (${result.reason})`);
    }
    // eslint-disable-next-line no-console
    console.log(`  ${name}: ${result.decision} (expected ${expected}) — ${result.reason}`);
  }
  for (const [name, expected] of Object.entries(EXPECTED_SETTLE)) {
    const p = path.join(ROOT, "public", "examples", name);
    if (!fs.existsSync(p)) throw new Error(`Missing canned example: ${p}`);
    const result = await auction.settleAuction(example(name), { secret: DEMO_SECRET });
    if (result.decision !== expected) {
      throw new Error(`Example ${name}: expected ${expected}, got ${result.decision} (${result.reason})`);
    }
    if (name === "settle-valid.json" && (result.winner !== "bob" || result.winningBid !== 920)) {
      throw new Error(`Example ${name}: expected winner bob/920, got ${result.winner}/${result.winningBid}`);
    }
    // eslint-disable-next-line no-console
    console.log(
      `  ${name}: ${result.decision} (expected ${expected}) — ${result.reason}`
    );
  }
  const demoBidsPath = path.join(ROOT, "public", "examples", "demo-bids.json");
  if (!fs.existsSync(demoBidsPath)) throw new Error(`Missing canned example: ${demoBidsPath}`);
  const demoBids = JSON.parse(fs.readFileSync(demoBidsPath, "utf8"));
  if (!Array.isArray(demoBids.bids) || demoBids.bids.length !== 3) {
    throw new Error("demo-bids.json must contain exactly 3 bids");
  }
  // eslint-disable-next-line no-console
  console.log("  demo-bids.json: OK (3 bids with proofs)");

  // Modules load.
  require(path.join(ROOT, "lib", "http-handler"));
  require(path.join(ROOT, "api", "auction"));
  require(path.join(ROOT, "api", "bid"));
  require(path.join(ROOT, "api", "reveal"));
  require(path.join(ROOT, "api", "settle"));
  require(path.join(ROOT, "server"));
  // eslint-disable-next-line no-console
  console.log("  lib/http-handler, api/*, server: load OK");
  // eslint-disable-next-line no-console
  console.log("Build validation passed.");
  process.exit(0); // snarkjs leaves async handles open; exit explicitly
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
