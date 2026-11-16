"use strict";

/**
 * Reproducible setup for BlindBid.
 *
 *   npm run setup
 *
 * What it does (all local, no network except the circom binary which must
 * already be installed — see README):
 *   1. Compiles circuits/blindbid.circom with Circom 2.x (r1cs + wasm + sym).
 *   2. Runs the Groth16 trusted setup on the Powers of Tau file
 *      (circuits/pot12_final.ptau, copied from the Gatekeeper project —
 *      Powers of Tau is circuit-independent) and contributes once,
 *      producing the proving key circuits/blindbid_final.zkey.
 *   3. Exports the verification key to lib/verification_key.json — the
 *      key the endpoint trusts at runtime (committed to the repo).
 *   4. Builds a SECOND proving key from a different contribution
 *      (circuits/blindbid_alt.zkey). A proof made with it is the
 *      "VK substitution" demo case: it must NOT verify against the
 *      registered key.
 *   5. Generates the canned payloads in public/examples/:
 *      bid-valid, bid-out-of-range, bid-tampered-commitment,
 *      bid-vk-substitution, bid-fake-proof, bid-after-close,
 *      reveal-valid, reveal-wrong-salt, reveal-before-close,
 *      settle-valid, settle-duplicate-bidder, settle-tampered-reveal,
 *      plus demo-bids.json (the three proofs the demo UI reuses for its
 *      live full-auction run).
 *   6. Self-checks: the valid proof verifies, the alt proof does not, the
 *      JS Poseidon commitment equals the proof's public commitment, and a
 *      full local auction (create -> bid -> reveal -> settle) ends with
 *      the right winner.
 *
 * NOTE on the trusted setup: the Powers of Tau file used here was generated
 * locally (snarkjs powersoftau, power 12, one contribution) because the
 * public Hermez ceremony file (hermez S3 bucket) currently returns
 * AccessDenied from this environment. The ceremony is real Groth16 setup,
 * just a local one. To use the multi-party Hermez ceremony instead, drop a
 * powersOfTau28_hez_final_*.ptau file in as circuits/pot12_final.ptau and
 * re-run this script — the verification key and canned proofs regenerate.
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const ROOT = path.join(__dirname, "..");
const CIRCUITS = path.join(ROOT, "circuits");
const LIB = path.join(ROOT, "lib");
const EXAMPLES = path.join(ROOT, "public", "examples");

const MIN_BID = 100;
const MAX_BID = 1000;
const OPEN_CLOSE_AT = Date.parse("2030-01-01T00:00:00.000Z");
const CLOSED_CLOSE_AT = Date.parse("2020-01-01T00:00:00.000Z");
const REGISTERED_AT = Date.parse("2019-06-01T00:00:00.000Z"); // bidAt for closed-auction receipts

// Demo bidders for the full-auction run (public by design — anyone can run it).
const DEMO_BIDS = [
  { bidder: "alice", bid: 750, salt: 12345 },
  { bidder: "bob", bid: 920, salt: 777 },
  { bidder: "carol", bid: 610, salt: 424242 },
];

function run(cmd, cwd) {
  // eslint-disable-next-line no-console
  console.log(`$ ${cmd}`);
  execSync(cmd, { cwd, stdio: "inherit" });
}

function findCircom() {
  if (process.env.CIRCOM_BIN) return process.env.CIRCOM_BIN;
  try {
    return execSync("which circom", { encoding: "utf8" }).trim();
  } catch {
    const local = path.join(process.env.HOME || "", ".local", "bin", "circom");
    if (fs.existsSync(local)) return local;
    throw new Error(
      "circom binary not found. Install Circom 2.x (https://docs.circom.io/getting-started/installation/) and make sure `circom` is on PATH, or set CIRCOM_BIN."
    );
  }
}

async function main() {
  const circom = findCircom();
  // eslint-disable-next-line no-console
  console.log(`Using circom: ${circom}`);
  fs.mkdirSync(EXAMPLES, { recursive: true });

  const r1cs = path.join(CIRCUITS, "blindbid.r1cs");
  const wasm = path.join(CIRCUITS, "blindbid_js", "blindbid.wasm");
  const zkey0 = path.join(CIRCUITS, "blindbid_0000.zkey");
  const zkeyFinal = path.join(CIRCUITS, "blindbid_final.zkey");
  const zkeyAlt = path.join(CIRCUITS, "blindbid_alt.zkey");
  const ptau = path.join(CIRCUITS, "pot12_final.ptau");
  const vkPath = path.join(LIB, "verification_key.json");

  if (!fs.existsSync(ptau)) {
    throw new Error(
      `Powers of Tau file missing: ${ptau}. Generate one with:\n` +
        `  npx snarkjs powersoftau new bn128 12 pot12_0000.ptau\n` +
        `  npx snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="..." -e="..."\n` +
        `  npx snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau`
    );
  }

  // 1. Compile the circuit.
  run(
    `"${circom}" blindbid.circom --r1cs --wasm --sym -l ${path.join(ROOT, "node_modules")}`,
    CIRCUITS
  );

  // 2. Groth16 setup + one contribution.
  // eslint-disable-next-line no-console
  console.log("Groth16 setup...");
  await snarkjs.zKey.newZKey(r1cs, ptau, zkey0);
  // eslint-disable-next-line no-console
  console.log("Contributing to the zkey (entropy is a fixed demo string)...");
  await snarkjs.zKey.contribute(zkey0, zkeyFinal, "BlindBid v1", "blindbid-demo-entropy-v1");
  await snarkjs.zKey.contribute(zkey0, zkeyAlt, "BlindBid alt (vk-substitution demo)", "different-entropy-for-vk-substitution-demo");

  // 3. Export the verification key the endpoint trusts.
  const vk = await snarkjs.zKey.exportVerificationKey(zkeyFinal);
  fs.writeFileSync(vkPath, JSON.stringify(vk, null, 2));
  // eslint-disable-next-line no-console
  console.log(`Verification key written to ${vkPath}`);

  // From here on, lib/auction.js can load (it reads the VK at require time).
  const auctionLib = require(path.join(LIB, "auction"));
  const { commitment } = require(path.join(LIB, "poseidon"));
  const demoSecret = auctionLib.DEMO_TICKET_KEY;

  const openAuction = {
    auctionId: "demo-auction-001",
    item: "Rare VFY Art #1",
    minBid: MIN_BID,
    maxBid: MAX_BID,
    closeAt: OPEN_CLOSE_AT,
  };
  const closedAuction = {
    auctionId: "demo-auction-closed-001",
    item: "Rare VFY Art #1 (closed)",
    minBid: MIN_BID,
    maxBid: MAX_BID,
    closeAt: CLOSED_CLOSE_AT,
  };
  const openTicket = { auction: openAuction, signature: auctionLib.signTicket(demoSecret, openAuction) };
  const closedTicket = { auction: closedAuction, signature: auctionLib.signTicket(demoSecret, closedAuction) };

  // 4. Generate the proofs.
  // eslint-disable-next-line no-console
  console.log("Generating proofs...");
  const valid = await snarkjs.groth16.fullProve(
    { bid: "750", salt: "12345", minBid: String(MIN_BID), maxBid: String(MAX_BID) },
    wasm,
    zkeyFinal
  );
  const outOfRange = await snarkjs.groth16.fullProve(
    { bid: "1500", salt: "12345", minBid: String(MIN_BID), maxBid: String(MAX_BID) },
    wasm,
    zkeyFinal
  );
  const altProof = await snarkjs.groth16.fullProve(
    { bid: "750", salt: "12345", minBid: String(MIN_BID), maxBid: String(MAX_BID) },
    wasm,
    zkeyAlt
  );

  // Demo bids for the UI's live full-auction run (fixed bids/salts so the
  // proofs are reusable for any auction with bounds [100, 1000]).
  const demoBids = [];
  for (const d of DEMO_BIDS) {
    const p = await snarkjs.groth16.fullProve(
      { bid: String(d.bid), salt: String(d.salt), minBid: String(MIN_BID), maxBid: String(MAX_BID) },
      wasm,
      zkeyFinal
    );
    demoBids.push({ ...d, commitment: p.publicSignals[1], proof: p.proof, publicSignals: p.publicSignals });
  }

  // Helpers to mint receipts with the demo key (as the agent would).
  function bidReceipt(auctionId, bidder, commitmentValue, bidAt) {
    const core = { auctionId, bidder, commitment: commitmentValue, bidAt };
    return { ...core, signature: auctionLib.signBidReceipt(demoSecret, core) };
  }
  function revealReceipt(auctionId, bidder, bidValue, commitmentValue) {
    const core = { auctionId, bidder, bid: bidValue, commitment: commitmentValue };
    return { ...core, signature: auctionLib.signRevealReceipt(demoSecret, core) };
  }

  // Closed-auction receipts for the canned reveal/settle examples.
  const closedBidReceipts = {};
  const closedRevealReceipts = {};
  for (const d of DEMO_BIDS) {
    const c = await commitment(d.bid, d.salt);
    closedBidReceipts[d.bidder] = bidReceipt(closedAuction.auctionId, d.bidder, c, REGISTERED_AT);
    closedRevealReceipts[d.bidder] = revealReceipt(closedAuction.auctionId, d.bidder, d.bid, c);
  }
  const aliceCommitment = demoBids[0].commitment;

  const examples = {
    "bid-valid.json": {
      ticket: openTicket,
      bidder: "alice",
      commitment: aliceCommitment,
      proof: valid.proof,
      publicSignals: valid.publicSignals,
    },
    "bid-out-of-range.json": {
      ticket: openTicket,
      bidder: "mallory",
      commitment: outOfRange.publicSignals[1],
      proof: outOfRange.proof, // proves inRange=0 (bid 1500 > max 1000)
      publicSignals: outOfRange.publicSignals,
    },
    "bid-tampered-commitment.json": {
      ticket: openTicket,
      bidder: "alice",
      // Valid proof, but the claimed commitment is not the proven one.
      commitment: "123456789",
      proof: valid.proof,
      publicSignals: valid.publicSignals,
    },
    "bid-vk-substitution.json": {
      ticket: openTicket,
      bidder: "alice",
      commitment: altProof.publicSignals[1],
      proof: altProof.proof, // made with a DIFFERENT proving key
      publicSignals: altProof.publicSignals,
    },
    "bid-fake-proof.json": {
      ticket: openTicket,
      bidder: "alice",
      commitment: aliceCommitment,
      proof: {
        pi_a: ["123", "456", "1"],
        pi_b: [
          ["1", "2"],
          ["3", "4"],
          ["1", "0"],
        ],
        pi_c: ["5", "6", "1"],
        protocol: "groth16",
        curve: "bn128",
      },
      publicSignals: ["1", aliceCommitment, String(MIN_BID), String(MAX_BID)],
    },
    "bid-after-close.json": {
      ticket: closedTicket,
      bidder: "alice",
      commitment: aliceCommitment,
      proof: valid.proof,
      publicSignals: valid.publicSignals,
    },
    "reveal-valid.json": {
      ticket: closedTicket,
      bidReceipt: closedBidReceipts.alice,
      bid: 750,
      salt: 12345,
    },
    "reveal-wrong-salt.json": {
      ticket: closedTicket,
      bidReceipt: closedBidReceipts.alice,
      bid: 750,
      salt: 99999, // wrong salt -> commitment mismatch
    },
    "reveal-before-close.json": {
      ticket: openTicket,
      bidReceipt: bidReceipt(openAuction.auctionId, "alice", aliceCommitment, Date.parse("2026-01-01T00:00:00.000Z")),
      bid: 750,
      salt: 12345,
    },
    "settle-valid.json": {
      ticket: closedTicket,
      reveals: DEMO_BIDS.map((d) => ({
        bidReceipt: closedBidReceipts[d.bidder],
        revealReceipt: closedRevealReceipts[d.bidder],
        bid: d.bid,
        salt: d.salt,
      })),
    },
    "settle-duplicate-bidder.json": {
      ticket: closedTicket,
      reveals: [
        {
          bidReceipt: closedBidReceipts.alice,
          revealReceipt: closedRevealReceipts.alice,
          bid: 750,
          salt: 12345,
        },
        {
          bidReceipt: closedBidReceipts.alice,
          revealReceipt: closedRevealReceipts.alice,
          bid: 750,
          salt: 12345,
        },
      ],
    },
    "settle-tampered-reveal.json": {
      ticket: closedTicket,
      reveals: DEMO_BIDS.map((d) => ({
        bidReceipt: closedBidReceipts[d.bidder],
        revealReceipt: closedRevealReceipts[d.bidder],
        // Bob "reveals" 950 instead of his committed 920.
        bid: d.bidder === "bob" ? 950 : d.bid,
        salt: d.salt,
      })),
    },
    "demo-bids.json": {
      minBid: MIN_BID,
      maxBid: MAX_BID,
      bids: demoBids,
    },
  };

  for (const [name, envelope] of Object.entries(examples)) {
    fs.writeFileSync(path.join(EXAMPLES, name), JSON.stringify(envelope, null, 2));
    // eslint-disable-next-line no-console
    console.log(`Wrote public/examples/${name}`);
  }

  // 5. Self-checks.
  const vkJson = JSON.parse(fs.readFileSync(vkPath, "utf8"));
  const okValid = await snarkjs.groth16.verify(vkJson, valid.publicSignals, valid.proof);
  const okAlt = await snarkjs.groth16.verify(vkJson, altProof.publicSignals, altProof.proof).catch(() => false);
  const jsCommitment = await commitment(750, 12345);
  // eslint-disable-next-line no-console
  console.log(`Self-check: valid proof verifies: ${okValid} (expected true)`);
  // eslint-disable-next-line no-console
  console.log(`Self-check: alt-key proof verifies: ${okAlt} (expected false)`);
  // eslint-disable-next-line no-console
  console.log(`Self-check: JS Poseidon(750, 12345) == proof commitment: ${jsCommitment === valid.publicSignals[1]} (expected true)`);
  if (!okValid || okAlt || jsCommitment !== valid.publicSignals[1]) {
    throw new Error("Self-check failed — the setup is inconsistent, do not ship these artifacts.");
  }

  // Full local auction flow through the real lib functions.
  const nowOpen = Date.parse("2026-06-01T00:00:00.000Z");
  const nowClosed = Date.parse("2026-07-01T00:00:00.000Z");
  const liveTicket = {
    auction: { auctionId: "selfcheck-001", item: "Self-check lot", minBid: MIN_BID, maxBid: MAX_BID, closeAt: Date.parse("2026-06-15T00:00:00.000Z") },
    signature: "",
  };
  liveTicket.signature = auctionLib.signTicket(demoSecret, liveTicket.auction);
  const receipts = {};
  for (const d of DEMO_BIDS) {
    const p = demoBids.find((x) => x.bidder === d.bidder);
    const r = await auctionLib.verifyBid(
      { ticket: liveTicket, bidder: d.bidder, commitment: p.commitment, proof: p.proof, publicSignals: p.publicSignals },
      { secret: demoSecret, nowMs: nowOpen }
    );
    if (r.decision !== "ACCEPT") throw new Error(`Self-check bid for ${d.bidder} rejected: ${r.reason}`);
    receipts[d.bidder] = r.receipt;
  }
  const reveals = [];
  for (const d of DEMO_BIDS) {
    const r = await auctionLib.verifyReveal(
      { ticket: liveTicket, bidReceipt: receipts[d.bidder], bid: d.bid, salt: d.salt },
      { secret: demoSecret, nowMs: nowClosed }
    );
    if (r.decision !== "ACCEPT") throw new Error(`Self-check reveal for ${d.bidder} rejected: ${r.reason}`);
    reveals.push({ bidReceipt: receipts[d.bidder], revealReceipt: r.receipt, bid: d.bid, salt: d.salt });
  }
  const settled = await auctionLib.settleAuction({ ticket: liveTicket, reveals }, { secret: demoSecret, nowMs: nowClosed });
  // eslint-disable-next-line no-console
  console.log(`Self-check: full auction settles, winner=${settled.winner} bid=${settled.winningBid} (expected bob 920)`);
  if (settled.decision !== "ACCEPT" || settled.winner !== "bob" || settled.winningBid !== 920) {
    throw new Error("Self-check failed — the auction flow is inconsistent, do not ship.");
  }
  // eslint-disable-next-line no-console
  console.log("Setup complete. Run `npm test` to verify the endpoint end to end.");
  process.exit(0); // snarkjs leaves async handles open; exit explicitly
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
