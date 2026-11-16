"use strict";

/**
 * Generate a Groth16 proof for the BlindBid circuit.
 *
 *   node scripts/prove.js <bid> <salt> <minBid> <maxBid> [output-prefix]
 *
 * Writes <prefix>.proof.json and <prefix>.public.json, and prints the
 * Poseidon commitment (publicSignals[1]).
 * Example: node scripts/prove.js 750 12345 100 1000 my-bid
 *   -> public signals ["1","<commitment>","100","1000"] (inRange=1)
 *   -> node scripts/prove.js 1500 12345 100 1000 my-bid
 *   -> public signals ["0","<commitment>","100","1000"] (inRange=0, out of range)
 */

const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

async function main() {
  const [bid, salt, minBid, maxBid, prefix = "proof"] = process.argv.slice(2);
  if (bid === undefined || salt === undefined || minBid === undefined || maxBid === undefined) {
    // eslint-disable-next-line no-console
    console.error("Usage: node scripts/prove.js <bid> <salt> <minBid> <maxBid> [output-prefix]");
    process.exit(1);
  }
  const wasm = path.join(__dirname, "..", "circuits", "blindbid_js", "blindbid.wasm");
  const zkey = path.join(__dirname, "..", "circuits", "blindbid_final.zkey");
  for (const [label, p] of [
    ["wasm", wasm],
    ["zkey", zkey],
  ]) {
    if (!fs.existsSync(p)) {
      // eslint-disable-next-line no-console
      console.error(`Missing ${label} artifact: ${p}\nRun \`npm run setup\` first.`);
      process.exit(1);
    }
  }
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    { bid: String(bid), salt: String(salt), minBid: String(minBid), maxBid: String(maxBid) },
    wasm,
    zkey
  );
  fs.writeFileSync(`${prefix}.proof.json`, JSON.stringify(proof, null, 2));
  fs.writeFileSync(`${prefix}.public.json`, JSON.stringify(publicSignals, null, 2));
  // eslint-disable-next-line no-console
  console.log(`Wrote ${prefix}.proof.json and ${prefix}.public.json`);
  // eslint-disable-next-line no-console
  console.log(
    `Public signals: ${JSON.stringify(publicSignals)} (inRange=${publicSignals[0]}, commitment=${publicSignals[1]}, minBid=${publicSignals[2]}, maxBid=${publicSignals[3]})`
  );
  process.exit(0); // snarkjs leaves async handles open; exit explicitly
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
