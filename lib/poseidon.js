"use strict";

/**
 * Poseidon commitment helper (circomlibjs), matching the Poseidon(2)
 * used in circuits/blindbid.circom.
 *
 * commitment = Poseidon(bid, salt), returned as a decimal string — the
 * same representation snarkjs uses for public signals, so a JS-computed
 * commitment can be compared directly with a proof's public signals.
 *
 * The builder is cached (building it is slow); callers await
 * commitment(bid, salt).
 */

const { buildPoseidon } = require("circomlibjs");

let poseidonPromise = null;

function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

/**
 * @param {number|string|bigint} bid
 * @param {number|string|bigint} salt
 * @returns {Promise<string>} decimal-string commitment
 */
async function commitment(bid, salt) {
  const poseidon = await getPoseidon();
  const out = poseidon([BigInt(bid), BigInt(salt)]);
  return poseidon.F.toString(out);
}

module.exports = { commitment };
