"use strict";

/**
 * Verify a proof ON-CHAIN via Kurier (zkVerify REST API) and poll to Finalized.
 *
 *   KURIER_API_KEY=... node scripts/verify-onchain.js [example-name]
 *
 * The API key is free: sign up at https://kurier.xyz (mainnet) and generate
 * one — no payment is mentioned anywhere on Kurier's site or in the
 * zkVerify docs. This script never commits or prints the key; it reads it
 * only from the KURIER_API_KEY environment variable.
 *
 * What it does:
 *   1. Registers this project's verification key with Kurier
 *      (POST /register-vk) and records the returned vkHash.
 *   2. Submits the canned bid proof from public/examples/<name>.json
 *      (POST /submit-proof) and polls GET /job-status until Finalized.
 *   3. Prints the job id, status, and on-chain txHash, and saves the full
 *      result to .kurier-result.json (gitignored).
 *
 * Default example: "bid-valid". Requires Node 18+ (global fetch).
 */

const fs = require("fs");
const path = require("path");

const API_URL = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";
const API_KEY = process.env.KURIER_API_KEY;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`POST ${url} -> HTTP ${res.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

async function getJson(url) {
  const res = await fetch(url);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`GET ${url} -> HTTP ${res.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

async function main() {
  if (!API_KEY) {
    // eslint-disable-next-line no-console
    console.error(
      "KURIER_API_KEY is not set.\n" +
        "Get a free key by signing up at https://kurier.xyz (mainnet), then run:\n" +
        "  KURIER_API_KEY=<your-key> node scripts/verify-onchain.js"
    );
    process.exit(1);
  }
  const exampleName = process.argv[2] || "bid-valid";
  const root = path.join(__dirname, "..");
  const vk = JSON.parse(fs.readFileSync(path.join(root, "lib", "verification_key.json"), "utf8"));
  const example = JSON.parse(
    fs.readFileSync(path.join(root, "public", "examples", `${exampleName}.json`), "utf8")
  );

  // eslint-disable-next-line no-console
  console.log("Registering verification key with Kurier...");
  const reg = await postJson(`${API_URL}/register-vk/${API_KEY}`, {
    proofType: "groth16",
    proofOptions: { library: "snarkjs", curve: "bn128" },
    vk,
  });
  const vkHash = reg.vkHash || (reg.meta && reg.meta.vkHash) || (reg.data && reg.data.vkHash);
  if (!vkHash) {
    // eslint-disable-next-line no-console
    console.error("Could not find vkHash in register-vk response:", JSON.stringify(reg, null, 2));
    process.exit(1);
  }
  // eslint-disable-next-line no-console
  console.log(`vkHash: ${vkHash}`);

  // eslint-disable-next-line no-console
  console.log("Submitting proof...");
  const submitted = await postJson(`${API_URL}/submit-proof/${API_KEY}`, {
    proofType: "groth16",
    vkRegistered: true,
    proofOptions: { library: "snarkjs", curve: "bn128" },
    proofData: {
      proof: example.proof,
      publicSignals: example.publicSignals,
      vk: vkHash,
    },
  });
  // eslint-disable-next-line no-console
  console.log(`jobId: ${submitted.jobId}, optimisticVerify: ${submitted.optimisticVerify}`);
  if (submitted.optimisticVerify !== "success") {
    // eslint-disable-next-line no-console
    console.error("Optimistic verification did not succeed — check the proof artifacts.");
    process.exit(1);
  }

  // eslint-disable-next-line no-console
  console.log("Polling job status (up to 10 minutes)...");
  const deadline = Date.now() + 10 * 60 * 1000;
  let final = null;
  while (Date.now() < deadline) {
    const status = await getJson(`${API_URL}/job-status/${API_KEY}/${submitted.jobId}`);
    // eslint-disable-next-line no-console
    console.log(`Job status: ${status.status}`);
    if (status.status === "Finalized") {
      final = status;
      break;
    }
    if (status.status === "Failed") {
      // eslint-disable-next-line no-console
      console.error("Job failed:", JSON.stringify(status, null, 2));
      process.exit(1);
    }
    await sleep(5000);
  }
  if (!final) {
    // eslint-disable-next-line no-console
    console.error("Timed out waiting for Finalized.");
    process.exit(1);
  }
  // eslint-disable-next-line no-console
  console.log("Job finalized successfully:");
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(final, null, 2));
  fs.writeFileSync(path.join(root, ".kurier-result.json"), JSON.stringify(final, null, 2));
  // eslint-disable-next-line no-console
  console.log("Full result saved to .kurier-result.json (gitignored).");
  // eslint-disable-next-line no-console
  console.log(`On-chain txHash: ${final.txHash}`);
  process.exit(0);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
