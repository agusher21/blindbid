# Agent Games Wildcard — submission texts (2nd entry)

Paste these into the Wildcard "New submission" form at
https://agentgames.zkverify.io/dashboard/submissions?category=wildcard
(do NOT submit until the demo URL is live and the proof reference is filled
in — see the notes at the bottom).

## Project title

BlindBid

## What it does (max 2,000 characters)

BlindBid is a sealed-bid first-price auction agent that runs the whole auction autonomously — and never sees a bid before the reveal. A bidder commits Poseidon(bid, salt) plus a Groth16 proof that the hidden bid is inside [minBid, maxBid]. The agent verifies the proof against a registered key, checks the proven commitment and bounds, and returns a signed bid receipt proving the bid was registered before the close. After the close, each bidder reveals (bid, salt); the agent recomputes the commitment and requires an exact match, then re-verifies every reveal, rejects duplicate bidders, and signs the settlement: the highest revealed bid wins.

The problem it solves is the core risk of sealed-bid auctions: bids must stay hidden until the close, or the auction is gameable — but the auctioneer must still know each hidden bid is valid. BlindBid proves validity without revealing the bid, and binds every reveal to its commitment, so a bidder cannot change their bid after seeing others.

It is built with a real Circom 2.x circuit (range check + Poseidon commitment), snarkjs Groth16/BN128 proofs, and a stateless Node.js agent: every step is carried by a signed receipt, so it runs on serverless with no database. The live demo runs a full auction (3 sealed bids, close, reveal, settle) and fires 12 canned payloads — valid bids and reveals, out-of-range bids, tampered commitments, VK substitution, fake proofs, bids after close, wrong salts, duplicate bidders — showing each verdict. Local verification is the core and fully demonstrated; the on-chain step (the same bid proof verified on zkVerify mainnet via Kurier) is pending a Kurier key — the script is ready in the repo.

## Message to judges (max 1,000 characters)

Thank you for reviewing this entry. Everything here is real and runnable: a genuine Circom circuit, genuine Groth16 proofs, and an agent that runs a full sealed-bid auction — create, bid, reveal, settle — verifying every step cryptographically and signing every receipt, with no database and nothing faked. The demo makes the security story visible: bids stay hidden until the close, and each tampered variant (out-of-range bid, swapped commitment, wrong salt, duplicate bidder) is rejected for the exact reason it should be. One honest boundary: the on-chain proof verification via Kurier is scripted and ready but needs a Kurier API key, which I do not have in this environment — local verification is complete and demonstrated. I built this because sealed-bid auctions are the cleanest case where privacy is load-bearing: if the auctioneer can see the bids early, the auction is already broken.

## Other form fields

- Public GitHub repo: https://github.com/agusher21/blindbid
- Agent endpoint: https://blindbid.vercel.app/api/bid (confirm the exact Vercel URL after the dashboard import — the name may differ if blindbid.vercel.app is taken)
- Proof reference: PENDING — needs a free Kurier API key. Run `KURIER_API_KEY=<key> node scripts/verify-onchain.js`, then paste the Subscan extrinsic link here. Local verification done: fresh bid proof (bid 850, salt 31337) verifies with snarkjs against the registered key, public signals ["1", "11501687651838972920506440655765179309893390823508896377454774643950849626057", "100", "1000"].
- Additional links: live demo https://blindbid.vercel.app (same URL caveat as above)

## Before submitting

1. Toni imports the repo in the Vercel dashboard (Add New → Project → Import).
2. Copy the production URL into "agent endpoint" and "additional links" above.
3. Sign up for a free Kurier key at https://kurier.xyz, run
   `KURIER_API_KEY=<your-key> node scripts/verify-onchain.js`, and paste the
   resulting Subscan extrinsic link as the proof reference.
4. Submit via the dashboard "New submission" form (Wildcard). Note: this is
   a SECOND Wildcard entry from the same account (the first, Universal Proof
   Gatekeeper, is already submitted and pending) — the dashboard shows the
   form and the site states no per-account limit, but backend acceptance of
   a second entry is unproven.
