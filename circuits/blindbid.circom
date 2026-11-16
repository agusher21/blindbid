pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * BlindBid circuit — "BlindBid" sealed-bid auction agent (Agent Games Wildcard).
 *
 * What it proves, in plain language:
 *   "I know a bid that is between `minBid` and `maxBid`, and it is the bid
 *   hidden inside `commitment` — without revealing the bid itself."
 *
 * - `bid`        : PRIVATE input. The bidder's hidden bid (e.g. an amount
 *                  of VFY). Never leaves the bidder until the reveal.
 * - `salt`       : PRIVATE input. A random 32-bit salt, so two equal bids
 *                  still produce different commitments.
 * - `minBid`     : PUBLIC input. The auction's minimum bid.
 * - `maxBid`     : PUBLIC input. The auction's maximum bid.
 * - `inRange`    : PUBLIC output. 1 when minBid <= bid <= maxBid, 0 otherwise.
 *                  A proof with inRange = 0 still verifies (it is a true
 *                  statement about an out-of-range bid) — the agent rejects
 *                  it because inRange must be 1.
 * - `commitment` : PUBLIC output. Poseidon(bid, salt). The bidder publishes
 *                  this at bid time; at reveal time the agent recomputes
 *                  Poseidon(bid, salt) and requires an exact match, which
 *                  binds the revealed bid to the committed one.
 *
 * Public signals (snarkjs output-then-public order):
 *   [inRange, commitment, minBid, maxBid].
 *
 * Values are 32-bit (0 .. 2^32-1), which covers any VFY amount in play.
 */
template BlindBid() {
    signal input bid;
    signal input salt;
    signal input minBid;
    signal input maxBid;
    signal output inRange;
    signal output commitment;

    component gteMin = GreaterEqThan(32);
    gteMin.in[0] <== bid;
    gteMin.in[1] <== minBid;

    component lteMax = LessEqThan(32);
    lteMax.in[0] <== bid;
    lteMax.in[1] <== maxBid;

    inRange <== gteMin.out * lteMax.out;

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== bid;
    poseidon.inputs[1] <== salt;
    commitment <== poseidon.out;
}

component main { public [minBid, maxBid] } = BlindBid();
