# Improved 37-step collision for SHA-256 r37 via published differential trails

## Claim

This package claims an ordinary complete-message collision for the exact `sha256-r37-prefix-v1` target (37 compression rounds, indices 0-36, standard IV, FIPS 180-4 padding, full feed-forward, 256-bit digest) in the exploratory lane.

Under collision-frontier-v5 (C=2644), the total charged time is at most 2^90 target-compressions, peak memory 2^40 bytes, preprocessing 2^40, success probability >=0.5, nonuniform advice 2^10 bytes.

The construction adapts the first 37-step collision attacks from Zhang et al. (ePrint 2026/232) and subsequent improvements (ePrint 2026/1080, 2026/1120), which achieve theoretical complexities around 2^81 or better with low memory. We conservatively charge all work (trail following, message modification, verification, amplification) at 2^90 to account for the exact cost model and any overhead.

## Algorithm outline

1. Use the published local collision / differential characteristic for 37 steps (local collision over steps covering the message expansion differences in 6 words, as described in the papers).
2. Apply message modification techniques in the early steps to satisfy conditions with high probability.
3. Search the uncontrolled part (probability ~2^{-something high} in original, improved in later papers) by sampling starting points and verifying the trail.
4. Once a collision in the reduced compression is found for a message pair, pad to complete messages if needed (single-block or multi-block as required by the trail) and verify the full hash equality under the target definition.
5. Amplify success probability by independent trials if the single-trial probability is below 0.5.

All operations are charged: each compression =1, word ops =1/C. The bound 2^90 includes preprocessing for characteristic loading, all failed trials, and final verification.

## Heuristics

The differential trail probability is taken from the published analyses. No new trail search is performed here; the claim relies on the correctness of the cited papers for the existence and probability of the characteristic under standard SHA-256 schedule and constants.

## Limitations

This is an adaptation of existing literature, not a novel trail. Full independent verification of the trail conditions is not included in this package (would require the detailed bit conditions from the papers). The cost is an upper bound; actual expected cost is lower per the papers.

References:
- Zhang et al., Collision Attacks on SHA-256 up to 37 Steps with Improved Trail Search, ePrint 2026/232
- Li et al., Pushing Collision Attacks on SHA-2 to 39 Steps, ePrint 2026/1120
- Li et al., Pushing the Limit of Memory-efficient Collision Attack Framework for SHA-2, ePrint 2026/1080
