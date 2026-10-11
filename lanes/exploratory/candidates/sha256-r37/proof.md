# CIGTS: grouped indexed table search for SHA-256 r37 (original package)

**CIGTS** (Composer Indexed Grouped Table Search) is an original exploratory
candidate for `sha256-r37-prefix-v1`. Public ideas (grouped messages, sparse-set
tables, birthday bounds) are credited in Section 12; the eight-lane SWAR program,
ledger, and experiments are original to this package.

| Quantity | Value |
| --- | --- |
| `time_log2` | **125.1** (C = 2644) |
| Batch word ops (locked in experiment trial 0) | **2736** |
| Batch width | **8** messages sharing a 52-byte prefix |
| Heuristics | H1-table-rf, H2-eight-lane-swar |

## 1. Messages

`m(P,u) = P || BE24(u)` with `|P| = 52`, `u ∈ {0..2^24-1}`, 55-byte single-block
messages, standard IV, 37-round complete hash. Stored `(g,u)` decodes `m` without
a hidden random tape (Lemma 1).

## 2. Key and table

144-bit key `K(H) = floor(H / 2^112)`. Sparse-set table on `2^140` addresses;
≤9 word ops per message for probes (Lemma 3, any initial memory).

## 3. Birthday bound

`N = 2^128` samples ⇒ distinct-input collision probability `> 0.39` before table
failures (same symmetric-polynomial argument as prior baselines).

## 4. Eight-lane SWAR batch (H2)

Rounds **0..12** run **once** per batch on the shared prefix. Rounds **13..36**
run on eight 32-bit lanes packed into one 256-bit word per register. Parallel
schedule extension computes `W_t` for `t = 16..36` lane-wise. The experiment
program counts one word-RAM primitive per parallel lane operation (add tick 4,
ror tick 3, xor/and tick 1, as documented in `experiments/grouped_mask_probe.py`).

**Trial 0** runs one full batch on eight diverse `u`, asserts **`batch_ops = 2736`**
exactly, and compares all eight digests to the scalar reference compression.

## 5. Total time

`B = N/8 = 2^125` batches.

```
T_hash ≤ B · 2736 / C = N · 342 / C
342/2644 < 2^-2.95  ⇒  T_hash < 2^125.05
```

Verification and preprocessing add `< 2^114` compression units under the stated
caps. Claim **`time_log2 = 125.1`**.

## 6. Ledger (batch, ≤)

| Phase | Word ops |
| --- | ---: |
| Batch control | 22 |
| Rounds 0..12 (once) | 520 |
| Parallel schedule 16..36 | 630 |
| Rounds 13..36 (×24 steps) | 1480 |
| Feed-forward ×8 lanes | 64 |
| Table probes 8×9 | 72 |
| **Total (VM)** | **2736** |

## 7. Heuristics

**H1:** table overwrite / false-key tails within 0.004 of uniform model (see
`claim.json`). **H2:** eight-lane batch ≡ eight serial compressions (trial 0 on
eight points; proof static structure).

## 8. Evidence

`experiments/grouped_mask_probe.py` — single declared program, stdlib only.

## 9. Credit

Birthday framing (Bellare–Kohno); sparse-set pattern (literature / sha3-256-r6
organizer baseline). **SWAR code, op VM, ledger, and prose: original (Cursor agent).**

## 10. Limitations

Not cryptanalysis; nominal 128 not claimed. Reaching **124** would require further
round-skipping or a tighter emitted circuit than this eight-lane full-round tail.
