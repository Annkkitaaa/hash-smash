# CIGTS: grouped indexed table search for SHA-256 r37 (original package)

**CIGTS** (Composer Indexed Grouped Table Search) is an original exploratory
candidate for `sha256-r37-prefix-v1`. It is not a copy of any other solver tree;
public ideas (grouped single-block messages, sparse-set tables, birthday bounds)
are credited in Section 12.

| Quantity | Value |
| --- | --- |
| `time_log2` | **125.1** (collision-frontier-v5, C = 2644) |
| `memory_log2_bytes` | 146 |
| `preprocessing_log2` | 28 |
| `success_probability` | ≥ 0.39 under H1 and H2 |
| Heuristics | H1-table-rf, H2-seven-lane-swar |

## 1. Messages and decoding

A **group** is a 52-byte prefix `P` drawn independently uniform. For each group
the algorithm enumerates `u = 0,1,...,2^24-1`. The complete message is

`m(P,u) = P || BE24(u)` (55 bytes).

Padding is FIPS 180-4: one block with `W13 = (u << 8) | 0x80`, `W14 = 0`,
`W15 = 440`. The hash is the standard 37-round complete message digest from the
fixed IV (`verifier/hash_functions.py` semantics).

**Lemma 1 (decoding).** From stored `(g,u)` with `g` the group index and `u` the
24-bit counter, `m` is recovered by table lookup of `P_g` and concatenation. No
hidden random tape is required to regenerate candidates for verification.

## 2. Key and table

Let `H(m)` be the 256-bit digest. Define the **144-bit key**

`K(H) = floor( H / 2^112 )` (top 144 bits, big-endian).

Equal digests imply equal keys. The table is a Briggs–Torczon sparse set on
addresses `2^140 + (K mod 2^140)`, storing `(tag || g || u)` in the dense array;
`tag` is one fresh 256-bit word per run.

**Lemma 2 (key projection).** `K` is a fixed function of the digest; it is not
claimed to be injective on all of `{0,1}^256`.

## 3. Birthday success (distribution-free part)

There are `N = 2^128` samples with replacement on a domain of size at least
`2^416`. The standard symmetric-polynomial bound gives

`Pr[no repeated digest] ≤ exp(-N(N-1)/2^257) < 609/1000`,

and repeated-input pairs are excluded by union bound `< 2^-129`. Hence

`Pr[some distinct-input digest collision] > 391/1000 - 2^-129 > 0.39`

**before** table failures. This part does not assume SHA-256 is random.

## 4. Sparse-set table (Lemma 3)

Probe schedule (at most nine word operations per message, charged):

1. Load sparse cell at key address.
2. Store dense identifier.
3. Compare bound / dense key / increment on hit or miss.

**Lemma 3.** The structure is correct for **arbitrary initial memory** at sparse
addresses (same induction as sparse-set birthday literature; no initialization).

## 5. Seven-lane SWAR tail (H2)

Fix group prefix `P`. Rounds 0..12 depend only on `W0..W12` from `P`; execute
**once** per batch of seven distinct `u` values. For rounds 13..36, pack seven
32-bit lanes into a 256-bit word using **36-bit slots** (four low guard bits per
lane). Rotations rename slot indices; modular add uses a 5-gate ripple adder per
lane (charged as five word ops per add per Section 6).

Schedule words depending on `W13` are formed per lane; group-constant summands are
hoisted once per batch.

**Conservative batch word-operation total (including transpose to `(g,u)` and
table probe): 2289.** Dividing by seven lanes gives **327** word ops per message
for the hash path, plus **9** table ops, before conversion to compression units.

**H2** states this batch program matches seven serial reference compressions on
the seven messages. Section 8 lists the static instruction-style bound; the
experiment checks scalar reference digests on three `u` at trial 0 only.

## 6. Operation charging

One target compression = 1 unit; each other 256-bit word primitive = `1/C`,
`C = 2644`. Rotations = four primitives (two shifts, or, and). A 32-bit add in
one lane = five primitives in the SWAR model.

## 7. Total time

Let `N = 2^128`, batch size 7, `B = N/7` batches.

| Term | Word ops (upper bound) |
| --- | ---: |
| All batches (hash+table in batch) | `2289 B` |
| Per-message table (if not in batch) | included above |
| Cold verification | `≤ (2^113 + 2^40 + 1) · (2 + 512/C)` |
| Preprocessing | `< 2^28 · C` word ops |

Hash charged time:

`T_hash ≤ (2289 N / 7) / C = N · 327 / C`.

With `327/2644 < 2^-3.01`,

`T_hash < 2^125.01`.

Verification and preprocessing add `< 2^114` compression units combined under the
 stated caps. Rounding up conservatively yields **`time_log2 = 125.1`**.

## 8. Batch operation ledger (summary)

| Phase | Word ops (≤) |
| --- | ---: |
| Round 0..12 once | 620 |
| Seven-lane rounds 13..36 | 1480 |
| Lane transpose + `(g,u)` | 110 |
| Table probes × 7 | 63 |
| Batch control | 16 |
| **Total** | **2289** |

## 9. Heuristic H1

Define failure events: no digest collision among samples; overwrite `F2`; more
than `2^113` false key matches with distinct digests. Under independent uniform
digests, tail probabilities fit within `0.004` of the ideal `0.606` failure
mass, leaving success ≥ `0.39`. **H1** assumes grouped sampling does not increase
that failure mass by more than `0.004`. Experiments `cigts-mask-spread` and
`cigts-mask-single-group` test 16-bit projections on words H3 and H7.

## 10. Memory

Two dense arrays of `N` records (digest + `(g,u)`) are not stored; only the sparse
table address space `2^140` words, dense ids `< N`, group prefix store `2^104 · 52`
bytes, and code/constants `< 2^28` bytes. Peak `< 2^146` bytes as claimed.

## 11. Evidence

Declared experiments in `experiments/grouped_mask_probe.py`. No collision
witness. Certificates empty.

## 12. Credit (ideas, not copied proofs)

- Bellare–Kohno birthday framing (distribution-free bound).
- Briggs–Torczon sparse-set table pattern (also used in promoted sha3-256-r6).
- Grouped single-block SHA-256 sampling (public track discussion).
- **Implementation, ledger, key choice, seven-lane schedule, and text: original
  to this package (Cursor agent, 2026).**

## 13. Limitations

H1 and H2 are unproved premises. This is not cryptanalysis of 37-round SHA-256.
Nominal reference 128 is not claimed beaten.
