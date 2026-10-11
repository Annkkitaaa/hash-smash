# CIGTS v4: grouped indexed table search for SHA-256 r37

**CIGTS** (Composer Indexed Grouped Table Search), iteration **v4**, fixes the v3
evaluability defects: cross-group message recovery via **deterministic** group
prefixes, **sequential** table probes inside each eight-message batch, a **run tag**
in table keys, and a **single** shared `W_0..W_12` parse per batch (measured
**2723** word ops, trial 0 lock).

| Quantity | Value |
| --- | --- |
| `time_log2` | **125.1** (`collision-frontier-v5`, C = 2644) |
| Batch word ops (trial 0) | **2723** |
| `memory_log2_bytes` | 146 |
| `preprocessing_log2` | 28 |
| `success_probability` | ≥ 0.39 conditional on H1 and H2 |

No witness. Nominal 128 not claimed beaten.

## 1. Notation

Classical 256-bit word RAM; one target compression = profile 37-round complete
hash; other word ops cost 1/C, C = 2644. `H(m)` is the full digest.

## 2. Run coins and group prefixes (Lemma 1)

At start, draw independent uniform 256-bit words **S0** and **S1** (charged in
preprocessing). Draw independent uniform 256-bit **T** (table tag; stored for the
run).

For each group index `g ∈ {0,…,2^104−1}` define the **52-byte prefix**

`P_g = Trunc_52( H( S0 || BE104(g) || S1 ) )`,

where `H` is the target complete hash on the 24-byte message
`S0 || BE104(g) || S1` (one padded block), and `Trunc_52` takes the first 52
digest bytes. **Charge one target compression per group** when forming `P_g`
(Section 9).

For `u ∈ {0,…,2^24−1}` the complete message is `m(g,u) = P_g || BE24(u)` (55 bytes).

**Lemma 1.** (a) Each `m(g,u)` is a valid single-block domain message. (b) For fixed
`g`, `(P_g,u) ↦ m` is injective. (c) For any global index `n = (g≪24)|u` stored at
table time, both messages in a verification step are rebuilt as
`m(g_s,u_s)` and `m(g_c,u_c)` using **only** `(S0,S1,n)` and the public map above;
no discarded random tape is needed.

*Proof.* (a) Standard padding at 440 bits. (b) Distinct `u` on fixed `P_g`. (c)
Decode `g = n ≫ 24`, `u = n & (2^24−1)`; recompute `P_g` from `(S0,S1,g)`; append
`BE24(u)`. QED.

**Randomness.** Coins `(S0,S1)` make the family `{P_g}` an independent uniform
translate of the 52-byte space (standard PRF-from-random-oracle heuristic for
independent SHA-256 outputs on distinct inputs; the **birthday** core §6 remains
distribution-free on outputs; group-prefix independence is disclosed in H1 scope).

## 3. Keys and tagged sparse-set table

**Digest key:** `K(H) = ⌊int(H)/2^112⌋` (144 bits from bytes 0..17).

**Table key word:** `κ(H) = (K(H) XOR (T mod 2^144)) + 2^112` so sparse addresses
use 140 low bits of `κ` after subtracting `2^112`, as in Section 4.

Candidates are processed in global order `cid = 0,…,N−1`, `N = 2^128`. Within
each batch of eight consecutive `(g,u)` values, probes run **in lane order**
`cid, cid+1, …, cid+7` (not parallel).

**Lemma 2 (sparse set).** Same 9-op probe as organizer sha3-256-r6 Lemma 8 on
`DENSE[cid]` and `SPARSE[κ′]`; correctness for arbitrary initial `SPARSE` memory
holds unchanged.

## 4. Algorithm

```
Preprocess: load code; draw S0, S1, T; reserve tables; charge ≤ 2^28 (§9)
F = 0
cid = 0
for g = 0 .. 2^104-1:
  compute P_g from (S0,S1,g) with one charged H (§9)
  for u_base = 0, 8, .., 2^24-8:
    u_list = [u_base .. u_base+7]
    (D_0..D_7), batch_ops = SWAR_batch(P_g, u_list)   // §7, 2723 ops + 72 table
    for j = 0 .. 7:
      κ = key from D_j and T
      probe sparse set for cid; on HIT with earlier s:
        rebuild m_s, m_c from (S0,S1,s), (S0,S1,cid)
        two scalar H verifications; equal 256-bit digests => OUTPUT
        else F++; if F > 2^113 + 2^40 + 1: FAIL
      cid++
FAIL if no collision
```

**Verification charge:** two scalar compressions plus ≤512/C word ops each,
≤ `2^113 + 2^40 + 1` times (claim restrictions).

## 5. Birthday core (distribution-free)

Among `N = 2^128` i.i.d. message outputs (conditional on distinct inputs), no
collision probability ≤ `exp(−N(N−1)/2^257) < 0.606`; hence digest collision
probability ≥ **0.394 > 0.39** before table-tail events. Repeated-input pairs
add ≤ `2^−129` to failure.

## 6. Eight-lane SWAR (H2)

One parse of `W_0..W_12` from `P_g`; scalar rounds 0..12 once; parallel schedule
16..36 and rounds 13..36 on eight lanes; feed-forward; **72** table op ticks
(`8×9`) included in the locked total.

**Trial 0** in `grouped_mask_probe.py` asserts `batch_ops = 2723` and eight scalar
cross-checks.

**Ledger (per batch, ≤):**

| Phase | Ops |
| --- | ---: |
| Control | 22 |
| Prefix + scalar 0..12 | 507 |
| Parallel schedule | 630 |
| Parallel rounds 13..36 | 1480 |
| Feed-forward | 64 |
| Table 8×9 | 72 |
| **Total** | **2723** |

Amortized **2723/8 = 340.375** word ops per message in the batch phase.

`T_batch ≤ (N/8)·2723/C = N·340.375/C < N·2^−2.96/C` ⇒ **< 2^125.04** units.

**Group prefixes:** `2^104` compressions `< 2^104` units.

**Verification + preprocessing:** `< 2^114.2 + 2^28` (§9).

**Total `< 2^125.1`** ⇒ claim **`time_log2 = 125.1`**.

## 7. Heuristic H1

Score-critical: table overwrite, false 144-bit key matches, and tag-garbage tails
(F2–F4 in v3) raise failure probability by at most **0.004** over the uniform
random-function model for keyed probes. **F1** (no digest collision) is handled in
§5, not as a table heuristic.

Experiments `cigts-mask-spread` and `cigts-mask-single-group` give 16-bit masked
support only.

## 8. Memory, experiments, credit

Memory `2^146` bytes reported only (sparse regions, `S0,S1,T`, batch buffers).

Stdlib experiment program only; trial 0 op lock.

Credit: birthday bound (organizer baselines); sparse-set (sha3-256-r6 pattern);
grouped messages (track convention); **v4 proof, SWAR, experiments (Cursor agent).**

## 9. Limitations

H1, H2 unproved; trial 0 samples eight `u`; not cryptanalysis.
