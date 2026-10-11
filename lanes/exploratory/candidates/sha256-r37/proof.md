# CIGTS v3: grouped indexed table search for SHA-256 r37

**CIGTS** (Composer Indexed Grouped Table Search) is an exploratory candidate for
`sha256-r37-prefix-v1`. It is a classical generic collision search with declared
heuristics **H1-table-rf** and **H2-eight-lane-swar**. Public patterns (grouped
single-block messages, Briggs–Torczon sparse-set tables, birthday bounds) are
credited in Section 14; the eight-lane SWAR program, ledger, experiments, and
this proof text are original to this package (Cursor agent, iteration v3).

| Quantity | Value |
| --- | --- |
| `time_log2` | **125.1** (cost model `collision-frontier-v5`, C = 2644) |
| Batch width | 8 messages sharing a 52-byte prefix |
| Batch word ops (trial 0 lock) | **2736** |
| `memory_log2_bytes` | 146 |
| `preprocessing_log2` | 28 |
| `success_probability` | ≥ 0.39 conditional on H1 and H2 |

No collision witness is asserted. Nominal reference 128 is not claimed beaten.

## 1. Target and notation

Work in classical 256-bit word RAM. One **target compression** is the profile
primitive: standard IV, FIPS 180-4 padding, rounds 0..36 inclusive with
feed-forward, full 256-bit digest. Other word operations cost 1/C compressions,
C = 2644.

`H(m)` denotes the complete 37-round hash. All digests are 256-bit big-endian
bytes. `popcount`, `log2`, and inequalities use exact real arithmetic; claimed
log exponents round **up** conservatively.

## 2. Messages and indexing (Lemma 1)

**Definition.** A **group prefix** `P` is 52 uniform independent bytes drawn once
per group. For `u ∈ {0,…,2^24−1}` define the complete message

`m(P,u) = P || BE24(u)` (55 bytes).

**Lemma 1 (domain and decoding).** (a) Every `m(P,u)` is in the profile message
domain and occupies exactly one 512-bit padded block (original bit length 440 =
55×8). (b) The map `(P,u) ↦ m(P,u)` is injective for fixed `P`. (c) Given stored
`(g,u)` with `g` the group index and `u` the inner counter, the algorithm can
reconstruct `m` using only `P_g` (the prefix of group `g`) and `u` with charged
operations bounded in Section 10; no hidden random tape is required for recovery.

*Proof.* (a) Padding appends `0x80`, zero fill to 56 mod 64, and 64-bit big-endian
bit length 440; this matches the reference one-block layout. (b) For fixed `P`,
bytes 52–54 are `BE24(u)`, so distinct `u` give distinct messages. Distinct
groups use independent `P`; collision of messages across groups requires equal
52-byte prefixes, an event charged under birthday/repetition bounds, not assumed
impossible. (c) `P_g` is retained for the active group batch; `u` is explicit in
the table record. QED.

**Global index.** Groups `g ∈ {0,…,2^104−1}`. Within group `g`, enumerate
`u = 0,…,2^24−1`. Total messages `N = 2^128`. Global index

`n(g,u) = (g ≪ 24) | u` (128 bits).

Processing order: increasing `g`, and within each group increasing `u` in batches
of eight consecutive values.

## 3. Key function

**Definition.** For digest bytes `H = (b_0,…,b_31)` define the **144-bit key**

`K(H) = Σ_{i=0}^{17} b_i · 2^{8(17−i)}` (big-endian prefix of the digest).

Equivalently `K(H) = ⌊int(H) / 2^112⌋`. Equal full digests imply equal keys.

**Remark.** This is a fixed projection, not a round-skip shortcut; the batch
evaluator still computes the full 37-round digest for scoring messages.

## 4. Sparse-set table (Lemma 2)

Candidates are processed in strict global order `cid = 0,1,…,N−1`. When
processing message with index `cid`, let `k = K(H)` be its key word (256-bit,
with `k ≥ 2^112` when key bits are stored right-aligned).

Use a Briggs–Torczon **sparse set** on 140-bit keys (organizer pattern; see
sha3-256-r6 exploratory Lemma 8). Address map:

- `DENSE[x]` for `x < N` stores `key(x)` at the word address `x`.
- `SPARSE[k′]` for `k′ = k − 2^112` in `[0,2^140)` holds the first candidate index
  with that key, at sparse address `k′ + 2^140`.

**Probe** (exactly nine word-RAM operations, charged per message):

```
s  = LOAD SPARSE[k′]           // arbitrary if never written
STORE DENSE[cid] = k
if s >= cid goto miss          // two ops: compare, branch
t  = LOAD DENSE[s]
if t != k goto miss            // three ops
// hit: first earlier candidate with key k is s
miss: STORE SPARSE[k′] = cid
cid = cid + 1
```

**Lemma 2 (sparse-set correctness, any initial memory).** At the probe of
candidate `cid` with key `k`: (a) for all `x < cid`, `DENSE[x] = key(x)`; (b) for
every key `k′` of some `x < cid`, `SPARSE[k′]` is the smallest such `x`; (c) the
probe **hits** iff ∃ `x < cid` with `key(x) = k`, and then returns that smallest
`x`.

*Proof.* Standard induction as in organizer sha3-256-r6 Lemma 8: writes to
`DENSE[cid]` occur only at probe of `cid`; misses store first owner of `k`; hits
read only `s < cid` with consistent `DENSE[s]`. Uninitialized `SPARSE` words are
valid loads; arbitrary contents either fail `s ≥ cid` or fail `DENSE[s] = k`. QED.

**Table charging.** Eight probes per SWAR batch ⇒ `8 × 9 = 72` word ops included
in the locked batch count 2736 (Section 8).

## 5. Algorithm CIGTS (pseudocode)

```
Preprocessing (once):
  Load program, constants K[0..36], IV; reserve sparse regions; draw group seeds.
  Charge ≤ 2^28 compression equivalents (Section 11).

F = 0  // verification counter cap witness

for g = 0 .. 2^104-1:
  Draw fresh 52-byte prefix P_g
  for u_base = 0, 8, 16, .., 2^24-8:
    u_list = [u_base .. u_base+7]
    // Eight-lane SWAR batch (Section 7)
    for lane in 0..7:
      compute H(P_g, u_list[lane])  // counted as batch amortization
      k = K(H)
      probe table with cid; on HIT with earlier index s:
        decode messages m_s, m_c from stored (g,u) records
        if H(m_s) == H(m_c) as full 256-bit digests:
          OUTPUT collision; STOP
        else:
          F += 1; if F > 2^113 + 2^40 + 1: FAIL
    // cid advanced 8 times inside batch table steps

FAIL if all N processed without collision
```

**Hit handling (charged verification).** On hit with earlier index `s` and current
index `cid`:

1. Reconstruct both 55-byte messages from `(g,u)` metadata (Lemma 1).
2. Compute `H(m_s)` and `H(m_c)` with two **full scalar** 37-round compressions
   (reference schedule, not SWAR), charged as 2 compressions plus at most 512/C
   ordinary ops each (conservative scalar upper bound from restriction text).
3. If digests equal, return collision. Else increment `F`.

At most `2^113 + 2^40 + 1` such verifications are allowed before failure (claim
restrictions); exceeding this aborts the algorithm.

## 6. Birthday success (distribution-free core)

Let `N = 2^128`. Conditional on **distinct message inputs** (not necessarily
distinct digests), the probability that **no** output collision occurs among `N`
i.i.d. samples is at most `exp(−N(N−1)/2^{257})` (elementary symmetric polynomial
bound; same as organizer merge baseline). For `N = 2^128` this is `< 0.606`; hence

`Pr[∃ output collision] ≥ 0.394 > 0.39`.

Repeated **inputs** (same message twice) do not count as collisions; the union
bound adds at most `N^2/2^{385} < 2^{−129}` to failure probability (domain size
`2^{384}` for `(P,u)` pairs with fixed-length encoding). Thus **without table
failures**, success probability exceeds 0.39.

## 7. Eight-lane SWAR batch (H2)

**Shared rounds 0..12.** For fixed prefix `P`, words `W_0..W_12` of the padded
block depend only on `P` (and fixed padding tail). The batch runs scalar rounds
0..12 **once**, producing chaining state `S_12`.

**Parallel rounds 13..36.** Eight messages differ only in `u`, hence in word `W_13`
(and schedule words `W_t` for `t ≥ 16`). Eight 32-bit lanes pack into one
256-bit word per register; each round applies the SHA-256 step lane-wise with the
same `K[i]` broadcast. Schedule extension for `t = 16..36` is computed in parallel
on packed lanes.

**Feed-forward.** After round 36, add IV words to each lane’s working state and
serialize eight digests.

**H2 (score-critical).** For every `P` and every eight values `u_0,…,u_7`, the
batch output digests equal `H(P,u_i)` from the scalar reference compression
(Section 1 primitive).

**Evidence.** `experiments/grouped_mask_probe.py` trial 0 executes one batch on
eight diverse `u`, counts word operations with the documented tick rules, asserts
`batch_ops = 2736` exactly, and compares all eight digests to `digest55` (scalar
reference in the same file, cross-checked against organizer `verifier/hash_functions`
during development).

**Op tick rules (256-bit word RAM).** One tick per parallel lane-wise op bundle:
`xor/and/not` tick 1; `add8` tick 4; `ror8` tick 3; `shr8` tick 2; scalar
rounds 0..12 use explicit scalar ticks as in the program. Batch control tick 22
before parallel phase; table ticks `9 × 8` after feed-forward.

## 8. Batch ledger (2736 word ops)

Let `B = N/8 = 2^125` batches.

| Phase | Charged word ops (per batch) |
| --- | ---: |
| Batch control | 22 |
| Prefix parse + scalar rounds 0..12 (once) | 520 |
| Parallel schedule words 16..36 | 630 |
| Parallel rounds 13..36 (24 steps) | 1480 |
| Feed-forward 8 lanes | 64 |
| Table probes 8 × 9 | 72 |
| **Total** | **2736** |

Per-message amortized word ops: `2736/8 = 342`.

Hashing charge:

`T_hash ≤ B · 2736 / C = N · 342 / C`.

Now `342/2644 < 2^{−2.95}`, hence `T_hash < 2^{125.05}` compression units.

## 9. Verification and preprocessing charges

**Verification.** At most `V = 2^113 + 2^40 + 1` false hits charged. Each
verification ≤ 2 compressions + 512/C ordinary ops `< 2.2` compression units.
Hence

`T_ver ≤ V · 2.2 < 2^{114.2}`.

**Preprocessing.** Group seed expansion, code, constants, table region reservation:
`< 2^{28}` compression units (claim field).

**Total.**

`T ≤ 2^{125.05} + 2^{114.2} + 2^{28} < 2^{125.1}`,

so **`time_log2 = 125.1`** is a conservative upper bound.

## 10. Heuristic H1 (table tails)

Define failure events beyond “no digest collision”:

- **F1:** no digest collision among the `N` samples (bounded §6).
- **F2:** an overwrite: second probe of a colliding key before the first is verified
  (table miss-path stores new owner).
- **F3:** more than `2^113` false 144-bit key matches among unrelated digests.
- **F4:** verification counter exceeds `2^40` on equal-key unequal-digest pairs.

**H1-table-rf (score-critical).** Over fresh group prefixes and table randomness,
`Pr[F2 ∨ F3 ∨ F4]` exceeds the uniform random-function model value by at most
**0.004**, so total failure probability remains `< 0.61` and success `> 0.39`.

**Scope and evidence.** Experiments `cigts-mask-spread` (32 messages, 16-bit mask)
and `cigts-mask-single-group` (512 consecutive `u`) exercise grouped sampling and
masked agreement statistics on the trusted digest; they support extrapolation only
(Section 12). They do **not** prove 144-bit key saturation.

## 11. Memory

Sparse `SPARSE` over `2^140` addresses (256-bit words), dense `DENSE` for `N`
indices, batch buffers, and group prefix storage fit within `2^146` bytes as
256-bit words addressed sparsely; **memory is reported only** and does not enter
the scalar score.

## 12. Experiments (declared only)

Program: `experiments/grouped_mask_probe.py` (stdlib only). Trial 0 on every run:
eight-lane batch op lock and digest cross-check. Mask experiments return
organizer-verified message pairs when low-bit masked digest words agree; they
test independence heuristics, not full collisions.

## 13. Limitations

Not cryptanalysis of 37-round SHA-256. H1 and H2 are unproved premises with
stated scope. Trial 0 samples eight `u` values, not all `2^24`. Reaching ~124
would require round-skip keys and/or large emitted bit-sliced circuits beyond this
package.

## 14. Credit

- Birthday bound: standard symmetric-polynomial argument (organizer baselines).
- Sparse-set table: Briggs–Torczon / organizer sha3-256-r6 exploratory Lemma 8
  pattern (no code copied).
- Grouped single-block messages: public HashSmash track convention.
- **Eight-lane SWAR, ledger, experiments, proof: original (CIGTS v3).**
