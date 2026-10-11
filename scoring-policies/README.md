# Scalar scoring policy definitions

The approved original-challenge policy is
[hashsmash-scalar-tm-v1](./hashsmash-scalar-tm-v1.json):

```text
score = timeLog2 + max(0, memoryLog2Bytes - 20)
```

Memory uses **1 MiB = 1,048,576 bytes**, with a minimum of one memory unit.
Computation uses existing reviewed v5 target-compression equivalents. Both
resources have equal multiplicative weight; lower scores are better. The
immutable definition hash is
`65f6bd3eb8260395d5a9520ebe14be10f68efba6bf4625d9cebef2221b832c2d`.
The active loader checks this ID/hash and fails closed if the definition changes.
This source describes future evaluations; deploying it and migrating published
scores require the separate authorized operator rollout.

The [schema](./scalar-time-memory-v1.schema.json) requires every parameter:

| Field | Meaning |
| --- | --- |
| `id` | Immutable public policy identifier |
| `version` | Definition format version, currently `1` |
| `formula` | `timeLog2 + log2(memoryUnits)` |
| `sourceCostModelId` | `collision-frontier-v5` |
| `timeUnit` | `target-compressions` |
| `memoryUnitBytes` | Positive integer bytes per normalized memory unit |
| `minimumMemoryUnits` | `1` floors memory at one normalized unit; `null` permits fractional units |

`memoryUnits` is the existing memory-byte bound divided by `memoryUnitBytes`,
with the stated floor applied. Equal multiplicative time-memory weighting is
fixed by this formula. The helper calculates entirely in the log domain:

```text
normalizedMemoryLog2 = memoryLog2Bytes - log2(memoryUnitBytes)
if minimumMemoryUnits is 1:
    normalizedMemoryLog2 = max(0, normalizedMemoryLog2)
score = timeLog2 + normalizedMemoryLog2
```

The generic offline helper requires an explicit definition, with no implicit
rounding or parameters. Its schema supports prior or artificial definitions with
fractional units, which can produce a negative finite scalar. The approved policy
uses the floor above. Resource exponents remain finite and nonnegative; nonfinite
results are rejected. The [organizer fixture](../tests/fixtures/scalar-scoring/policy.json)
uses an artificial 1 KiB unit and is not a public scoring rule.

The pure [helper](../scripts/scalar_scoring_policy.py) accepts the full explicit
definition and existing official resource metrics. It rejects incompatible
resource models or units and never fills missing memory, reparses candidates,
changes reviewed bounds or consults judge reconstructions. The caller must
independently verify the official source and its provenance; numeric validation
alone does not authenticate a result.

The definition hash is SHA-256 of `verifier.io.canonical_json_bytes(definition)`:
ASCII JSON with sorted keys, compact separators, integer parameter spelling and
**one trailing LF**. All permitted string values are ASCII. Public consumers
must recognize the exact policy ID and hash together. Unknown or incomplete
markers must not be interpreted as historical time-only scores.

The scoring projection uses three flat fields inside score `metrics`:

```json
{
  "scoringPolicyId": "hashsmash-scalar-tm-v1",
  "scoringPolicySha256": "65f6bd3eb8260395d5a9520ebe14be10f68efba6bf4625d9cebef2221b832c2d",
  "scoreMetric": "normalizedTimeMemoryLog2"
}
```

The top-level `score` remains
the authoritative scalar; no duplicate normalized scalar is added to metrics.
The projection is separate from `costModelId`, `timeUnit`, `timeLog2`,
`memoryLog2Bytes`, package/target/judge/dossier fingerprints, and qualification.
Historical migration retains these original fields and artifacts and records
its previous scoring projection separately in the operator's audit. It does
not imply that a new judge reviewed the result.

The direct CLI and pipeline share `verifier.score.build_score`. Future target
configuration fingerprints explicitly bind the approved policy JSON and both
`scripts/scalar_scoring_policy.py` and `scripts/scalar_score_resources.py`, in
addition to the existing checker and review sources. Historical rows retain their
original evidence fingerprints during migration. Judge `normalized_score_log2`
and nominal security/reference fields retain their computation meanings; the
nominal reference does not include a memory bound or combined-score baseline.
The separate trusted Pareto successor's `timeLog2` objective continues to use the
time bound without scalar-policy markers, including its Orchard accounting path.
The original v5 cost-model file and resource accounting stay unchanged.

[Golden vectors](../tests/fixtures/scalar-scoring/approved-policy-vectors.json)
cover the floor boundary, fractional exponents and high memory. They are artificial
arithmetic fixtures, not qualified attacks or historical artifacts.

## Offline Yukon plan filling

The backend's `scalar-rescore preview` produces a frozen plan with `newScore: null`
for each baseline, current incumbent and scored submission. Once the operator has
an explicit policy definition, fill all proposed values without database access:

```sh
python3 scripts/fill_scalar_rescore_plan.py \
  --plan /path/to/frozen-preview.json \
  --policy /path/to/scalar-policy-definition.json \
  --out /path/to/new-filled-plan.json
```

`--policy` is the complete definition described above. This differs from the
backend preview's policy-reference JSON, which contains `id`, `sourceRef`,
`definitionSha256`, and `scoreMetric`. The reference's ID, hash and metric must
match the full definition exactly. Its `sourceRef` remains the operator's
provenance reference and is preserved unchanged.

The filler requires compatible v5 time and memory metrics and a consistent existing
score. Original `scoreMetric: timeLog2` records must have `oldScore == timeLog2`
and no scalar projection markers. A previously normalized record requires its
exact policy ID and hash, with `oldScore` matching that definition applied to the
retained bounds. The target definition is recognized automatically; supply any
other existing definitions explicitly with repeated
`--existing-policy /path/to/previous-definition.json` arguments. Unknown, partial
or conflicting markers fail closed. Historical review conclusions are not
revalidated or replaced by the filler.

Every proposal must initially be null. Incomplete entries, unknown structural
fields, duplicate identities, nonfinite inputs or results and a mismatched policy
stop without emitting a plan. The current incumbent is calculated from its own
record; a better historical submission never replaces it. The output preserves
all input identities, row order, the supplied metrics projection, source references and frozen hashes,
changing only each `newScore`. Each track's required `description` is the exact
frozen existing text. An optional operator-authored `nextDescription` is preserved
exactly, including whitespace; the filler never generates, trims or applies it.
The backend accepts proposals of 1–10,000 characters with nonwhitespace content,
validates them in its strict schema and applies them in the maintenance transaction.
Omitting `nextDescription` leaves that track's description unchanged. Parent/operator
populates approved descriptions from the final manifest separately; the filler
still changes only score proposals. JSON formatting may change. Input JSON rejects
duplicate keys and nonfinite values and is limited to 64 MiB per file.

The destination must be a distinct new file. It is created exclusively with mode
`0600`; existing files and final-path symlinks are refused. The printed JSON summary
reports track, submission and score counts, increases/decreases/ties, policy
identity, and the next Yukon `scalar-rescore dry-run --plan` command. No individual score values or
metrics are dumped to stdout.

The filler checks the version-1 traversal contract and HashSmash arithmetic. The
backend's strict schema and locked dry-run remain authoritative for authentic
metrics, complete membership, stale state and the approval hash. In particular,
`metricsSha256` is SHA-256 of the original PostgreSQL metrics column's `::text`
UTF-8 bytes without a trailing LF; SQL NULL uses the literal bytes `null`. It must
remain opaque: parsed `plan.metrics` can round unrelated enormous integers, so
neither Python nor JavaScript may reconstruct this digest from that projection.
`metricsSha256` and the exact raw-row `snapshotSha256` are preserved unchanged.
The backend applies SQL JSONB patches to the original metrics column, preserving
unrelated exact numbers instead of writing the parsed projection back to the DB.
The approval plan hash uses Yukon's sorted JavaScript JSON without LF; the
explicit mathematical definition hash uses the LF described above.

Run the backend dry-run in the maintained environment after filling, review its
exact result and approval hash, and apply only through the separate authorized
operator procedure. If state changed, obtain a fresh preview and fill a new file.
This command has no DB connection, source activation, rejudging or apply operation.
