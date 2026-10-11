#!/usr/bin/env python3
"""Fill a frozen Yukon scalar-rescore preview offline using an explicit policy."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import re
import shlex
import sys
from typing import Any
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.scalar_score_resources import read_v5_score_resources
from scripts.scalar_scoring_policy import SCORE_METRIC, scalar_score, scoring_policy_metadata, validate_policy
from verifier.errors import VerificationError


def _object(value, fields, where, optional=()):
    if not isinstance(value, dict) or not set(fields) <= value.keys() or value.keys() - set(fields) - set(optional):
        raise VerificationError(f"{where}: incomplete or unexpected fields; use an unchanged Yukon version-1 preview")


def _identifier(value, where):
    try:
        if not isinstance(value, str):
            raise ValueError()
        UUID(value)
    except ValueError:
        raise VerificationError(f"{where}: expected a UUID") from None


def _hash(value, where, length=64):
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
        raise VerificationError(f"{where}: expected {length} lowercase hexadecimal characters")


def _finite(value, where):
    try:
        valid = type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        valid = False
    if not valid:
        raise VerificationError(f"{where}: expected a finite number")


def _old_score(entry, definitions, where):
    metrics = entry["metrics"]
    time, _ = read_v5_score_resources(metrics)
    marker_keys = {"scoringPolicyId", "scoringPolicySha256"}
    present = marker_keys & metrics.keys()
    if metrics.get("scoreMetric") == "timeLog2" and not present and "_scalarRescore" not in metrics:
        expected = time
    elif metrics.get("scoreMetric") == SCORE_METRIC and present == marker_keys:
        identifier, digest = metrics["scoringPolicyId"], metrics["scoringPolicySha256"]
        if not isinstance(identifier, str) or not isinstance(digest, str):
            raise VerificationError(f"{where}: malformed existing scoring policy marker")
        definition = definitions.get((identifier, digest))
        if definition is None:
            raise VerificationError(f"{where}: unrecognized existing projection; supply its exact --existing-policy definition")
        expected = scalar_score(metrics, definition)
    else:
        raise VerificationError(f"{where}: unsupported or incomplete existing score projection")
    if entry["oldScore"] != expected:
        raise VerificationError(f"{where}: oldScore disagrees with retained resources and recognized scoring policy")


def fill_plan(plan: Any, policy: Any, existing_policies=()) -> dict:
    """Copy a backend preview, changing only every null newScore.

    This checks the version-1 traversal contract and HashSmash resource/scoring
    semantics. Yukon's strict schema and locked dry-run remain authoritative for
    complete membership, authentic metrics and snapshot/metrics/approval hashes.
    metricsSha256 binds original PostgreSQL metrics-column text (UTF-8, no LF),
    not the parsed metrics projection. It, other backend hashes and policy.sourceRef
    are opaque here and never rewritten.
    """
    definition = validate_policy(policy)
    marker = scoring_policy_metadata(definition)
    definitions, identifiers = {}, {}
    for item in (definition, *existing_policies):
        item = validate_policy(item)
        identity = scoring_policy_metadata(item)
        identifier, digest = identity["scoringPolicyId"], identity["scoringPolicySha256"]
        if identifier in identifiers and identifiers[identifier] != digest:
            raise VerificationError("existing policy definitions reuse one ID for different definitions")
        identifiers[identifier] = digest
        definitions[(identifier, digest)] = item

    _object(plan, {"version", "benchmarkId", "challengeId", "snapshotSha256", "policy", "tracks"},
            "plan")
    if type(plan["version"]) is not int or plan["version"] != 1:
        raise VerificationError("plan: only Yukon version-1 previews are supported")
    _identifier(plan["benchmarkId"], "plan.benchmarkId")
    if plan["challengeId"] is not None:
        _identifier(plan["challengeId"], "plan.challengeId")
    _hash(plan["snapshotSha256"], "plan.snapshotSha256")
    _object(plan["policy"], {"id", "sourceRef", "definitionSha256", "scoreMetric",
                             "sourceCostModelId", "timeUnit"}, "plan.policy")
    if (plan["policy"]["id"] != marker["scoringPolicyId"]
            or plan["policy"]["definitionSha256"] != marker["scoringPolicySha256"]
            or plan["policy"]["scoreMetric"] != marker["scoreMetric"]
            or plan["policy"]["sourceCostModelId"] != definition["sourceCostModelId"]
            or plan["policy"]["timeUnit"] != definition["timeUnit"]):
        raise VerificationError("plan.policy: ID, definition hash, scoreMetric and resource units must match --policy exactly")
    if not isinstance(plan["policy"]["sourceRef"], str) or not plan["policy"]["sourceRef"].strip():
        raise VerificationError("plan.policy.sourceRef: missing operator provenance")
    if not isinstance(plan["tracks"], list) or not plan["tracks"]:
        raise VerificationError("plan.tracks: expected at least one track")

    result = deepcopy(plan)
    tracks, submissions = set(), set()
    for index, track in enumerate(result["tracks"]):
        where = f"tracks[{index}]"
        _object(track, {"benchmarkId", "description", "source", "baseline", "currentBest", "submissions"},
                where, {"nextDescription"})
        # Preserve both the frozen text and any operator-authored proposal exactly.
        # The backend schema/dry-run validates proposal length and nonblank content.
        for field in ("description", "nextDescription"):
            if field in track and not isinstance(track[field], str):
                raise VerificationError(f"{where}.{field}: expected a string")
        _identifier(track["benchmarkId"], f"{where}.benchmarkId")
        if track["benchmarkId"] in tracks:
            raise VerificationError(f"{where}: duplicate benchmarkId")
        tracks.add(track["benchmarkId"])
        _object(track["source"], {"url", "ref", "branch", "rootDir"}, f"{where}.source")
        for field, value in track["source"].items():
            if not isinstance(value, str) and not (field in {"branch", "rootDir"} and value is None):
                raise VerificationError(f"{where}.source.{field}: invalid frozen source value")
        if not isinstance(track["submissions"], list):
            raise VerificationError(f"{where}.submissions: expected a list")
        entries = [("baseline", track["baseline"]), ("currentBest", track["currentBest"])]
        entries += [(f"submissions[{i}]", entry) for i, entry in enumerate(track["submissions"])]
        for label, entry in entries:
            location = f"{where}.{label}"
            fields = {"oldScore", "newScore", "metrics", "metricsSha256"}
            if label.startswith("submissions["):
                fields.add("submissionId")
            _object(entry, fields, location)
            if "submissionId" in entry:
                _identifier(entry["submissionId"], f"{location}.submissionId")
                if entry["submissionId"] in submissions:
                    raise VerificationError(f"{location}: duplicate submissionId")
                submissions.add(entry["submissionId"])
            if entry["newScore"] is not None:
                raise VerificationError(f"{location}.newScore: already filled; use the original frozen preview")
            _finite(entry["oldScore"], f"{location}.oldScore")
            _hash(entry["metricsSha256"], f"{location}.metricsSha256")
            try:
                _old_score(entry, definitions, location)
                entry["newScore"] = scalar_score(entry["metrics"], definition)
            except VerificationError as error:
                raise VerificationError(f"{location}: {error}") from error
    if plan["benchmarkId"] not in tracks:
        raise VerificationError("plan.benchmarkId: anchor is missing from tracks")
    if plan["challengeId"] is None and len(tracks) != 1:
        raise VerificationError("plan: a standalone benchmark cannot have multiple tracks")
    return result


def read_json(path: Path) -> Any:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON property")
            value[key] = item
        return value

    def number(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("nonfinite JSON number")
        return value

    try:
        with path.open("rb") as source:
            data = source.read(64 * 1024 * 1024 + 1)
        if len(data) > 64 * 1024 * 1024:
            raise VerificationError("input JSON exceeds the 64 MiB file limit")
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_float=number,
                          parse_constant=number)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise VerificationError("input must be unambiguous finite UTF-8 JSON") from error


def write_new(path: Path, plan: dict) -> None:
    data = (json.dumps(plan, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("ascii")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True, help="unchanged backend preview with null newScore values")
    parser.add_argument("--policy", type=Path, required=True, help="explicit target scalar policy definition")
    parser.add_argument("--existing-policy", type=Path, action="append", default=[],
                        help="recognized existing scalar definition (repeat for earlier policies)")
    parser.add_argument("--out", type=Path, required=True, help="distinct new output file; never overwritten")
    args = parser.parse_args(argv)
    try:
        output = args.out.absolute()
        if output.resolve() in {path.resolve() for path in (args.plan, args.policy, *args.existing_policy)}:
            raise VerificationError("--out must differ from every input file")
        filled = fill_plan(read_json(args.plan), read_json(args.policy),
                           [read_json(path) for path in args.existing_policy])
        write_new(output, filled)
        entries = [entry for track in filled["tracks"]
                   for entry in (track["baseline"], track["currentBest"], *track["submissions"])]
        print(json.dumps({
            "output": str(output), "tracks": len(filled["tracks"]),
            "submissions": sum(len(track["submissions"]) for track in filled["tracks"]),
            "scores": len(entries),
            "increased": sum(entry["newScore"] > entry["oldScore"] for entry in entries),
            "decreased": sum(entry["newScore"] < entry["oldScore"] for entry in entries),
            "unchanged": sum(entry["newScore"] == entry["oldScore"] for entry in entries),
            "scoringPolicyId": filled["policy"]["id"],
            "scoringPolicySha256": filled["policy"]["definitionSha256"],
            "nextStep": f"Run in Yukon: bun run scalar-rescore dry-run --plan {shlex.quote(str(output))}",
            "databaseAccess": False,
        }, sort_keys=True))
        return 0
    except FileExistsError:
        print("Plan filling failed: output already exists; choose a distinct new file.", file=sys.stderr)
    except VerificationError as error:
        print(f"Plan filling failed: {error}", file=sys.stderr)
    except (OSError, ValueError, RecursionError):
        print("Plan filling failed: could not read inputs or write the new output file.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
