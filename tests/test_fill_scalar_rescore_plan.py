"""Artificial Yukon plans; no database, historical submission or model calls."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from scripts.fill_scalar_rescore_plan import fill_plan, main, read_json
from scripts.scalar_scoring_policy import scalar_score, scoring_policy_metadata
from verifier.errors import VerificationError

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    policy = json.loads((ROOT / "tests/fixtures/scalar-scoring/policy.json").read_text())
    marker = scoring_policy_metadata(policy)

    def identifier(value):
        return f"10000000-0000-4000-8000-{value:012d}"

    def entry(time, memory, submission=None):
        metrics = {
            "costModelId": "collision-frontier-v5", "timeUnit": "target-compressions",
            "scoreMetric": "timeLog2", "timeLog2": time, "memoryLog2Bytes": memory,
            "reviewStatus": "plausible_not_refuted", "qualificationPolicy": "paired-lanes-v1",
            "inputPackageSha256": "a" * 64, "targetConfigSha256": "b" * 64,
            "judgeConfigSha256": "c" * 64, "dossierSha256": "d" * 64,
            "opaque": {"retained": [None, True, "σ\nfixture", {"key": 1.5}]},
        }
        value = {"oldScore": time, "newScore": None, "metrics": metrics, "metricsSha256": "e" * 64}
        if submission is not None:
            value["submissionId"] = identifier(submission)
        return value

    plan = {
        "version": 1, "benchmarkId": identifier(1), "challengeId": identifier(10),
        "snapshotSha256": "f" * 64,
        "policy": {"id": marker["scoringPolicyId"], "definitionSha256": marker["scoringPolicySha256"],
                   "scoreMetric": marker["scoreMetric"], "sourceRef": "organizer fixture definition",
                   "sourceCostModelId": policy["sourceCostModelId"], "timeUnit": policy["timeUnit"]},
        "tracks": [
            {"benchmarkId": identifier(1), "description": "Original organizer fixture description.",
             "source": {"url": "https://example.test/organizer-fixture", "ref": "1" * 40, "branch": "main", "rootDir": None},
             "baseline": entry(100, 20), "currentBest": entry(90, 8),
             "submissions": [entry(80, 30, 101), entry(70, 12, 102)]},
            {"benchmarkId": identifier(2), "description": "",
             "source": {"url": "https://example.test/organizer-fixture", "ref": "2" * 40, "branch": None, "rootDir": "fixture"},
             "baseline": entry(100, 0), "currentBest": entry(60, 25),
             "submissions": [entry(50, 40, 201)]},
        ],
    }
    return plan, policy


def entries(plan):
    return [entry for track in plan["tracks"]
            for entry in (track["baseline"], track["currentBest"], *track["submissions"])]


class ScalarRescorePlanTests(unittest.TestCase):
    def test_fills_all_entries_without_changing_frozen_plan_or_metrics(self):
        plan, policy = fixture()
        original = deepcopy(plan)
        result = fill_plan(plan, policy)
        self.assertEqual(plan, original)
        self.assertEqual([entry["newScore"] for entry in entries(result)], [110, 90, 100, 72, 100, 75, 80])
        self.assertEqual(result["tracks"][0]["currentBest"]["newScore"], 90)
        self.assertNotEqual(result["tracks"][0]["currentBest"]["newScore"],
                            min(item["newScore"] for item in result["tracks"][0]["submissions"]))
        for entry in entries(result):
            entry["newScore"] = None
        self.assertEqual(result, original)

    def test_preserves_frozen_and_optional_proposed_descriptions_exactly(self):
        plan, policy = fixture()
        plan["tracks"][0]["description"] = "  Original σ description.\n"
        plan["tracks"][0]["nextDescription"] = "  Minimize timeLog2 + max(0, memoryLog2Bytes - 20). 🧮\n"
        original = deepcopy(plan)
        result = fill_plan(plan, policy)
        self.assertEqual(plan, original)
        self.assertEqual(result["tracks"][0]["description"], original["tracks"][0]["description"])
        self.assertEqual(result["tracks"][0]["nextDescription"], original["tracks"][0]["nextDescription"])
        self.assertEqual(result["tracks"][1]["description"], "")
        self.assertNotIn("nextDescription", result["tracks"][1])
        for entry in entries(result):
            entry["newScore"] = None
        self.assertEqual(result, original)

    def test_preserves_raw_postgresql_metrics_digest_despite_lossy_js_projection(self):
        plan, policy = fixture()
        raw = (b'{"costModelId":"collision-frontier-v5","timeUnit":"target-compressions",'
               b'"scoreMetric":"timeLog2","timeLog2":100,"memoryLog2Bytes":20,'
               b'"exactUnrelatedInteger":9007199254740993}')
        entry = plan["tracks"][0]["baseline"]
        entry["metrics"] = json.loads(raw)
        # Simulate the backend JavaScript projection of exact PostgreSQL JSONB.
        entry["metrics"]["exactUnrelatedInteger"] = 9007199254740992
        entry["metricsSha256"] = hashlib.sha256(raw).hexdigest()
        result = fill_plan(plan, policy)["tracks"][0]["baseline"]
        self.assertEqual(result["newScore"], 110)
        self.assertEqual(result["metrics"], entry["metrics"])
        self.assertEqual(result["metricsSha256"], hashlib.sha256(raw).hexdigest())
        projected = json.dumps(result["metrics"], separators=(",", ":")).encode()
        self.assertNotEqual(result["metricsSha256"], hashlib.sha256(projected).hexdigest())

    def test_identical_retained_entries_receive_identical_scores(self):
        plan, policy = fixture()
        plan["tracks"][0]["currentBest"] = deepcopy(plan["tracks"][0]["baseline"])
        filled = fill_plan(plan, policy)["tracks"][0]
        self.assertEqual(filled["baseline"], filled["currentBest"])

    def test_prior_projection_requires_exact_explicit_definition(self):
        plan, policy = fixture()
        previous = {**policy, "id": "organizer-previous-v1", "memoryUnitBytes": 2048, "minimumMemoryUnits": None}
        entry = plan["tracks"][0]["currentBest"]
        entry["metrics"].update(scoring_policy_metadata(previous))
        entry["metrics"]["_scalarRescore"] = [{"version": 1, "planSha256": "9" * 64}]
        entry["oldScore"] = scalar_score(entry["metrics"], previous)
        with self.assertRaisesRegex(VerificationError, "--existing-policy"):
            fill_plan(plan, policy)
        result = fill_plan(plan, policy, [previous])
        self.assertEqual(result["tracks"][0]["currentBest"]["oldScore"], 87)
        self.assertEqual(result["tracks"][0]["currentBest"]["newScore"], 90)
        self.assertEqual(result["tracks"][0]["currentBest"]["metrics"], entry["metrics"])
        with self.assertRaisesRegex(VerificationError, "reuse one ID"):
            fill_plan(plan, policy, [{**policy, "memoryUnitBytes": 2048}])

    def test_target_policy_can_recognize_an_existing_projection(self):
        plan, policy = fixture()
        entry = plan["tracks"][0]["baseline"]
        entry["metrics"].update(scoring_policy_metadata(policy))
        entry["oldScore"] = scalar_score(entry["metrics"], policy)
        self.assertEqual(fill_plan(plan, policy)["tracks"][0]["baseline"]["newScore"], entry["oldScore"])

    def test_policy_reference_must_match_definition_and_resource_units(self):
        for field in ("id", "definitionSha256", "scoreMetric", "sourceCostModelId", "timeUnit"):
            plan, policy = fixture()
            plan["policy"][field] = "wrong"
            with self.subTest(field=field), self.assertRaisesRegex(VerificationError, "match --policy"):
                fill_plan(plan, policy)

    def test_invalid_or_inconsistent_existing_scores_and_resources_fail(self):
        changes = [
            lambda e: e.update(oldScore=99), lambda e: e.update(oldScore=True),
            lambda e: e.update(oldScore=float("inf")), lambda e: e.update(newScore=110),
            lambda e: e["metrics"].pop("memoryLog2Bytes"),
            lambda e: e["metrics"].update(memoryLog2Bytes=True),
            lambda e: e["metrics"].update(memoryLog2Bytes=float("nan")),
            lambda e: e["metrics"].update(costModelId="collision-frontier-v4"),
            lambda e: e["metrics"].update(timeUnit="word-operations"),
            lambda e: e["metrics"].update(scoreMetric="unknown"),
            lambda e: e["metrics"].update(scoringPolicyId="unknown"),
            lambda e: e["metrics"].update(_scalarRescore=[]),
            lambda e: e["metrics"].update(scoringPolicySha256="a" * 64), lambda e: e.update(metrics=None),
        ]
        for index, change in enumerate(changes):
            plan, policy = fixture()
            change(plan["tracks"][0]["baseline"])
            with self.subTest(case=index), self.assertRaises(VerificationError):
                fill_plan(plan, policy)

    def test_incomplete_unexpected_or_duplicate_records_fail(self):
        changes = [
            lambda p: p.update(version=2), lambda p: p.update(version=True),
            lambda p: p.update(unknown="not a backend field"), lambda p: p.update(tracks=[]),
            lambda p: p.update(snapshotSha256="wrong"), lambda p: p.update(nextSourceRef="main"),
            lambda p: p.update(nextSourceRef="7" * 40),
            lambda p: p.update(challengeId=None), lambda p: p.update(benchmarkId="not a UUID"),
            lambda p: p["policy"].pop("sourceRef"), lambda p: p["policy"].pop("sourceCostModelId"),
            lambda p: p["policy"].pop("timeUnit"), lambda p: p["tracks"][0].pop("currentBest"),
            lambda p: p["tracks"][0]["source"].pop("branch"),
            lambda p: p["tracks"][0].pop("description"),
            lambda p: p["tracks"][0].update(description=None),
            lambda p: p["tracks"][0].update(nextDescription=False),
            lambda p: p["tracks"][0]["baseline"].pop("newScore"),
            lambda p: p["tracks"][0]["baseline"].update(metricsPatch={}),
            lambda p: p["tracks"][0]["submissions"][0].pop("submissionId"),
            lambda p: p["tracks"].append(deepcopy(p["tracks"][0])),
            lambda p: p["tracks"][1]["submissions"].append(deepcopy(p["tracks"][0]["submissions"][0])),
            lambda p: p["tracks"].pop(0),
        ]
        for index, change in enumerate(changes):
            plan, policy = fixture()
            change(plan)
            with self.subTest(case=index), self.assertRaises(VerificationError):
                fill_plan(plan, policy)

    def test_single_benchmark_and_no_submissions_are_supported(self):
        plan, policy = fixture()
        plan["challengeId"] = None
        plan["tracks"] = plan["tracks"][:1]
        plan["tracks"][0]["submissions"] = []
        self.assertEqual(len(entries(fill_plan(plan, policy))), 2)


class ScalarRescoreCommandTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.plan_path, self.policy_path, self.output_path = [self.root / p for p in ("preview.json", "policy.json", "filled.json")]
        self.plan, self.policy = fixture()
        self.plan_path.write_text(json.dumps(self.plan))
        self.policy_path.write_text(json.dumps(self.policy))

    def invoke(self, extra=(), output=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--plan", str(self.plan_path), "--policy", str(self.policy_path),
                         "--out", str(output or self.output_path), *extra])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_command_writes_distinct_private_file_and_actionable_counts(self):
        before = (self.plan_path.read_bytes(), self.policy_path.read_bytes())
        code, stdout, stderr = self.invoke()
        self.assertEqual((code, stderr), (0, ""))
        summary = json.loads(stdout)
        self.assertEqual((summary["tracks"], summary["submissions"], summary["scores"]), (2, 3, 7))
        self.assertEqual((summary["increased"], summary["decreased"], summary["unchanged"]), (5, 0, 2))
        self.assertFalse(summary["databaseAccess"])
        self.assertIn("scalar-rescore dry-run --plan", summary["nextStep"])
        self.assertEqual(stat.S_IMODE(self.output_path.stat().st_mode), 0o600)
        self.assertEqual(read_json(self.output_path), fill_plan(self.plan, self.policy))
        self.assertEqual(before, (self.plan_path.read_bytes(), self.policy_path.read_bytes()))

    def test_output_cannot_overwrite_inputs_existing_files_or_symlinks(self):
        for output in (self.plan_path, self.policy_path):
            before = output.read_bytes()
            code, _, stderr = self.invoke(output=output)
            self.assertEqual(code, 2)
            self.assertIn("differ", stderr)
            self.assertEqual(output.read_bytes(), before)
        self.output_path.write_text("retained output")
        self.assertEqual(self.invoke()[0], 2)
        self.assertEqual(self.output_path.read_text(), "retained output")
        self.output_path.unlink()
        target = self.root / "must-not-create.json"
        self.output_path.symlink_to(target)
        self.assertEqual(self.invoke()[0], 2)
        self.assertTrue(self.output_path.is_symlink())
        self.assertFalse(target.exists())

    def test_bad_json_or_bad_entry_never_creates_output(self):
        for text in ('{"version":1,"version":1}', '{"value":NaN}', '{"value":1e999}', "not json"):
            self.plan_path.write_text(text)
            self.assertEqual(self.invoke()[0], 2)
            self.assertFalse(self.output_path.exists())
        self.plan["tracks"][1]["submissions"][0]["oldScore"] += 1
        self.plan_path.write_text(json.dumps(self.plan))
        code, _, stderr = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("tracks[1].submissions[0]", stderr)
        self.assertFalse(self.output_path.exists())

    def test_real_script_help_and_invocation_require_no_database(self):
        script = ROOT / "scripts/fill_scalar_rescore_plan.py"
        command = [sys.executable, str(script)]
        help_result = subprocess.run([*command, "--help"], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        result = subprocess.run([*command, "--plan", str(self.plan_path), "--policy", str(self.policy_path),
                                 "--out", str(self.output_path)], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["scores"], 7)


if __name__ == "__main__":
    unittest.main()
