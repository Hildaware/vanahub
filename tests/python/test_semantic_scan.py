import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import semantic_scan


class SemanticScanTests(unittest.TestCase):
    def fixture(self, root: Path, source: str = "os.execute('calc')\n"):
        archive = root / "sample.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
            package.writestr("sample/sample.lua", source)
        catalog_report = root / "catalog.json"
        catalog_report.write_text(json.dumps({"accepted": True, "findings": []}), encoding="utf-8")
        return archive, catalog_report, source

    def fake_semgrep(self, risk: str = "elevated", errors=None):
        def run(command, **_kwargs):
            output = Path(command[command.index("--json-output") + 1])
            source = Path(command[-1]) / "sample.lua"
            error_values = [{**error, "path": str(source)} for error in (errors or [])]
            output.write_text(json.dumps({
                "results": [{
                    "check_id": "vanahub.lua.process-execution",
                    "path": str(source),
                    "start": {"line": 1},
                    "extra": {
                        "message": "process execution",
                        "metadata": {
                            "capability": "process-execution",
                            "vanahub_risk": risk,
                        },
                    },
                }],
                "errors": error_values,
            }), encoding="utf-8")
            return CompletedProcess(command, 0, "", "")
        return run

    def arguments(self, archive: Path, report: Path, output: Path, baseline: Path | None = None):
        values = [
            "--semgrep", "semgrep", "--rules", "policy/semgrep-lua.yml",
            "--archive", str(archive), "--archive-root", "sample",
            "--package-id", "sample", "--output-directory", str(output),
            "--catalog-report", str(report),
        ]
        if baseline:
            values.extend(["--baseline", str(baseline)])
        return values

    def test_exact_baseline_approves_archive_findings_and_merges_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, report, source = self.fixture(root)
            first_output = root / "first"
            with patch.object(semantic_scan.subprocess, "run", self.fake_semgrep()):
                self.assertEqual(semantic_scan.main(self.arguments(archive, report, first_output)), 1)
            candidate = json.loads(
                (first_output / "semantic-review-candidate.json").read_text(encoding="utf-8")
            )
            self.assertEqual(candidate["files"], {
                "sample.lua": hashlib.sha256(source.encode()).hexdigest(),
            })

            baseline = root / "baseline.json"
            baseline.write_text(json.dumps(candidate), encoding="utf-8")
            report.write_text(json.dumps({"accepted": True, "findings": []}), encoding="utf-8")
            second_output = root / "second"
            with patch.object(semantic_scan.subprocess, "run", self.fake_semgrep()):
                self.assertEqual(
                    semantic_scan.main(self.arguments(archive, report, second_output, baseline)), 0
                )
            merged = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(merged["accepted"])
            self.assertTrue(merged["findings"][0]["reviewed"])

    def test_critical_finding_cannot_be_approved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, report, source = self.fixture(root)
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({
                "schemaVersion": 1,
                "packageId": "sample",
                "reviewedCommit": "a" * 40,
                "files": {"sample.lua": hashlib.sha256(source.encode()).hexdigest()},
            }), encoding="utf-8")
            with patch.object(semantic_scan.subprocess, "run", self.fake_semgrep("critical")):
                self.assertEqual(
                    semantic_scan.main(self.arguments(archive, report, root / "critical", baseline)), 1
                )

    def test_parser_gap_requires_an_exact_file_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, report, _source = self.fixture(root)
            error = {
                "path": str(root / "parse" / "source" / "sample.lua"),
                "message": "partial parse",
                "spans": [{"start": {"line": 1}}],
            }
            with patch.object(semantic_scan.subprocess, "run", self.fake_semgrep(errors=[error])):
                self.assertEqual(
                    semantic_scan.main(self.arguments(archive, report, root / "parse")), 1
                )
            candidate = json.loads(
                (root / "parse" / "semantic-review-candidate.json").read_text(encoding="utf-8")
            )
            self.assertIn("semgrep.parse-error", {finding["ruleId"] for finding in candidate["findings"]})


if __name__ == "__main__":
    unittest.main()
