import base64
import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "catalog" / "scripts"))
import catalog_scan
import extract_pr_manifest
import verify_submission


class CatalogScanTests(unittest.TestCase):
    def test_decodes_line_wrapped_github_content(self):
        document = b'{"schemaVersion":1,"id":"sample"}\n'
        encoded = base64.encodebytes(document).decode("ascii")
        self.assertEqual(extract_pr_manifest.decode_github_content(encoded), document)

    def manifest(self, digest: str, size: int, **overrides):
        value = {
            "schemaVersion": 1, "id": "sample", "name": "Sample",
            "description": "Sample addon", "author": "author",
            "maintainers": ["author"], "version": "1.0.0", "changelog": "Initial",
            "sourceUrl": "https://github.com/author/sample",
            "downloadUrl": "https://github.com/author/sample/releases/download/v1.0.0/sample.zip",
            "sha256": digest, "compressedSize": size, "archiveRoot": "sample",
            "entrypoint": "sample.lua", "declaredCapabilities": ["ui"],
        }
        value.update(overrides)
        return value

    def make_zip(self, root: Path, files: dict[str, str]):
        archive = root / "sample.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return archive

    def run_scan(self, files, **overrides):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.make_zip(root, files)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            manifest = self.manifest(digest, archive.stat().st_size, **overrides)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            return catalog_scan.scan(manifest_path, archive)

    def test_accepts_restricted_addon(self):
        report = self.run_scan(
            {"sample/sample.lua": "local imgui = require('imgui')\nreturn true\n"},
            screenshots=["https://raw.githubusercontent.com/author/sample/main/screenshots/main.png"],
        )
        self.assertTrue(report["accepted"], report["findings"])

    def test_rejects_invalid_screenshot_urls(self):
        report = self.run_scan(
            {"sample/sample.lua": "return true"},
            screenshots=["http://example.com/insecure.png", "http://example.com/insecure.png"],
        )
        self.assertFalse(report["accepted"])
        self.assertIn("manifest.screenshots", {f["rule_id"] for f in report["findings"]})

    def test_rejects_network(self):
        report = self.run_scan({"sample/sample.lua": "local socket = require('socket')\n"})
        self.assertFalse(report["accepted"])
        self.assertIn("lua.blocked-symbol", {f["rule_id"] for f in report["findings"]})

    def test_rejects_traversal(self):
        report = self.run_scan({"sample/sample.lua": "return true", "../escape.lua": "return false"})
        self.assertFalse(report["accepted"])
        self.assertIn("zip.unsafe-path", {f["rule_id"] for f in report["findings"]})

    def test_rejects_case_collision(self):
        report = self.run_scan({"sample/sample.lua": "return true", "sample/Data.json": "{}", "sample/data.json": "{}"})
        self.assertFalse(report["accepted"])
        self.assertIn("zip.path-collision", {f["rule_id"] for f in report["findings"]})

    def test_malformed_manifest_is_a_report_not_a_crash(self):
        report = self.run_scan({"sample/sample.lua": "return true"}, archiveRoot=7)
        self.assertFalse(report["accepted"])
        self.assertIn("manifest.archive-root", {f["rule_id"] for f in report["findings"]})

    def test_rejects_release_from_another_repository(self):
        report = self.run_scan(
            {"sample/sample.lua": "return true"},
            downloadUrl="https://github.com/attacker/other/releases/download/v1.0.0/sample.zip",
        )
        self.assertFalse(report["accepted"])
        self.assertIn("manifest.repository-mismatch", {f["rule_id"] for f in report["findings"]})

    def test_only_manager_package_may_ship_its_engine_dll(self):
        accepted = self.run_scan(
            {"vanahub/vanahub.lua": "return true", "vanahub/bin/vanahub_engine.dll": "PE"},
            id="vanahub", archiveRoot="vanahub", entrypoint="vanahub.lua",
        )
        self.assertTrue(accepted["accepted"], accepted["findings"])
        rejected = self.run_scan(
            {"sample/sample.lua": "return true", "sample/bin/helper.dll": "PE"},
        )
        self.assertFalse(rejected["accepted"])
        self.assertIn("zip.file-type", {f["rule_id"] for f in rejected["findings"]})

    def test_runtime_policy_tracks_catalog_policy(self):
        root = Path(__file__).resolve().parents[2]
        policy = json.loads((root / "policy/scanner-policy.json").read_text(encoding="utf-8"))
        native = (root / "native/src/core.cpp").read_text(encoding="utf-8").casefold()
        for extension in policy["allowedExtensions"]:
            self.assertIn(f'"{extension}"'.casefold(), native)
        for symbol in policy["blockedSymbols"]:
            self.assertIn(f'"{symbol}"'.casefold(), native)

    def test_semver_update_ordering(self):
        self.assertTrue(verify_submission.semver_greater("1.0.0", "1.0.0-rc.2"))
        self.assertTrue(verify_submission.semver_greater("1.0.1", "1.0.0"))
        self.assertFalse(verify_submission.semver_greater("1.0.0-rc.1", "1.0.0"))
        self.assertFalse(verify_submission.semver_greater("1.0.0", "1.0.0"))


if __name__ == "__main__":
    unittest.main()
