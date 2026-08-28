import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).parents[2] / "tools" / "profile_scan.py"
spec = importlib.util.spec_from_file_location("profile_scan", SCRIPT)
profile_scan = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = profile_scan
spec.loader.exec_module(profile_scan)


def portable(settings=True):
    return {
        "schemaVersion": 1,
        "profile": {
            "name": "Raid Profile",
            "addons": [{
                "id": "sample-addon",
                "autoLoad": True,
                "settings": settings,
                "source": {"builtin": True},
            }],
        },
    }


def write_profile(path, entries, manifest=None):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("profile.json", json.dumps(manifest or portable()))
        for name, contents in entries.items():
            archive.writestr(name, contents)


class ProfileScanTests(unittest.TestCase):
    def prepare(self, root, source):
        archive = root / "sanitized.zip"
        manifest = root / "manifest.json"
        report = root / "report.json"
        profile_scan.prepare(SimpleNamespace(
            source=source,
            archive=archive,
            manifest=manifest,
            report=report,
            id="raid-profile",
            version="1.2.3",
            description="A settings-aware raid profile.",
            author="VanaHub",
            download_url="https://github.com/Hildaware/vanahub-catalog/releases/download/profile-raid-profile-v1.2.3/raid-profile-1.2.3.vanahub-profile.zip",
            categories="combat,jobs",
            settings_scanner=None,
        ))
        return archive, manifest, report

    def test_prepares_deterministic_sanitized_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.zip"
            write_profile(source, {
                "settings/sample-addon/settings.json": json.dumps({"theme": "blue", "api_key": "secret-value"}),
                "settings/sample-addon/settings.lua": 'return T{ password = "hunter2", enabled = true }',
            })
            archive, manifest, report = self.prepare(root, source)
            first = archive.read_bytes()
            archive2, _, _ = self.prepare(root, source)
            self.assertEqual(first, archive2.read_bytes())
            with zipfile.ZipFile(archive) as output:
                self.assertNotIn(b"secret-value", output.read("settings/sample-addon/settings.json"))
                self.assertNotIn(b"hunter2", output.read("settings/sample-addon/settings.lua"))
            catalog = json.loads(manifest.read_text())
            self.assertEqual(catalog["addons"], portable()["profile"]["addons"])
            self.assertEqual(catalog["compressedSize"], archive.stat().st_size)
            self.assertEqual(json.loads(report.read_text())["redacted"], 2)

    def test_private_key_blocks_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.zip"
            write_profile(source, {"settings/sample-addon/key.txt": "-----BEGIN PRIVATE KEY-----\nsecret"})
            with self.assertRaisesRegex(profile_scan.ProfileError, "manual removal"):
                self.prepare(root, source)

    def test_settings_must_be_declared_and_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.zip"
            write_profile(source, {"settings/sample-addon/value.txt": "safe"}, portable(False))
            with self.assertRaisesRegex(profile_scan.ProfileError, "disabled addon"):
                self.prepare(root, source)

    def test_verify_rejects_browse_metadata_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.zip"
            write_profile(source, {"settings/sample-addon/value.txt": "safe"})
            archive, manifest, _ = self.prepare(root, source)
            value = json.loads(manifest.read_text())
            value["name"] = "Different"
            manifest.write_text(json.dumps(value))
            with self.assertRaisesRegex(profile_scan.ProfileError, "does not match"):
                profile_scan.verify(SimpleNamespace(
                    manifest=manifest, archive=archive, output=root / "verify.json", settings_scanner=None,
                ))


if __name__ == "__main__":
    unittest.main()
