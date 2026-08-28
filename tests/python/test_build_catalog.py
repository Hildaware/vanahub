import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parents[2] / "tools" / "build_catalog.py"
spec = importlib.util.spec_from_file_location("build_catalog", SCRIPT)
build_catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_catalog)


class BuildCatalogTests(unittest.TestCase):
    def test_includes_profile_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packages = root / "packages"
            packages.mkdir()
            profile_dir = root / "profiles" / "starter"
            profile_dir.mkdir(parents=True)
            profile = {
                "schemaVersion": 1,
                "id": "starter",
                "name": "Starter",
                "description": "A useful starting point.",
                "author": "VanaHub",
                "version": "1.0.0",
                "downloadUrl": "https://github.com/Hildaware/vanahub-catalog/releases/download/profile-starter-v1.0.0/starter-1.0.0.vanahub-profile.zip",
                "sha256": "a" * 64,
                "compressedSize": 100,
                "addons": [{"id": "example-addon", "autoLoad": True, "settings": True, "source": {"builtin": True}}],
            }
            (profile_dir / "manifest.json").write_text(json.dumps(profile), encoding="utf-8")
            output = root / "public"
            with mock.patch.object(sys, "argv", [
                "build_catalog.py", str(packages), str(output), "--unsigned",
            ]):
                build_catalog.main()
            index = json.loads((output / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["profiles"], [profile])

    def test_refuses_unsigned_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packages = root / "packages"
            packages.mkdir()
            output = root / "public"
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                sys,
                "argv",
                ["build_catalog.py", str(packages), str(output)],
            ):
                with self.assertRaisesRegex(SystemExit, "refusing to publish an unsigned catalog"):
                    build_catalog.main()
            self.assertFalse((output / "index.json.sig").exists())


if __name__ == "__main__":
    unittest.main()
