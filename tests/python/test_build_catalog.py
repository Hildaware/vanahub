import importlib.util
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
