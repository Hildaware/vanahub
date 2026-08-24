#!/usr/bin/env python3
"""Extract exactly one permitted PR manifest through the GitHub contents API."""

import base64
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

changed_path, repository, ref, output = sys.argv[1:]
changed = json.loads(Path(changed_path).read_text(encoding="utf-8"))
paths = [item["filename"] for item in changed]
if len(paths) != 1 or not re.fullmatch(r"packages/[a-z0-9][a-z0-9._-]{1,63}/manifest\.json", paths[0]):
    raise SystemExit("Routine admission PRs must change exactly one package manifest")
token = os.environ.get("GH_TOKEN", "")
request = urllib.request.Request(
    f"https://api.github.com/repos/{repository}/contents/{paths[0]}?ref={ref}",
    headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "User-Agent": "xirepo-admission/1"},
)
with urllib.request.urlopen(request, timeout=20) as response:
    content = json.load(response)["content"]
decoded = base64.b64decode(content, validate=True)
if len(decoded) > 128 * 1024:
    raise SystemExit("manifest exceeds the 128 KiB admission limit")
manifest = json.loads(decoded)
package_id = paths[0].split("/")[1]
if manifest.get("id") != package_id:
    raise SystemExit("manifest id must match its catalog package directory")
Path(output).write_bytes(decoded)
