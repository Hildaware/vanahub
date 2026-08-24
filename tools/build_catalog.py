#!/usr/bin/env python3
"""Build a canonical repository index and detached Ed25519 signature."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packages", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repository-id", default="builtin")
    parser.add_argument("--repository-name", default="Built-in screened repository")
    parser.add_argument("--revocations", type=Path)
    parser.add_argument("--signing-key-env", default="XIREPO_ED25519_PRIVATE_KEY")
    parser.add_argument("--key-id", default="catalog-2026-01")
    args = parser.parse_args()

    manifests = []
    for path in sorted(args.packages.glob("*/manifest.json")):
        manifests.append(json.loads(path.read_text(encoding="utf-8")))
    revocations = []
    if args.revocations and args.revocations.exists():
        revocations = json.loads(args.revocations.read_text(encoding="utf-8"))
    index = {
        "schemaVersion": 1,
        "repository": {"id": args.repository_id, "name": args.repository_name},
        "generatedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "packages": manifests,
        "revocations": revocations,
    }
    payload = canonical_bytes(index)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "index.json").write_bytes(payload)

    encoded_key = os.environ.get(args.signing_key_env)
    if encoded_key:
        try:
            from nacl.signing import SigningKey
        except ImportError as exc:
            raise SystemExit("PyNaCl is required when signing") from exc
        key = SigningKey(base64.b64decode(encoded_key))
        signature = key.sign(payload).signature
        detached = {"keyId": args.key_id, "algorithm": "Ed25519", "signature": base64.b64encode(signature).decode("ascii")}
        (args.output / "index.json.sig").write_text(json.dumps(detached, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
