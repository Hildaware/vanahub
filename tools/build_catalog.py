#!/usr/bin/env python3
"""Build a canonical repository index and detached Ed25519 signature."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import subprocess
import tempfile
from pathlib import Path


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def sign_ed25519(payload: bytes, encoded_key: str) -> bytes:
    try:
        seed = base64.b64decode(encoded_key, validate=True)
        if len(seed) != 32:
            raise ValueError("seed must contain exactly 32 bytes")
    except (ValueError, TypeError) as exc:
        raise ValueError("signing key must be a base64-encoded 32-byte Ed25519 seed") from exc
    # RFC 8410 PKCS#8 prefix for a raw 32-byte Ed25519 private key. Using the
    # runner's OpenSSL avoids installing third-party code in the signing job.
    private_der = bytes.fromhex("302e020100300506032b657004220420") + seed
    with tempfile.TemporaryDirectory(prefix="vanahub-sign-") as directory:
        root = Path(directory)
        key_path = root / "key.der"
        payload_path = root / "index.json"
        signature_path = root / "index.sig"
        key_path.write_bytes(private_der)
        key_path.chmod(0o600)
        payload_path.write_bytes(payload)
        try:
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
                    "-inkey", str(key_path), "-in", str(payload_path), "-out", str(signature_path),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RuntimeError("OpenSSL could not create the Ed25519 signature") from exc
        signature = signature_path.read_bytes()
    if len(signature) != 64:
        raise RuntimeError("OpenSSL returned a malformed Ed25519 signature")
    return signature


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packages", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repository-id", default="builtin")
    parser.add_argument("--repository-name", default="Built-in screened repository")
    parser.add_argument("--revocations", type=Path)
    parser.add_argument("--signing-key-env", default="VANAHUB_ED25519_PRIVATE_KEY")
    parser.add_argument("--key-id", default="catalog-2026-01")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--unsigned", action="store_true", help="Build index.json without exposing a signing key")
    mode.add_argument("--sign-only", action="store_true", help="Sign an existing output/index.json without parsing manifests")
    args = parser.parse_args()

    if not args.sign_only:
        manifests = []
        for path in sorted(args.packages.glob("*/manifest.json")):
            manifests.append(json.loads(path.read_text(encoding="utf-8")))
        profiles = []
        profiles_root = args.packages.parent / "profiles"
        for path in sorted(profiles_root.glob("*/manifest.json")):
            profiles.append(json.loads(path.read_text(encoding="utf-8")))
        revocations = []
        if args.revocations and args.revocations.exists():
            revocations = json.loads(args.revocations.read_text(encoding="utf-8"))
        index = {
            "schemaVersion": 1,
            "repository": {"id": args.repository_id, "name": args.repository_name},
            "generatedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "packages": manifests,
            "profiles": profiles,
            "revocations": revocations,
        }
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "index.json").write_bytes(canonical_bytes(index))
    if args.unsigned:
        return 0
    payload = (args.output / "index.json").read_bytes()

    encoded_key = os.environ.get(args.signing_key_env)
    if not encoded_key:
        raise SystemExit(f"{args.signing_key_env} is required; refusing to publish an unsigned catalog")
    try:
        signature = sign_ed25519(payload, encoded_key)
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(f"{args.signing_key_env}: {exc}") from exc
    detached = {"keyId": args.key_id, "algorithm": "Ed25519", "signature": base64.b64encode(signature).decode("ascii")}
    (args.output / "index.json.sig").write_text(json.dumps(detached, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
