#!/usr/bin/env python3
"""Validate, sanitize, and describe VanaHub profile archives.

Archive members are always treated as untrusted data.  The prepare command
creates a deterministic sanitized archive and its catalog manifest; verify
checks an existing catalog manifest against either a local or downloaded
artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "sensitive-data-policy.json"
PACKAGE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
RELEASE_URL = re.compile(r"^https://github\.com/[^/]+/[^/]+/releases/download/[^/]+/[^/]+$")
CATEGORIES = {
    "combat", "jobs", "inventory", "crafting", "economy", "maps-travel",
    "user-interface", "chat-communication", "data-tracking",
    "quality-of-life", "development-tools",
}
WINDOWS_DEVICES = {"con", "prn", "aux", "nul", "clock$", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
APPROVED_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
MAX_COMPRESSED = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_ENTRY = 32 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_RATIO = 200
REDACTED = "<REDACTED>"


class ProfileError(Exception):
    pass


@dataclass(frozen=True)
class Finding:
    ruleId: str
    severity: str
    path: str = ""
    key: str = ""
    action: str = ""
    message: str = ""


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def load_policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def normalized_path(name: str) -> PurePosixPath:
    if "\\" in name or "\0" in name or name.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", name):
        raise ProfileError("absolute, backslash, drive, or NUL path")
    path = PurePosixPath(name)
    if not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ProfileError("empty, dot, or traversal path segment")
    for part in path.parts:
        stem = part.rstrip(" .").split(".", 1)[0].casefold()
        if stem in WINDOWS_DEVICES or ":" in part or part != part.rstrip(" ."):
            raise ProfileError("Windows device, stream, or ambiguous path segment")
    return path


def validate_source(value: object) -> None:
    if not isinstance(value, dict) or set(value) - {"builtin", "name", "url"} or not isinstance(value.get("builtin"), bool):
        raise ProfileError("addon source is invalid")
    if value["builtin"]:
        if set(value) != {"builtin"}:
            raise ProfileError("built-in source has unexpected fields")
        return
    if set(value) - {"builtin", "name", "url"} or not isinstance(value.get("url"), str):
        raise ProfileError("custom source is invalid")
    parsed = urllib.parse.urlsplit(value["url"])
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or len(value["url"]) > 2048:
        raise ProfileError("custom source must be a credential-free HTTPS URL")
    if "name" in value and (not isinstance(value["name"], str) or len(value["name"]) > 200):
        raise ProfileError("custom source name is invalid")


def validate_addons(value: object) -> list[dict]:
    if not isinstance(value, list) or len(value) > 256:
        raise ProfileError("addons must be an array with at most 256 entries")
    seen: set[str] = set()
    result: list[dict] = []
    for entry in value:
        required = {"id", "autoLoad", "source", "settings"}
        if not isinstance(entry, dict) or set(entry) - required - {"version", "sha256"} or not required.issubset(entry):
            raise ProfileError("addon entry has missing or unknown fields")
        package_id = entry.get("id")
        if not isinstance(package_id, str) or not PACKAGE_ID.fullmatch(package_id) or package_id == "vanahub" or package_id in seen:
            raise ProfileError("addon id is invalid, reserved, or duplicated")
        if not isinstance(entry["autoLoad"], bool) or not isinstance(entry["settings"], bool):
            raise ProfileError("addon options must be booleans")
        if "version" in entry and (not isinstance(entry["version"], str) or len(entry["version"]) > 80):
            raise ProfileError("addon version is invalid")
        if "sha256" in entry and (not isinstance(entry["sha256"], str) or not SHA256.fullmatch(entry["sha256"])):
            raise ProfileError("addon SHA-256 is invalid")
        validate_source(entry["source"])
        seen.add(package_id)
        result.append(entry)
    return result


def validate_portable(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "profile"} or value.get("schemaVersion") != 1:
        raise ProfileError("portable profile manifest is invalid")
    profile = value.get("profile")
    if not isinstance(profile, dict) or set(profile) != {"name", "addons"}:
        raise ProfileError("portable profile has missing or unknown fields")
    name = profile.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 80 or any(ord(char) < 32 for char in name):
        raise ProfileError("profile name is invalid")
    validate_addons(profile.get("addons"))
    return value


def validate_catalog(value: object) -> dict:
    required = {"schemaVersion", "id", "name", "description", "author", "version", "downloadUrl", "sha256", "compressedSize", "addons"}
    optional = {"categories", "iconUrl", "screenshots"}
    if not isinstance(value, dict) or set(value) - required - optional or not required.issubset(value) or value.get("schemaVersion") != 1:
        raise ProfileError("catalog profile has missing or unknown fields")
    if not isinstance(value["id"], str) or not PACKAGE_ID.fullmatch(value["id"]):
        raise ProfileError("catalog profile id is invalid")
    if not isinstance(value["name"], str) or not value["name"].strip() or len(value["name"]) > 80:
        raise ProfileError("catalog profile name is invalid")
    for key, maximum in (("description", 2000), ("author", 80)):
        if not isinstance(value[key], str) or not value[key].strip() or len(value[key]) > maximum:
            raise ProfileError(f"catalog {key} is invalid")
    if not isinstance(value["version"], str) or len(value["version"]) > 80 or not SEMVER.fullmatch(value["version"]):
        raise ProfileError("catalog profile version is invalid")
    if not isinstance(value["downloadUrl"], str) or not RELEASE_URL.fullmatch(value["downloadUrl"]):
        raise ProfileError("catalog download URL must be a GitHub Release asset")
    if not isinstance(value["sha256"], str) or not SHA256.fullmatch(value["sha256"]):
        raise ProfileError("catalog profile SHA-256 is invalid")
    if not isinstance(value["compressedSize"], int) or not 0 < value["compressedSize"] <= MAX_COMPRESSED:
        raise ProfileError("catalog compressed size is invalid")
    validate_addons(value["addons"])
    if "categories" in value:
        categories = value["categories"]
        if not isinstance(categories, list) or not 1 <= len(categories) <= 3 or len(categories) != len(set(categories)) or not set(categories) <= CATEGORIES:
            raise ProfileError("catalog categories are invalid")
    return value


def sensitive_key(key: str, policy: dict) -> bool:
    folded = re.sub(r"[^a-z0-9]", "", key.casefold())
    return folded in {re.sub(r"[^a-z0-9]", "", item.casefold()) for item in policy["sensitiveKeys"]}


def redact_json(value: object, path: str, policy: dict, findings: list[Finding], prefix: str = "") -> object:
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            location = f"{prefix}.{key}" if prefix else str(key)
            if sensitive_key(str(key), policy) and isinstance(child, (str, int, float)) and not isinstance(child, bool):
                result[key] = REDACTED
                findings.append(Finding("credential.sensitive-key", "redacted", path, location, "replaced", "Sensitive scalar replaced"))
            else:
                result[key] = redact_json(child, path, policy, findings, location)
        return result
    if isinstance(value, list):
        return [redact_json(child, path, policy, findings, f"{prefix}[{index}]") for index, child in enumerate(value)]
    return value


QUOTED_ASSIGNMENT = re.compile(r"(?P<prefix>(?:^|\n)[ \t]*(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=[ \t]*)(?P<quote>['\"])(?P<value>(?:\\.|(?!\3).)*)(?P=quote)")
LUA_ASSIGNMENT = re.compile(r"(?P<prefix>(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)(?P<quote>['\"])(?P<value>(?:\\.|(?!\3).)*)(?P=quote)")
INI_ASSIGNMENT = re.compile(r"(?m)^(?P<prefix>[ \t]*(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=[ \t]*)(?P<value>[^\r\n]*?)\s*$")


def redact_assignments(text: str, path: str, policy: dict, findings: list[Finding], lua: bool) -> str:
    pattern = LUA_ASSIGNMENT if lua else QUOTED_ASSIGNMENT
    def replace(match: re.Match[str]) -> str:
        key = match.group("key")
        if not sensitive_key(key, policy):
            return match.group(0)
        findings.append(Finding("credential.sensitive-key", "redacted", path, key, "replaced", "Sensitive scalar replaced"))
        return f'{match.group("prefix")}{match.group("quote")}{REDACTED}{match.group("quote")}'
    return pattern.sub(replace, text)


def redact_ini(text: str, path: str, policy: dict, findings: list[Finding]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group("key")
        if not sensitive_key(key, policy):
            return match.group(0)
        value = match.group("value").strip()
        quote = value[0] if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"" else ""
        findings.append(Finding("credential.sensitive-key", "redacted", path, key, "replaced", "Sensitive scalar replaced"))
        return f'{match.group("prefix")}{quote}{REDACTED}{quote}'
    return INI_ASSIGNMENT.sub(replace, text)


def redact_xml(text: str, path: str, policy: dict, findings: list[Finding]) -> str:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ProfileError(f"cannot safely sanitize malformed XML: {path}: {exc}") from exc
    for element in root.iter():
        if sensitive_key(element.tag.rsplit("}", 1)[-1], policy) and element.text and element.text.strip():
            element.text = REDACTED
            findings.append(Finding("credential.sensitive-key", "redacted", path, element.tag, "replaced", "Sensitive XML value replaced"))
        for key in list(element.attrib):
            if sensitive_key(key, policy):
                element.attrib[key] = REDACTED
                findings.append(Finding("credential.sensitive-key", "redacted", path, key, "replaced", "Sensitive XML attribute replaced"))
    return ElementTree.tostring(root, encoding="unicode") + "\n"


def sanitize_text(data: bytes, path: str, policy: dict, findings: list[Finding]) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    for rule in policy["blockingPatterns"]:
        if re.search(rule["pattern"], text):
            raise ProfileError(f"{rule['id']} requires manual removal: {path}")
    suffix = PurePosixPath(path).suffix.casefold()
    original = text
    if suffix == ".json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProfileError(f"cannot safely sanitize malformed JSON: {path}: {exc}") from exc
        value = redact_json(value, path, policy, findings)
        text = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    elif suffix == ".xml":
        text = redact_xml(text, path, policy, findings)
    elif suffix == ".lua":
        text = redact_assignments(text, path, policy, findings, True)
    elif suffix in {".ini", ".cfg", ".conf"}:
        text = redact_ini(text, path, policy, findings)
    for rule in policy["credentialPatterns"]:
        if re.search(rule["pattern"], text):
            raise ProfileError(f"{rule['id']} remains in unsupported or ambiguous context: {path}")
    if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        findings.append(Finding("privacy.email", "warning", path, action="review", message="Possible email address"))
    for match in re.finditer(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", text):
        try:
            if not ipaddress.ip_address(match.group(0)).is_unspecified:
                findings.append(Finding("privacy.ip-address", "warning", path, action="review", message="Possible IP address"))
                break
        except ValueError:
            pass
    if re.search(r"(?:[A-Za-z]:\\Users\\[^\\\r\n]+|/Users/[^/\r\n]+|/home/[^/\r\n]+)", text):
        findings.append(Finding("privacy.local-path", "warning", path, action="review", message="Possible user-specific local path"))
    return text.encode("utf-8") if text != original else data


def run_settings_scanner(scanner: Path | None, display_path: str, data: bytes) -> None:
    if scanner is None:
        return
    with tempfile.NamedTemporaryFile(prefix="vanahub-setting-", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
    try:
        result = subprocess.run([str(scanner), display_path, str(temporary)], capture_output=True, text=True)
    finally:
        temporary.unlink(missing_ok=True)
    if result.returncode != 0:
        detail = result.stdout.splitlines()[0] if result.stdout else result.stderr.strip()
        raise ProfileError(f"settings safety scan failed: {detail or display_path}")


def inspect_archive(path: Path, *, sanitize: bool, scanner: Path | None) -> tuple[dict, dict[str, bytes], list[Finding]]:
    if not path.is_file() or path.stat().st_size > MAX_COMPRESSED:
        raise ProfileError("profile archive is missing or exceeds 64 MiB")
    policy = load_policy()
    findings: list[Finding] = []
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    expanded = 0
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                raise ProfileError("profile entry-count limit exceeded")
            for info in infos:
                raw_name = info.filename.rstrip("/")
                if not raw_name:
                    continue
                normalized = normalized_path(raw_name).as_posix()
                folded = normalized.casefold()
                if folded in seen:
                    raise ProfileError(f"duplicate or case-colliding entry: {normalized}")
                seen.add(folded)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode) or info.flag_bits & 1:
                    raise ProfileError(f"linked or encrypted entry: {normalized}")
                if stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise ProfileError(f"non-regular archive entry: {normalized}")
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ProfileError(f"unsupported compression: {normalized}")
                expanded += info.file_size
                if info.file_size > MAX_ENTRY or expanded > MAX_EXPANDED:
                    raise ProfileError("profile expansion limit exceeded")
                if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                    raise ProfileError(f"suspicious compression ratio: {normalized}")
                if info.is_dir():
                    continue
                if folded != "profile.json" and not folded.startswith("settings/"):
                    raise ProfileError(f"unexpected profile entry: {normalized}")
                files[normalized] = archive.read(info)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ProfileError(f"invalid ZIP: {exc}") from exc
    manifest_name = next((name for name in files if name.casefold() == "profile.json"), None)
    if manifest_name is None:
        raise ProfileError("profile.json is missing")
    if len(files[manifest_name]) > 2 * 1024 * 1024:
        raise ProfileError("profile.json exceeds 2 MiB")
    try:
        portable = validate_portable(json.loads(files[manifest_name].decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile.json is not valid UTF-8 JSON: {exc}") from exc
    declared = {entry["id"]: entry for entry in portable["profile"]["addons"]}
    for name, data in list(files.items()):
        if name == manifest_name:
            continue
        parts = PurePosixPath(name).parts
        if len(parts) < 3 or parts[0].casefold() != "settings":
            raise ProfileError(f"settings entry has no addon-relative path: {name}")
        addon = declared.get(parts[1])
        if addon is None or not addon["settings"]:
            raise ProfileError(f"settings exist for an undeclared or disabled addon: {parts[1]}")
        if sanitize:
            cleaned = sanitize_text(data, name, policy, findings)
        else:
            audit: list[Finding] = []
            sanitize_text(data, name, policy, audit)
            if any(item.severity == "redacted" for item in audit):
                raise ProfileError(f"unsanitized sensitive value remains: {name}")
            findings.extend(item for item in audit if item.severity == "warning")
            cleaned = data
        run_settings_scanner(scanner, name, cleaned)
        files[name] = cleaned
    files[manifest_name] = canonical_bytes(portable)
    return portable, files, findings


def write_deterministic_zip(path: Path, files: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files, key=str.casefold):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, files[name])


class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or (parsed.hostname or "").casefold() not in APPROVED_HOSTS:
            raise ProfileError(f"redirect to unapproved host: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, destination: Path) -> None:
    headers = {"User-Agent": "vanahub-profile-scan/1"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    opener = urllib.request.build_opener(RestrictedRedirect())
    size = 0
    with opener.open(urllib.request.Request(url, headers=headers), timeout=30) as response, destination.open("wb") as output:
        while chunk := response.read(64 * 1024):
            size += len(chunk)
            if size > MAX_COMPRESSED:
                raise ProfileError("download exceeds 64 MiB")
            output.write(chunk)


def report(findings: list[Finding]) -> dict:
    return {
        "schemaVersion": 1,
        "redacted": sum(item.severity == "redacted" for item in findings),
        "warnings": sum(item.severity == "warning" for item in findings),
        "findings": [asdict(item) for item in findings],
    }


def prepare(args: argparse.Namespace) -> None:
    portable, files, findings = inspect_archive(args.source, sanitize=True, scanner=args.settings_scanner)
    write_deterministic_zip(args.archive, files)
    digest = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    categories = [item.strip() for item in args.categories.split(",") if item.strip()]
    manifest = {
        "schemaVersion": 1,
        "id": args.id,
        "name": portable["profile"]["name"],
        "description": args.description,
        "author": args.author,
        "version": args.version,
        "downloadUrl": args.download_url,
        "sha256": digest,
        "compressedSize": args.archive.stat().st_size,
        "addons": portable["profile"]["addons"],
    }
    if categories:
        manifest["categories"] = categories
    validate_catalog(manifest)
    args.manifest.write_bytes(canonical_bytes(manifest))
    args.report.write_bytes(canonical_bytes(report(findings)))


def verify(args: argparse.Namespace) -> None:
    manifest = validate_catalog(json.loads(args.manifest.read_text(encoding="utf-8")))
    temporary = None
    archive = args.archive
    if archive is None:
        temporary = tempfile.TemporaryDirectory(prefix="vanahub-profile-download-")
        archive = Path(temporary.name) / "profile.zip"
        download(manifest["downloadUrl"], archive)
    try:
        if archive.stat().st_size != manifest["compressedSize"] or hashlib.sha256(archive.read_bytes()).hexdigest() != manifest["sha256"]:
            raise ProfileError("catalog artifact size or SHA-256 does not match")
        portable, _, findings = inspect_archive(archive, sanitize=False, scanner=args.settings_scanner)
        if portable["profile"]["name"] != manifest["name"] or portable["profile"]["addons"] != manifest["addons"]:
            raise ProfileError("catalog browse metadata does not match profile.json")
        args.output.write_bytes(canonical_bytes(report(findings)))
    finally:
        if temporary is not None:
            temporary.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("prepare")
    create.add_argument("source", type=Path)
    create.add_argument("archive", type=Path)
    create.add_argument("manifest", type=Path)
    create.add_argument("--report", type=Path, required=True)
    create.add_argument("--id", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--description", required=True)
    create.add_argument("--author", required=True)
    create.add_argument("--download-url", required=True)
    create.add_argument("--categories", default="")
    create.add_argument("--settings-scanner", type=Path)
    create.set_defaults(function=prepare)
    check = subparsers.add_parser("verify")
    check.add_argument("manifest", type=Path)
    check.add_argument("--archive", type=Path)
    check.add_argument("--output", type=Path, required=True)
    check.add_argument("--settings-scanner", type=Path)
    check.set_defaults(function=verify)
    args = parser.parse_args()
    try:
        args.function(args)
    except (OSError, ProfileError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
