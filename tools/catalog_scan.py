#!/usr/bin/env python3
"""Scan an Ashita addon release as untrusted data.

This utility intentionally never imports or executes package content. It uses
only Python's ZIP reader and lexical Lua rules; the native engine applies the
same structural invariants again before installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "scanner-policy.json"
PACKAGE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GITHUB_RELEASE = re.compile(r"^https://github\.com/[^/]+/[^/]+/releases/download/[^/]+/[^/]+$")
SOURCE_REPOSITORY = re.compile(r"^https://github\.com/[^/]+/[^/]+/?$")
WINDOWS_DEVICES = {"con", "prn", "aux", "nul", "clock$", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
APPROVED_DOWNLOAD_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
ELEVATED_PATTERNS = (
    ("native-interop", re.compile(r"\bffi\s*\.\s*load\s*\(|\bffi\s*\.\s*C\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(", re.IGNORECASE)),
    ("process-execution", re.compile(r"\bos\s*\.\s*execute\s*\(|\bio\s*\.\s*popen\s*\(", re.IGNORECASE)),
    ("dynamic-code", re.compile(r"\b(?:loadfile|dofile|loadstring)\s*\(", re.IGNORECASE)),
    ("native-interop", re.compile(r"\bpackage\s*\.\s*loadlib\s*\(", re.IGNORECASE)),
    ("memory-write", re.compile(r"\bashita\s*\.\s*memory\s*\.\s*write\b", re.IGNORECASE)),
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    path: str = ""
    line: int = 0
    capability: str = ""


class ScanError(Exception):
    pass


def load_policy(path: Path = POLICY_PATH) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_distribution_provenance(manifest: dict, provenance: dict | None) -> list[Finding]:
    if provenance is None:
        return []
    required = {
        "schemaVersion", "packageId", "distributionMethod", "distributorRepository",
        "distroIssue", "distroCommit", "upstreamRepository", "upstreamReleaseId",
        "upstreamReleaseUrl", "upstreamTag", "upstreamCommit", "license",
    }
    findings: list[Finding] = []
    if set(provenance) - required - {"upstreamAsset", "buildRevision", "catalogSubmissionIssue"}:
        findings.append(Finding("provenance.unknown-fields", "error", "Distribution provenance contains unknown fields"))
    if not required.issubset(provenance):
        findings.append(Finding("provenance.missing-fields", "error", "Distribution provenance is incomplete"))
        return findings
    checks = [
        (provenance.get("schemaVersion") == 2, "provenance.schema", "Distribution provenance schemaVersion must be 2"),
        (provenance.get("packageId") == manifest.get("id"), "provenance.package", "Distribution provenance package ID does not match"),
        (provenance.get("distributionMethod") in {"upstream-asset", "vanahub-build"}, "provenance.method", "Unsupported distribution method"),
        (provenance.get("distributorRepository") == "https://github.com/Hildaware/vanahub-addon-distro", "provenance.distributor", "Untrusted distributor repository"),
        (provenance.get("upstreamRepository", "").rstrip("/").casefold() == manifest.get("sourceUrl", "").rstrip("/").casefold(), "provenance.upstream", "Upstream repository does not match sourceUrl"),
        (isinstance(provenance.get("distroIssue"), int) and provenance["distroIssue"] > 0, "provenance.issue", "Invalid distro issue"),
        (isinstance(provenance.get("distroCommit"), str) and bool(re.fullmatch(r"[0-9a-f]{40}", provenance["distroCommit"])), "provenance.commit", "Invalid distro commit"),
        (isinstance(provenance.get("upstreamCommit"), str) and bool(re.fullmatch(r"[0-9a-f]{40}", provenance["upstreamCommit"])), "provenance.upstream-commit", "Invalid upstream commit"),
        (isinstance(provenance.get("upstreamReleaseId"), int) and provenance["upstreamReleaseId"] > 0, "provenance.release", "Invalid upstream release ID"),
        (isinstance(provenance.get("license"), str) and bool(provenance["license"]), "provenance.license", "Missing SPDX license"),
    ]
    for ok, rule, message in checks:
        if not ok:
            findings.append(Finding(rule, "error", message))
    method = provenance.get("distributionMethod")
    if method == "upstream-asset":
        asset = provenance.get("upstreamAsset")
        if not isinstance(asset, dict) or set(asset) != {"id", "name", "url"}:
            findings.append(Finding("provenance.asset", "error", "Upstream asset provenance is incomplete"))
        elif asset.get("url") != manifest.get("downloadUrl"):
            findings.append(Finding("provenance.asset-url", "error", "Upstream asset URL does not match downloadUrl"))
    elif method == "vanahub-build":
        if not isinstance(provenance.get("buildRevision"), int) or provenance["buildRevision"] < 1:
            findings.append(Finding("provenance.build-revision", "error", "Invalid VanaHub build revision"))
    return findings


def validate_manifest(manifest: dict, provenance: dict | None = None) -> list[Finding]:
    findings: list[Finding] = []
    required = {
        "schemaVersion", "id", "name", "description", "author", "maintainers",
        "version", "changelog", "sourceUrl", "downloadUrl", "sha256",
        "compressedSize", "archiveRoot", "entrypoint", "declaredCapabilities",
    }
    missing = sorted(required - manifest.keys())
    optional = {"iconUrl", "screenshots", "categories"}
    unknown = sorted(manifest.keys() - required - optional)
    if unknown:
        findings.append(Finding("manifest.unknown-fields", "error", f"Unknown fields: {', '.join(unknown)}"))
    if missing:
        findings.append(Finding("manifest.missing-fields", "error", f"Missing fields: {', '.join(missing)}"))
        return findings
    checks = [
        (manifest.get("schemaVersion") == 1, "manifest.schema", "schemaVersion must be 1"),
        (isinstance(manifest.get("id"), str) and bool(PACKAGE_ID.fullmatch(manifest["id"])), "manifest.id", "Invalid package id"),
        (isinstance(manifest.get("version"), str) and bool(SEMVER.fullmatch(manifest["version"])), "manifest.version", "Version must be SemVer"),
        (isinstance(manifest.get("sha256"), str) and bool(SHA256.fullmatch(manifest["sha256"])), "manifest.sha256", "Invalid SHA-256"),
        (isinstance(manifest.get("downloadUrl"), str) and bool(GITHUB_RELEASE.fullmatch(manifest["downloadUrl"])), "manifest.download-url", "Built-in packages must use a GitHub Release asset"),
        (isinstance(manifest.get("sourceUrl"), str) and bool(SOURCE_REPOSITORY.fullmatch(manifest["sourceUrl"])), "manifest.source-url", "sourceUrl must be a public GitHub repository"),
        (isinstance(manifest.get("compressedSize"), int) and manifest["compressedSize"] > 0, "manifest.size", "compressedSize must be positive"),
        (isinstance(manifest.get("maintainers"), list) and len(manifest["maintainers"]) > 0, "manifest.maintainers", "At least one maintainer is required"),
        (isinstance(manifest.get("entrypoint"), str) and manifest["entrypoint"].endswith(".lua") and "/" not in manifest["entrypoint"] and "\\" not in manifest["entrypoint"], "manifest.entrypoint", "Entrypoint must be a Lua filename"),
        (isinstance(manifest.get("archiveRoot"), str) and len(manifest["archiveRoot"]) <= 200, "manifest.archive-root", "archiveRoot must be a string no longer than 200 characters"),
        (isinstance(manifest.get("declaredCapabilities"), list), "manifest.capabilities", "declaredCapabilities must be an array"),
    ]
    for ok, rule, message in checks:
        if not ok:
            findings.append(Finding(rule, "error", message))
    if "screenshots" in manifest:
        screenshots = manifest["screenshots"]
        valid_screenshots = isinstance(screenshots, list) and 1 <= len(screenshots) <= 10
        if valid_screenshots:
            valid_screenshots = len(screenshots) == len(set(screenshots)) if all(isinstance(url, str) for url in screenshots) else False
        if valid_screenshots:
            for url in screenshots:
                parsed = urllib.parse.urlparse(url)
                if len(url) > 2048 or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                    valid_screenshots = False
                    break
        if not valid_screenshots:
            findings.append(Finding(
                "manifest.screenshots", "error",
                "screenshots must contain 1 to 10 unique HTTPS URLs",
            ))
    if "categories" in manifest:
        categories = manifest["categories"]
        allowed_categories = {
            "combat", "jobs", "inventory", "crafting", "economy",
            "maps-travel", "user-interface", "chat-communication",
            "data-tracking", "quality-of-life", "development-tools",
        }
        valid_categories = (
            isinstance(categories, list)
            and 1 <= len(categories) <= 3
            and len(categories) == len(set(categories))
            and all(category in allowed_categories for category in categories)
        )
        if not valid_categories:
            findings.append(Finding(
                "manifest.categories", "error",
                "categories must contain 1 to 3 unique supported categories",
            ))
    findings.extend(validate_distribution_provenance(manifest, provenance))
    if isinstance(manifest.get("sourceUrl"), str) and isinstance(manifest.get("downloadUrl"), str):
        source = urllib.parse.urlparse(manifest["sourceUrl"]).path.strip("/").split("/")
        download = urllib.parse.urlparse(manifest["downloadUrl"]).path.strip("/").split("/")
        if len(source) >= 2 and len(download) >= 2 and [part.casefold() for part in source[:2]] != [part.casefold() for part in download[:2]]:
            trusted_build = (
                provenance is not None
                and not any(item.rule_id.startswith("provenance.") for item in findings)
                and provenance.get("distributionMethod") == "vanahub-build"
                and [part.casefold() for part in download[:2]] == ["hildaware", "vanahub-addon-distro"]
            )
            if not trusted_build:
                findings.append(Finding("manifest.repository-mismatch", "error", "Release asset must belong to sourceUrl repository"))
    privileged_source = load_policy().get("privilegedPackageSources", {}).get(manifest.get("id"))
    if privileged_source and manifest.get("sourceUrl", "").rstrip("/").casefold() != privileged_source.rstrip("/").casefold():
        findings.append(Finding("manifest.privileged-source", "error", "Privileged package id is reserved for its official source repository"))
    return findings


def normalized_zip_path(name: str) -> PurePosixPath:
    if "\\" in name or "\x00" in name:
        raise ScanError("backslashes or NUL bytes are not permitted")
    if name.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", name):
        raise ScanError("absolute, UNC, and drive paths are not permitted")
    path = PurePosixPath(name)
    if any(part in ("", ".", "..") for part in path.parts):
        raise ScanError("empty, dot, and traversal path segments are not permitted")
    for part in path.parts:
        stem = part.rstrip(" .").split(".", 1)[0].lower()
        if stem in WINDOWS_DEVICES or ":" in part or part != part.rstrip(" ."):
            raise ScanError("Windows device, stream, or ambiguous path segment")
    return path


CAPABILITY_PATTERNS = {
    "ui": re.compile(r"\bimgui\b", re.IGNORECASE),
    "game-state-read": re.compile(r"\b(?:GetPlayerEntity|GetEntity|ffxi\.(?:targets|recast|vanatime|weather))\b", re.IGNORECASE),
    "packet-read": re.compile(r"\bpacket_in\b|\bregister_event\s*\(\s*['\"]packet", re.IGNORECASE),
    "chat-output": re.compile(r"\b(?:print|chat\.)\s*\(", re.IGNORECASE),
    "command-handler": re.compile(r"\bcommand\b|\bregister_event\s*\(\s*['\"]command", re.IGNORECASE),
    "settings-write": re.compile(r"\bsettings\.(?:save|store)\b", re.IGNORECASE),
    "bundled-file-read": re.compile(r"\bio\.open\b|\bread_text\b", re.IGNORECASE),
}


def detected_capabilities(text: str) -> set[str]:
    return {
        capability
        for capability, pattern in CAPABILITY_PATTERNS.items()
        if pattern.search(text)
    }


def lua_findings(text: str, path: str, policy: dict, local_modules: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    blocked = {
        "ffi": "native-interop", "socket": "network", "ssl.https": "network",
        "os.execute": "process-execution", "io.popen": "process-execution",
        "package.loadlib": "native-interop", "loadstring": "dynamic-code",
        "load": "dynamic-code", "dofile": "dynamic-code", "debug": "dynamic-code",
        "ashita.memory.write": "memory-write", "InjectPacket": "packet-injection",
        "QueueCommand": "command-injection", "CreateProcess": "process-execution",
        "ShellExecute": "process-execution", "WinExec": "process-execution",
        "LoadLibrary": "native-interop", "RegSetValue": "registry-write",
        "URLDownloadToFile": "network",
    }
    for capability, pattern in ELEVATED_PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(Finding(
                "lua.elevated-capability", "warning",
                "Elevated Lua behavior requires review", path, line, capability,
            ))
    for symbol in policy["blockedSymbols"]:
        pattern = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"(?![A-Za-z0-9_])", re.IGNORECASE)
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            severity = "error" if symbol.casefold() == "urldownloadtofile" else "warning"
            findings.append(Finding("lua.blocked-symbol", severity, f"Sensitive symbol requires semantic review: {symbol}", path, line, blocked.get(symbol, "elevated")))

    literal_requires: set[str] = set()
    for match in re.finditer(r"\brequire\s*(?:\(\s*)?(['\"])([^'\"]+)\1\s*\)?", text):
        literal_requires.add(match.group(2))
    all_requires = len(re.findall(r"\brequire\b", text))
    if all_requires != len(literal_requires):
        findings.append(Finding("lua.computed-require", "warning", "All require targets must be unique string literals", path, capability="dynamic-code"))

    if re.search(r"\b_G\b|\bpackage\s*[.[]", text):
        findings.append(Finding("lua.environment-manipulation", "warning", "Global or package environment manipulation requires semantic review", path, capability="dynamic-code"))
    if re.search(r"\\x[0-9A-Fa-f]{2}", text) and text.count("\\x") > 16:
        findings.append(Finding("lua.encoded-payload", "warning", "Large encoded payload requires semantic review", path, capability="obfuscation"))
    if max((len(line) for line in text.splitlines()), default=0) > 4000:
        findings.append(Finding("lua.obfuscated-line", "warning", "An excessively long source line requires semantic review", path, capability="obfuscation"))

    local_modules = local_modules or set()
    for module in literal_requires:
        if module in policy["allowedModules"] or module in local_modules:
            continue
        if (
            not re.fullmatch(r"[A-Za-z0-9_./-]+", module)
            or any(part in ("", ".", "..") for part in module.split("/"))
        ):
            findings.append(Finding("lua.invalid-module", "warning", f"Invalid or dynamic-looking module name requires semantic review: {module}", path, capability="dynamic-code"))
        else:
            findings.append(Finding("lua.disallowed-module", "warning", f"Module is neither policy-approved nor bundled locally: {module}", path, capability="unapproved-module"))
    return findings


def scan_archive(
    archive: Path,
    manifest: dict,
    policy: dict,
) -> tuple[list[Finding], list[str], set[str]]:
    findings: list[Finding] = []
    files: list[str] = []
    limits = policy["limits"]
    seen: set[str] = set()
    total_expanded = 0
    root = manifest.get("archiveRoot", "").strip("/")
    prefix = f"{root}/" if root else ""
    entrypoint_found = False
    capabilities: set[str] = set()

    try:
        with zipfile.ZipFile(archive) as package:
            infos = package.infolist()
            local_modules: set[str] = set()
            for info in infos:
                try:
                    normalized = normalized_zip_path(info.filename.rstrip("/")).as_posix()
                except ScanError:
                    continue
                if info.is_dir() or (prefix and not normalized.startswith(prefix)):
                    continue
                relative = normalized[len(prefix):] if prefix else normalized
                if relative.lower().endswith(".lua"):
                    slash_module = relative[:-4]
                    local_modules.add(slash_module)
                    local_modules.add(slash_module.replace("/", "."))
                    local_modules.add(slash_module.rsplit("/", 1)[-1])
            if len(infos) > limits["entries"]:
                findings.append(Finding("zip.too-many-entries", "error", "Archive entry limit exceeded"))
            for info in infos:
                try:
                    path = normalized_zip_path(info.filename.rstrip("/"))
                except ScanError as exc:
                    findings.append(Finding("zip.unsafe-path", "error", str(exc), info.filename))
                    continue
                normalized = path.as_posix()
                folded = normalized.casefold()
                if folded in seen:
                    findings.append(Finding("zip.path-collision", "error", "Duplicate or case-colliding path", normalized))
                seen.add(folded)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    findings.append(Finding("zip.symlink", "error", "Symbolic links are prohibited", normalized))
                if info.flag_bits & 0x1:
                    findings.append(Finding("zip.encrypted", "error", "Encrypted entries are prohibited", normalized))
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    findings.append(Finding("zip.compression", "error", "Only Stored and DEFLATE are supported", normalized))
                total_expanded += info.file_size
                if info.file_size > limits["entryBytes"]:
                    findings.append(Finding("zip.entry-too-large", "error", "Entry expanded-size limit exceeded", normalized))
                if info.compress_size and info.file_size / info.compress_size > limits["compressionRatio"]:
                    findings.append(Finding("zip.compression-ratio", "error", "Suspicious compression ratio", normalized))
                if info.is_dir():
                    continue
                if prefix and not normalized.startswith(prefix):
                    findings.append(Finding("zip.outside-root", "error", f"Entry is outside declared archiveRoot {root!r}", normalized))
                    continue
                relative = normalized[len(prefix):] if prefix else normalized
                if "/" not in relative and relative.casefold() == manifest.get("entrypoint", "").casefold():
                    entrypoint_found = True
                suffix = Path(relative).suffix.lower()
                engine_binary = manifest.get("id") in policy.get("privilegedPackageIds", []) and relative.casefold() == "bin/vanahub_engine.dll"
                if suffix not in policy["allowedExtensions"] and not engine_binary:
                    findings.append(Finding("zip.file-type", "error", f"File type {suffix or '<none>'} is prohibited", normalized))
                files.append(relative)
                if suffix == ".lua" and info.file_size <= limits["entryBytes"]:
                    try:
                        text = package.read(info).decode("utf-8")
                    except (UnicodeDecodeError, RuntimeError, zipfile.BadZipFile):
                        findings.append(Finding("lua.encoding", "error", "Lua source must be valid UTF-8 and readable", normalized))
                    else:
                        capabilities.update(detected_capabilities(text))
                        findings.extend(lua_findings(text, normalized, policy, local_modules))
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        findings.append(Finding("zip.invalid", "error", f"Invalid ZIP: {exc}"))

    if total_expanded > limits["expandedBytes"]:
        findings.append(Finding("zip.expanded-size", "error", "Total expanded-size limit exceeded"))
    if not entrypoint_found:
        findings.append(Finding("package.entrypoint", "error", "Declared entrypoint was not found at the archive root"))
    for capability in sorted(capabilities):
        message = policy.get("capabilityWarnings", {}).get(capability)
        if message:
            findings.append(Finding("lua.capability-warning", "warning", message, capability=capability))
    return findings, sorted(files, key=str.casefold), capabilities


class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in APPROVED_DOWNLOAD_HOSTS:
            raise ScanError(f"redirect to unapproved location: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, destination: Path, maximum: int) -> tuple[str, int]:
    opener = urllib.request.build_opener(RestrictedRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "vanahub-catalog-scanner/1"})
    digest = hashlib.sha256()
    size = 0
    with opener.open(request, timeout=30) as response, destination.open("wb") as output:
        while chunk := response.read(64 * 1024):
            size += len(chunk)
            if size > maximum:
                raise ScanError("download exceeds compressed-size limit")
            digest.update(chunk)
            output.write(chunk)
    return digest.hexdigest(), size


def scan(
    manifest_path: Path,
    archive_path: Path | None = None,
    archive_output: Path | None = None,
    provenance_path: Path | None = None,
) -> dict:
    policy = load_policy()
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    provenance = None
    if provenance_path is not None:
        with provenance_path.open("r", encoding="utf-8") as handle:
            provenance = json.load(handle)
    findings = validate_manifest(manifest, provenance)
    files: list[str] = []
    capabilities: set[str] = set()
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        if archive_path is None and not findings:
            if archive_output is None:
                temporary = tempfile.TemporaryDirectory(prefix="vanahub-scan-")
                archive_path = Path(temporary.name) / "package.zip"
            else:
                archive_output.parent.mkdir(parents=True, exist_ok=True)
                archive_path = archive_output
            try:
                digest, size = download(manifest["downloadUrl"], archive_path, policy["limits"]["compressedBytes"])
                if digest != manifest["sha256"]:
                    findings.append(Finding("artifact.hash", "error", f"SHA-256 mismatch: got {digest}"))
                if size != manifest["compressedSize"]:
                    findings.append(Finding("artifact.size", "error", f"Size mismatch: got {size}"))
            except (OSError, ScanError, urllib.error.URLError) as exc:
                findings.append(Finding("artifact.download", "error", str(exc)))
        elif archive_path is not None:
            data_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            if data_hash != manifest.get("sha256"):
                findings.append(Finding("artifact.hash", "error", f"SHA-256 mismatch: got {data_hash}"))
        if archive_path is not None and archive_path.exists() and not findings:
            archive_findings, files, capabilities = scan_archive(archive_path, manifest, policy)
            findings.extend(archive_findings)
            declared = set(manifest.get("declaredCapabilities", []))
            for capability in sorted(capabilities - declared):
                findings.append(Finding(
                    "manifest.missing-capability", "error",
                    f"Scanner-detected capability is missing from the manifest: {capability}",
                    capability=capability,
                ))
    finally:
        if temporary:
            temporary.cleanup()
    return {
        "schemaVersion": 1,
        "policyVersion": policy["version"],
        "packageId": manifest.get("id", ""),
        "version": manifest.get("version", ""),
        "sha256": manifest.get("sha256", ""),
        "accepted": not any(f.severity == "error" for f in findings),
        "findings": [asdict(f) for f in findings],
        "files": files,
        "detectedCapabilities": sorted(capabilities),
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--archive-output", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.archive and args.archive_output:
            raise ValueError("--archive and --archive-output cannot be used together")
        report = scan(args.manifest, args.archive, archive_output=args.archive_output, provenance_path=args.provenance)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
