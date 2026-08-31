#!/usr/bin/env python3
"""Run VanaHub's semantic Lua policy against source or a validated catalog ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import zipfile


MAX_ENTRIES = 8192
MAX_ENTRY_BYTES = 50 * 1024 * 1024
MAX_EXPANDED_BYTES = 200 * 1024 * 1024
STATIC_REVIEW_RULES = {
    "lua.blocked-symbol",
    "lua.elevated-capability",
    "lua.encoded-payload",
    "lua.environment-manipulation",
    "lua.invalid-module",
    "lua.obfuscated-line",
}


def lua_tokens(source: str) -> list[tuple[str, int]]:
    """Return Lua tokens and their starting lines without parsing comments or strings."""
    tokens: list[tuple[str, int]] = []
    index = 0
    line = 1
    while index < len(source):
        if source.startswith("--", index):
            match = re.match(r"--\[(=*)\[", source[index:])
            if match:
                closing = "]" + match.group(1) + "]"
                end = source.find(closing, index + len(match.group(0)))
                end = len(source) if end < 0 else end + len(closing)
            else:
                end = source.find("\n", index)
                end = len(source) if end < 0 else end
            line += source[index:end].count("\n")
            index = end
            continue
        character = source[index]
        if character in "'\"":
            quote = character
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == quote:
                    end += 1
                    break
                end += 1
            line += source[index:end].count("\n")
            index = end
            continue
        match = re.match(r"\[(=*)\[", source[index:])
        if match:
            closing = "]" + match.group(1) + "]"
            end = source.find(closing, index + len(match.group(0)))
            end = len(source) if end < 0 else end + len(closing)
            line += source[index:end].count("\n")
            index = end
            continue
        if character.isspace():
            if character == "\n":
                line += 1
            index += 1
            continue
        match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", source[index:])
        if match:
            value = match.group(0)
            tokens.append((value, line))
            index += len(value)
            continue
        tokens.append((character, line))
        index += 1
    return tokens


def lua_function_scopes(source: str) -> list[dict[str, int | str]]:
    """Map named Lua function ranges with a conservative token-aware block stack."""
    tokens = lua_tokens(source)
    stack: list[dict[str, int | str]] = []
    scopes: list[dict[str, int | str]] = []
    last_line = source.count("\n") + 1
    for index, (token, line) in enumerate(tokens):
        if token == "function":
            name_tokens: list[str] = []
            cursor = index + 1
            while cursor < len(tokens) and tokens[cursor][0] != "(":
                candidate = tokens[cursor][0]
                if candidate not in {".", ":"} and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate):
                    break
                name_tokens.append(candidate)
                cursor += 1
            value = "".join(name_tokens)
            name = value if value and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:]*", value) else "<anonymous function>"
            stack.append({"kind": "function", "name": name, "start": line})
        elif token in {"if", "for", "while", "repeat"}:
            stack.append({"kind": token, "start": line})
        elif token == "do":
            if not stack or stack[-1]["kind"] not in {"for", "while"}:
                stack.append({"kind": "do", "start": line})
        elif token == "until":
            if stack and stack[-1]["kind"] == "repeat":
                stack.pop()
        elif token == "end" and stack:
            closed = stack.pop()
            if closed["kind"] == "function":
                scopes.append({**closed, "end": line})
    for scope in stack:
        if scope["kind"] == "function":
            scopes.append({**scope, "end": last_line})
    return scopes


def method_for_line(path: Path, line: int, cache: dict[Path, list[dict[str, int | str]]]) -> str:
    if line <= 0:
        return "<top-level>"
    if path not in cache:
        try:
            cache[path] = lua_function_scopes(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            cache[path] = []
    matches = [scope for scope in cache[path] if int(scope["start"]) <= line <= int(scope["end"])]
    if not matches:
        return "<top-level>"
    return str(max(matches, key=lambda scope: int(scope["start"]))["name"])


def stable_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value or value.startswith("/"):
        raise ValueError(f"unsafe archive path: {value}")
    path = PurePosixPath(value)
    if any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe archive path: {value}")
    return path


def extract_lua(archive: Path, archive_root: str, destination: Path) -> Path:
    source = destination / "source"
    source.mkdir(parents=True, exist_ok=False)
    root = archive_root.strip("/")
    prefix = f"{root}/" if root else ""
    seen: set[str] = set()
    expanded = 0
    with zipfile.ZipFile(archive) as package:
        infos = package.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ValueError("archive entry limit exceeded during semantic review")
        for info in infos:
            name = info.filename.rstrip("/")
            if not name:
                continue
            normalized = normalized_path(name).as_posix()
            folded = normalized.casefold()
            if folded in seen:
                raise ValueError(f"duplicate or case-colliding archive path: {normalized}")
            seen.add(folded)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode) or info.flag_bits & 0x1:
                raise ValueError(f"link or encrypted entry during semantic review: {normalized}")
            expanded += info.file_size
            if info.file_size > MAX_ENTRY_BYTES or expanded > MAX_EXPANDED_BYTES:
                raise ValueError("archive expansion limit exceeded during semantic review")
            if info.is_dir() or (prefix and normalized == root):
                continue
            if prefix and not normalized.startswith(prefix):
                raise ValueError(f"archive entry is outside archiveRoot: {normalized}")
            relative = normalized[len(prefix):] if prefix else normalized
            if not relative.lower().endswith(".lua"):
                continue
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(package.read(info))
    return source


def safe_relative(source: Path, result_path: str) -> tuple[str, Path]:
    candidate = Path(result_path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    resolved = candidate.resolve()
    try:
        relative = resolved.relative_to(source)
    except ValueError as exc:
        raise ValueError(f"Semgrep result escapes source root: {result_path}") from exc
    return relative.as_posix(), resolved


def load_baseline(path: Path | None, package_id: str) -> dict[str, str]:
    if path is None:
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        value.get("schemaVersion") != 1
        or value.get("packageId") != package_id
        or not isinstance(value.get("reviewedCommit"), str)
        or len(value["reviewedCommit"]) != 40
        or any(character not in "0123456789abcdef" for character in value["reviewedCommit"])
        or not isinstance(value.get("files"), dict)
    ):
        raise ValueError("semantic review baseline has an invalid shape or package ID")
    files: dict[str, str] = {}
    for name, value_digest in value["files"].items():
        if (
            not isinstance(name, str)
            or normalized_path(name).as_posix() != name
            or not isinstance(value_digest, str)
            or len(value_digest) != 64
            or any(character not in "0123456789abcdef" for character in value_digest)
        ):
            raise ValueError(f"semantic review baseline contains an invalid file: {name}")
        files[name] = value_digest
    return files


def merge_catalog_report(path: Path, semantic_report: dict) -> None:
    catalog = json.loads(path.read_text(encoding="utf-8"))
    semantic_findings = []
    for finding in semantic_report["findings"]:
        severity = "warning" if finding["reviewed"] else "error"
        semantic_findings.append({
            "rule": finding["ruleId"],
            "rule_id": finding["ruleId"],
            "severity": severity,
            "message": finding["message"],
            "path": finding["path"],
            "line": finding["line"],
            "method": finding["method"],
            "capability": finding["capability"],
            "reviewed": finding["reviewed"],
        })
    catalog.setdefault("findings", []).extend(semantic_findings)
    catalog["semanticReview"] = {
        "accepted": semantic_report["accepted"],
        "findings": len(semantic_report["findings"]),
    }
    catalog["accepted"] = bool(catalog.get("accepted")) and semantic_report["accepted"]
    path.write_text(stable_json(catalog), encoding="utf-8")


def summarize_findings(findings: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], dict] = {}
    for finding in findings:
        if finding["reviewed"]:
            continue
        key = (finding["capability"], finding["risk"])
        group = groups.setdefault(key, {"capability": key[0], "risk": key[1], "findings": 0, "files": set(), "examples": []})
        group["findings"] += 1
        group["files"].add(finding["path"])
        if len(group["examples"]) < 3:
            group["examples"].append({key: finding[key] for key in ("path", "line", "method", "message")})
    return [
        {**group, "files": len(group["files"])}
        for group in sorted(groups.values(), key=lambda value: (-value["findings"], value["capability"]))
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--semgrep", default="semgrep")
    parser.add_argument("--rules", type=Path, required=True)
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--source", type=Path)
    source_group.add_argument("--archive", type=Path)
    parser.add_argument("--archive-root", default="")
    parser.add_argument("--package-id", required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--catalog-report", type=Path)
    args = parser.parse_args(argv)

    output_directory = args.output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.archive:
        temporary = tempfile.TemporaryDirectory(prefix="vanahub-semantic-")
        source = extract_lua(
            args.archive.resolve(), args.archive_root, Path(temporary.name)
        ).resolve()
    else:
        source = args.source.resolve()
        if not source.is_dir():
            raise ValueError(f"addon source directory was not found: {source}")

    raw_report = output_directory / "semgrep.json"
    subprocess.run(
        [
            args.semgrep,
            "scan",
            "--config",
            str(args.rules),
            "--metrics=off",
            "--quiet",
            "--json-output",
            str(raw_report),
            str(source),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    baseline = load_baseline(args.baseline.resolve() if args.baseline else None, args.package_id)
    raw = json.loads(raw_report.read_text(encoding="utf-8"))
    findings: list[dict] = []
    scopes: dict[Path, list[dict[str, int | str]]] = {}
    unapproved: dict[str, str] = {}
    critical = False
    if args.catalog_report:
        catalog = json.loads(args.catalog_report.read_text(encoding="utf-8"))
        root = args.archive_root.strip("/")
        prefix = f"{root}/" if root else ""
        for static in catalog.get("findings", []):
            rule_id = static.get("rule_id") or static.get("rule")
            if rule_id not in STATIC_REVIEW_RULES or not static.get("path"):
                continue
            relative = str(static["path"])
            if prefix and relative.startswith(prefix):
                relative = relative[len(prefix):]
            absolute = (source / relative).resolve()
            try:
                absolute.relative_to(source)
            except ValueError as exc:
                raise ValueError(f"catalog finding escapes source root: {relative}") from exc
            if not absolute.is_file():
                raise ValueError(f"catalog finding references a missing Lua file: {relative}")
            file_digest = digest(absolute)
            reviewed = baseline.get(relative) == file_digest
            if not reviewed:
                unapproved[relative] = file_digest
            findings.append({
                "ruleId": f"static.{rule_id}",
                "risk": "elevated",
                "capability": static.get("capability") or "elevated",
                "path": relative,
                "line": static.get("line") or 0,
                "method": method_for_line(absolute, int(static.get("line") or 0), scopes),
                "message": str(static.get("message") or "Static finding requires semantic review")[:2000],
                "reviewed": reviewed,
            })
    for result in raw.get("results", []):
        relative, absolute = safe_relative(source, result["path"])
        file_digest = digest(absolute)
        metadata = result.get("extra", {}).get("metadata", {})
        risk = metadata.get("vanahub_risk", "elevated")
        reviewed = risk == "informational" or baseline.get(relative) == file_digest
        if risk == "critical":
            reviewed = False
            critical = True
        if risk == "elevated" and not reviewed:
            unapproved[relative] = file_digest
        findings.append({
            "ruleId": result.get("check_id", "unknown"),
            "risk": risk,
            "capability": metadata.get("capability", "elevated"),
            "path": relative,
            "line": result.get("start", {}).get("line", 0),
            "method": method_for_line(absolute, int(result.get("start", {}).get("line", 0)), scopes),
            "message": result.get("extra", {}).get("message", "")[:2000],
            "reviewed": reviewed,
        })

    for error in raw.get("errors", []):
        error_path = error.get("path")
        if not error_path:
            raise ValueError(f"Semgrep reported a scan error: {error.get('message', 'unknown error')}")
        relative, absolute = safe_relative(source, error_path)
        file_digest = digest(absolute)
        reviewed = baseline.get(relative) == file_digest
        if not reviewed:
            unapproved[relative] = file_digest
        spans = error.get("spans") or []
        line = spans[0].get("start", {}).get("line", 0) if spans else 0
        findings.append({
            "ruleId": "semgrep.parse-error",
            "risk": "elevated",
            "capability": "analysis-gap",
            "path": relative,
            "line": line,
            "method": method_for_line(absolute, int(line), scopes),
            "message": str(error.get("message", "Semgrep could not fully parse this file."))[:2000],
            "reviewed": reviewed,
        })

    report = {
        "schemaVersion": 1,
        "packageId": args.package_id,
        "accepted": not critical and not unapproved,
        "findings": findings,
        "summary": summarize_findings(findings),
    }
    reviewed_commit = ""
    if args.source:
        reviewed_commit = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.strip().lower()
    if len(reviewed_commit) != 40 or any(character not in "0123456789abcdef" for character in reviewed_commit):
        reviewed_commit = "0" * 40
    candidate = {
        "schemaVersion": 1,
        "packageId": args.package_id,
        "reviewedCommit": reviewed_commit,
        "files": dict(sorted({**baseline, **unapproved}.items())),
        "findings": [finding for finding in findings if not finding["reviewed"]],
    }
    report_path = output_directory / "semantic-review.json"
    candidate_path = output_directory / "semantic-review-candidate.json"
    report_path.write_text(stable_json(report), encoding="utf-8")
    candidate_path.write_text(stable_json(candidate), encoding="utf-8")
    if args.catalog_report:
        merge_catalog_report(args.catalog_report.resolve(), report)
    print(
        f"VanaHub semantic review: {len(findings)} finding(s), "
        f"{len(unapproved)} file(s) need review."
    )
    if temporary:
        temporary.cleanup()
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        print(f"VanaHub semantic review failed: {error}", file=sys.stderr)
        raise SystemExit(1)
