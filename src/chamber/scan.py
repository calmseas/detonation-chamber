"""Walk an artefact and produce an evidence bundle.

An artefact is a directory (a SKILL.md folder, an MCP server definition, a rule
file and its supporting material) or a single file. Every file is read as bytes
first -- binary detection has to happen before any decode -- and only then as
text if it decodes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from .rules import FAIL, FLAG, Finding, TEXT_RULES, check_binary, check_size

# Directories skipped as build/VCS noise. NOTE: skipping a directory must never
# make a genuinely-loadable file invisible. __pycache__ was here originally and
# was a critical bypass -- it is the one place a .pyc normally lives, and a
# shipped unchecked-hash .pyc is loaded in preference to its source. Bytecode is
# therefore scanned wherever it sits, regardless of this set (see scan_path).
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", ".mypy_cache"}

# Files scanned even inside an otherwise-skipped directory: they carry
# executable behaviour a reviewer does not read.
ALWAYS_SCAN_SUFFIXES = (".pyc", ".pyo", ".so", ".dll", ".dylib")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bom_decode(data: bytes) -> str | None:
    """Decode content that declares a non-UTF-8 encoding via BOM.

    The original code attempted UTF-8 only and treated failure as a terminal
    FLAG that skipped every text rule -- so a whole hostile file encoded as
    UTF-16 disarmed R1/R2/R3/R5 for the cost of one flag. If the bytes decode
    cleanly under a declared BOM, review the decoded text like any other.
    """
    for bom, enc in ((b"\xff\xfe\x00\x00", "utf-32-le"), (b"\x00\x00\xfe\xff", "utf-32-be"),
                     (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"),
                     (b"\xef\xbb\xbf", "utf-8-sig")):
        if data.startswith(bom):
            try:
                return data[len(bom):].decode(enc)
            except UnicodeDecodeError:
                return None
    return None


def scan_path(root: Path, **limits) -> dict:
    """Scan a file or directory. Returns an evidence bundle, not a verdict."""
    root = Path(root)
    files: list[Path] = []
    if root.is_file():
        files = [root]
    else:
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            skipped = any(part in SKIP_DIRS for part in p.parts)
            # A skipped directory does not hide executable payloads.
            if not skipped or p.suffix in ALWAYS_SCAN_SUFFIXES:
                files.append(p)

    findings: list[Finding] = []
    inventory: list[dict] = []

    for p in files:
        rel = str(p.relative_to(root)) if root.is_dir() else p.name

        # Read must not fail open. A crash here previously exited 1 (below the
        # FAIL threshold), so an unreadable file read as "not blocked".
        try:
            data = p.read_bytes()
        except OSError as exc:
            findings.append(Finding(
                "R0.unreadable", FAIL, rel,
                detail=f"could not be read, so was not reviewed: {exc}",
                evidence=type(exc).__name__,
            ))
            inventory.append({"path": rel, "bytes": None, "sha256": None})
            continue

        inventory.append({"path": rel, "bytes": len(data), "sha256": _sha256(data)})

        findings.extend(check_binary(rel, data))

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = _bom_decode(data)
            if text is None:
                findings.append(Finding(
                    "R4.encoding", FLAG, rel,
                    detail="not valid UTF-8 and no recognised BOM — cannot be reviewed as text",
                    evidence=f"{len(data)} bytes",
                ))
                continue
            # Decoded under a declared non-UTF-8 encoding: fall through and apply
            # every text rule to the decoded content, exactly as for UTF-8.
            findings.append(Finding(
                "R4.encoding", FLAG, rel,
                detail="declares a non-UTF-8 encoding (BOM) — reviewed after decoding, but a "
                       "reviewer's editor may render it differently",
                evidence=f"{len(data)} bytes",
            ))

        # The whole per-file rule pass must not fail open either.
        for rule in TEXT_RULES:
            try:
                # check_size is the only rule that takes tunable limits.
                findings.extend(rule(rel, text, **limits) if rule is check_size else rule(rel, text))
            except Exception as exc:  # a rule crash is a review gap, not a pass
                findings.append(Finding(
                    "R0.rule_error", FAIL, rel,
                    detail=f"{rule.__name__} raised on this file, leaving it partly unreviewed: {exc}",
                    evidence=type(exc).__name__,
                ))

    fails = [f for f in findings if f.severity == FAIL]
    flags = [f for f in findings if f.severity == FLAG]

    return {
        "artefact": str(root),
        "artefact_sha256": _tree_hash(inventory),
        "files_scanned": len(files),
        "inventory": inventory,
        "verdict": "fail" if fails else ("flag" if flags else "pass"),
        "counts": {"fail": len(fails), "flag": len(flags)},
        "findings": [asdict(f) for f in findings],
        # Stating what was not tested is part of the bundle, not a footnote.
        "not_tested": [
            "whether the artefact's instructions are harmful in intent",
            "runtime behaviour — see the detonation chamber",
            "dormant or conditional payloads",
            "semantic equivalence of code the artefact ships",
        ],
    }


def _tree_hash(inventory: list[dict]) -> str:
    """One hash over the whole artefact, so a bundle pins exactly what was seen."""
    h = hashlib.sha256()
    for entry in sorted(inventory, key=lambda e: e["path"]):
        h.update(entry["path"].encode())
        # An unreadable file has no content hash; pin the fact, not a digest.
        h.update((entry["sha256"] or "unreadable").encode())
    return h.hexdigest()


def diff_scan(old: Path, new: Path, **limits) -> dict:
    """R5 diff-gating: score the change, not the artefact.

    The realistic attack on a trusted artefact is an update to it, so an update
    is reviewed against what was previously accepted rather than from scratch.
    """
    a, b = scan_path(old, **limits), scan_path(new, **limits)
    before = {(f["rule"], f["path"], f["evidence"]) for f in a["findings"]}
    introduced = [f for f in b["findings"] if (f["rule"], f["path"], f["evidence"]) not in before]
    return {
        "old_sha256": a["artefact_sha256"],
        "new_sha256": b["artefact_sha256"],
        "verdict": "fail" if any(f["severity"] == FAIL for f in introduced)
                   else ("flag" if introduced else "pass"),
        "introduced": introduced,
        "pre_existing": a["counts"],
    }


def to_json(bundle: dict) -> str:
    return json.dumps(bundle, indent=2, ensure_ascii=False)
