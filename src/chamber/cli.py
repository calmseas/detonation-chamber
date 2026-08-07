"""`chamber` — containment and review for installable prompt artefacts.

Two subcommands, matching the two halves of the design:

    chamber scan      static legibility checks — deterministic, no model, no network
    chamber detonate  runtime behavioural observation — not yet implemented

`scan` answers a decidable question: are the bytes a reviewer approves the bytes
the model receives? It does not, and cannot, decide whether an artefact is
malicious. Tools claiming that get bypassed.

Exit codes are the contract, so this drops into CI unchanged:

    0   pass  — nothing found
    1   flag  — a human should look, with the evidence in front of them
    2   fail  — do not install without a recorded exception
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scan import diff_scan, scan_path, to_json

RED, YEL, GRN, DIM, OFF = "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[0m"
EXIT = {"pass": 0, "flag": 1, "fail": 2}


def _colour(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def render(bundle: dict, *, use_colour: bool) -> str:
    r, y, g, d, o = (RED, YEL, GRN, DIM, OFF) if use_colour else ("",) * 5
    lines = [f"{d}artefact{o} {bundle['artefact']}",
             f"{d}sha256  {o} {bundle['artefact_sha256'][:16]}…  "
             f"{d}({bundle['files_scanned']} files){o}", ""]

    if not bundle["findings"]:
        lines.append(f"{g}no findings{o}")
    for f in bundle["findings"]:
        tag = f"{r}FAIL{o}" if f["severity"] == "fail" else f"{y}FLAG{o}"
        loc = f":{f['line']}" if f.get("line") else ""
        lines.append(f"{tag}  {f['rule']:<16} {f['path']}{loc}")
        lines.append(f"      {f['detail']}")
        if f.get("evidence"):
            lines.append(f"      {d}evidence:{o} {f['evidence']}")
        if f.get("decoded"):
            # The point of the tool: show the reviewer what was concealed.
            lines.append(f"      {r}concealed content:{o} {f['decoded']!r}")
        lines.append("")

    v = bundle["verdict"]
    colour = {"pass": g, "flag": y, "fail": r}[v]
    lines.append(f"{colour}{v.upper()}{o}  "
                 f"{bundle['counts']['fail']} fail, {bundle['counts']['flag']} flag")
    lines.append("")
    lines.append(f"{d}NOT tested by this layer:{o}")
    for n in bundle["not_tested"]:
        lines.append(f"{d}  · {n}{o}")
    return "\n".join(lines)


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("path", type=Path, help="artefact file or directory")
    p.add_argument("--against", type=Path, metavar="OLD",
                   help="diff-gate: report only what this version introduces over OLD")
    p.add_argument("--json", action="store_true", help="emit the evidence bundle as JSON")
    p.add_argument("--review-window", type=int, default=10_000,
                   help="characters a reviewer is assumed to read (default: 10000)")
    p.add_argument("--hard-limit", type=int, default=100_000)
    p.add_argument("--max-blank-run", type=int, default=20)
    p.add_argument("--fail-on-flag", action="store_true",
                   help="treat FLAG as failure (strict CI gate)")


def _run_scan(args) -> int:
    if not args.path.exists():
        print(f"chamber: {args.path} does not exist", file=sys.stderr)
        return 2

    limits = dict(review_window=args.review_window, hard_limit=args.hard_limit,
                  max_blank_run=args.max_blank_run)

    if args.against:
        if not args.against.exists():
            print(f"chamber: {args.against} does not exist", file=sys.stderr)
            return 2
        bundle = diff_scan(args.against, args.path, **limits)
        if args.json:
            print(to_json(bundle))
        else:
            print(f"introduced by this version: {len(bundle['introduced'])} finding(s)")
            for f in bundle["introduced"]:
                print(f"  {f['severity'].upper()}  {f['rule']}  {f['path']}  {f['detail']}")
            print(f"\n{bundle['verdict'].upper()}")
    else:
        bundle = scan_path(args.path, **limits)
        print(to_json(bundle) if args.json else render(bundle, use_colour=_colour(sys.stdout)))

    code = EXIT[bundle["verdict"]]
    return 2 if (args.fail_on_flag and code == 1) else code


def _run_detonate(args) -> int:
    print(
        "chamber detonate: not implemented.\n\n"
        "The runtime half — disposable container, default-deny egress with full-body\n"
        "capture, per-run canary tokens, and a baseline arm — is specified but not\n"
        "built. `chamber scan` is the static layer and runs first.\n\n"
        "Nothing here silently degrades to a weaker check: a tool that reports a\n"
        "verdict it did not earn is the failure mode this project exists to avoid.",
        file=sys.stderr,
    )
    return 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="chamber",
        description="Containment and review for installable prompt artefacts. "
                    "Establishes that what a reviewer sees is what the model receives. "
                    "Does not, and cannot, decide whether an artefact is malicious.",
    )
    sub = ap.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="static legibility checks (deterministic)")
    _add_scan_args(scan)
    scan.set_defaults(func=_run_scan)

    det = sub.add_parser("detonate", help="runtime behavioural observation (not yet implemented)")
    det.add_argument("path", type=Path, nargs="?")
    det.set_defaults(func=_run_detonate)

    args = ap.parse_args(argv)
    if not getattr(args, "command", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
