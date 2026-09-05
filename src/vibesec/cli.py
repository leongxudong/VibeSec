from __future__ import annotations

import argparse
from pathlib import Path

from vibesec.scanner import materialize_target, scan_path, write_reports
from vibesec.triage import triage, write_triage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vibesec",
        description="Security triage and remediation handoff for rapidly developed applications",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run the small built-in deterministic POC checks")
    scan.add_argument("target", help="Local path or public GitHub HTTPS URL")
    scan.add_argument("--out", default="./reports", help="Report output directory")

    tri = sub.add_parser("triage", help="Prioritise findings from established scanner JSON/SARIF outputs")
    tri.add_argument("inputs", nargs="+", help="Semgrep JSON, SARIF, Trivy JSON, or VibeSec JSON files")
    tri.add_argument("--out", default="./reports", help="Report output directory")
    tri.add_argument("--limit", type=int, default=10, help="Maximum prioritised findings to show")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.command == "triage":
        try:
            paths = [Path(x) for x in args.inputs]
            missing = [str(x) for x in paths if not x.is_file()]
            if missing:
                raise ValueError(f"Input file(s) not found: {', '.join(missing)}")
            findings = triage(paths, max(1, args.limit))
            md, js = write_triage(findings, Path(args.out), len(paths))
            print(f"VibeSec triage complete: {len(findings)} prioritised finding(s)")
            print(f"Markdown report: {md}")
            print(f"JSON report:     {js}")
            return 0
        except (ValueError, OSError) as exc:
            print(f"VibeSec error: {exc}")
            return 1

    temp = None
    try:
        root, temp = materialize_target(args.target)
        result = scan_path(root, target_label=args.target)
        md, js = write_reports(result, Path(args.out))
        print(f"VibeSec POC scan complete: {len(result.findings)} review item(s), {len(result.controls)} control(s) detected")
        print(f"Markdown report: {md}")
        print(f"JSON report:     {js}")
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"VibeSec error: {exc}")
        return 1
    finally:
        if temp is not None:
            temp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
