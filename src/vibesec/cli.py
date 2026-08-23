from __future__ import annotations

import argparse
from pathlib import Path

from vibesec.scanner import materialize_target, scan_path, write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vibesec", description="Explainable security review for rapidly developed web apps")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a local repository or public GitHub repository")
    scan.add_argument("target", help="Local path or public GitHub HTTPS URL")
    scan.add_argument("--out", default="./reports", help="Report output directory")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command != "scan":
        return 2
    temp = None
    try:
        root, temp = materialize_target(args.target)
        result = scan_path(root, target_label=args.target)
        md, js = write_reports(result, Path(args.out))
        print(f"VibeSec scan complete: {len(result.findings)} review item(s), {len(result.controls)} control(s) detected")
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
