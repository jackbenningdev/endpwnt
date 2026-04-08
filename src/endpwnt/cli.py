import argparse
import sys
from pathlib import Path

from endpwnt.html_reporter import HtmlReporter
from endpwnt.scanner import EndPwnt

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endpwnt",
        description="Auth-aware API endpoint security scanner.",
    )
    parser.add_argument(
        "--config",
        required=True,
        type=Path,
        help="Path to the endpwnt YAML config file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("report.html"),
        help="Path to write the HTML report (default: report.html).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high"],
        default=None,
        help="Exit non-zero if any finding meets or exceeds this severity.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    scanner = EndPwnt(config_path=str(args.config))
    findings = scanner.run_scan()

    HtmlReporter(findings).write(str(args.output))

    print(
        f"endpwnt: scanned {len(scanner.endpoints)} endpoints, "
        f"produced {len(findings)} findings -> {args.output}"
    )

    if args.fail_on:
        threshold = _SEVERITY_RANK[args.fail_on]
        worst = max(
            (_SEVERITY_RANK.get(f.severity, 0) for f in findings),
            default=0,
        )
        if worst >= threshold:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
