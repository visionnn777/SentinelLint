#!/usr/bin/env python3
"""
SentinelLint - offline AST-based style enforcer and security linter
for Python and C++.

    python run.py <path>                      scan a file or a directory
    python run.py <path> --format json        machine-readable output
    python run.py <path> --format sarif       SARIF 2.1.0 for CI / GitHub
    python run.py <path> --format html -o r.html   standalone HTML report
    python run.py <path> --fix                preview the safe auto-fixes
    python run.py <path> --fix --write        apply them, then re-scan
    python run.py --rules                     list every rule
    python run.py --selftest                  run the validation corpus

The analyzer only ever reads source code. It never executes the code it
analyses and never opens a network connection.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import analyzer.cpp        # noqa: E402,F401  (registers C++ rules)
import analyzer.python     # noqa: E402,F401  (registers Python rules)
from analyzer.core.engine import scan                      # noqa: E402
from analyzer.core.baseline import load_baseline, save_baseline, filter_baseline  # noqa: E402
from analyzer.core.policy import meets_threshold  # noqa: E402
from analyzer.core.report import (                         # noqa: E402
    render_cli, render_html, render_json, render_sarif,
)
from analyzer.core.rule import all_rules                   # noqa: E402
from analyzer.fixes.autofix import apply_fixes             # noqa: E402


def cmd_rules():
    rules = sorted(all_rules(), key=lambda r: r.id)
    print(f"\n  SentinelLint - {len(rules)} rules loaded\n")
    header = f"  {'RULE ID':<16}{'LANG':<9}{'CATEGORY':<11}{'SEVERITY':<10}{'CWE':<10}DESCRIPTION"
    print(header)
    print("  " + "-" * (len(header) + 12))
    for r in rules:
        fixable = "  [auto-fixable]" if r.fixable else ""
        print(f"  {r.id:<16}{r.language:<9}{r.category:<11}{r.severity:<10}"
              f"{(r.cwe or '-'):<10}{r.message}{fixable}")
    print()
    print(f"  Auto-fixable: {sum(1 for r in rules if r.fixable)}     "
          f"CWE-mapped: {sum(1 for r in rules if r.cwe)}")
    print()
    return 0


def cmd_selftest():
    from tests.validate import run_validation
    return run_validation()


def _exit_code_for_result(result, threshold=None):
    """Return CI-safe exit codes: 0 clean, 1 policy violation, 2 incomplete/error."""
    if result.status in {"ERROR", "PARTIAL"}:
        return 2
    threshold = threshold or "HIGH"
    return 1 if any(meets_threshold(f, threshold) for f in result.findings) else 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="sentinellint",
        description="Offline AST-based style enforcer and security linter for Python and C++.",
    )
    p.add_argument("target", nargs="?", help="file or directory to scan")
    p.add_argument("--format", "-f", default="cli",
                   choices=["cli", "json", "sarif", "html"],
                   help="output format (default: cli)")
    p.add_argument("--output", "-o", help="write the report to a file")
    p.add_argument("--fix", action="store_true",
                   help="show the safe auto-fixes as a diff")
    p.add_argument("--write", action="store_true",
                   help="with --fix, apply the fixes and re-scan")
    p.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   help="only report findings at or above this severity")
    p.add_argument("--baseline", metavar="FILE",
                   help="ignore findings already present in a SentinelLint baseline")
    p.add_argument("--write-baseline", metavar="FILE",
                   help="write the current findings as a baseline and exit")
    p.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   help="return exit code 1 when findings meet this threshold")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--rules", action="store_true", help="list every rule and exit")
    p.add_argument("--selftest", action="store_true",
                   help="run the validation corpus and report precision")
    args = p.parse_args(argv)

    if args.rules:
        return cmd_rules()
    if args.selftest:
        return cmd_selftest()
    if not args.target:
        p.print_help()
        return 1
    if not os.path.exists(args.target):
        print(f"error: path not found: {args.target}", file=sys.stderr)
        return 2

    result = scan(args.target)

    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
            root = args.target if os.path.isdir(args.target) else os.path.dirname(os.path.abspath(args.target))
            result.findings, suppressed = filter_baseline(result.findings, baseline, root=root)
            if suppressed:
                result.notes.append(f"{suppressed} finding(s) hidden by baseline: {args.baseline}")
                result.finalize()
        except (OSError, ValueError, TypeError) as exc:
            print(f"error: could not load baseline: {exc}", file=sys.stderr)
            return 2

    if args.write_baseline:
        try:
            root = args.target if os.path.isdir(args.target) else os.path.dirname(os.path.abspath(args.target))
            save_baseline(args.write_baseline, result.findings, root=root)
        except OSError as exc:
            print(f"error: could not write baseline: {exc}", file=sys.stderr)
            return 2
        print(f"Baseline written to {args.write_baseline} ({len(result.findings)} finding(s))")
        return _exit_code_for_result(result, args.fail_on)

    if args.severity:
        from analyzer.core.finding import SEVERITY_ORDER
        cutoff = SEVERITY_ORDER[args.severity]
        result.findings = [f for f in result.findings
                           if SEVERITY_ORDER.get(f.severity, 9) <= cutoff]

    # ---------------------------------------------------------- fix mode
    if args.fix:
        fix_results = apply_fixes(result.findings, write=args.write)
        changed = [r for r in fix_results if r.changed]

        if not changed:
            print("\n  No auto-fixable findings in this scan.\n")
            return _exit_code_for_result(result, args.fail_on)

        print("\n" + "=" * 74)
        print("  SentinelLint  |  " + ("APPLYING" if args.write else "PREVIEW - no files written"))
        print("=" * 74 + "\n")

        total = 0
        for r in changed:
            print(f"--- {r.path}")
            for f in r.applied:
                print(f"    {f.rule_id}  line {f.fix.line}  -  {f.fix.describe}")
                total += 1
            for f, why in r.rejected:
                print(f"    {f.rule_id}  line {f.fix.line}  -  REJECTED: {why}")
            print()
            print(r.diff())

        print(f"  {total} fix(es) verified by re-parsing the patched file.")
        if not args.write:
            print("  Nothing was written. Re-run with  --fix --write  to apply.\n")
            return 0

        print("  Files written. Re-scanning to confirm the findings are gone...\n")
        after = scan(args.target)
        before_n, after_n = len(result.findings), len(after.findings)
        print(render_cli(after, colour=not args.no_color))
        print(f"  Findings before fix: {before_n}      after fix: {after_n}"
              f"      resolved: {before_n - after_n}\n")
        return _exit_code_for_result(after, args.fail_on)

    # ------------------------------------------------------- report mode
    if args.format == "json":
        out = render_json(result)
    elif args.format == "sarif":
        out = render_sarif(result)
    elif args.format == "html":
        out = render_html(result)
    else:
        out = render_cli(result, colour=(False if args.no_color else None))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Report written to {args.output}  "
              f"({len(result.findings)} findings, {result.files_scanned} files)")
    else:
        print(out)

    return _exit_code_for_result(result, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
