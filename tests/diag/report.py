#!/usr/bin/env python3
"""Post-run diagnostic analyzer for the flow-scheduler test suite.

Reads a results tree (tests/results by default, or the first CLI arg /
RESULTS_ROOT) and writes two files into the output dir (tests/diag by
default, or --json-dir):

  diag-report.txt - human digest of what each run's scheduler.log literally
                    contains (attachment points, warnings, capacity/override
                    lines, per-process lines) plus the bench.sh stats.txt
  diag-report.json - the same data as JSON

Root-free and deterministic: it only reads artifacts already written by a run.
Exit status 0 = no literal failures found, 2 = at least one case logs one.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ATTACH_MARKERS = {
    "RTT": {
        "loaded": "BPF program loaded (RTT)!",
        "attached": "BPF program attached (RTT)!",
        "fail_load": "Failure opening/loading BPF (RTT)",
        "fail_attach": "Failure attaching BPF (RTT)",
    },
    "XDP": {
        "loaded": "BPF program loaded (XDP)!",
        "attached": "BPF program attached (XDP)!",
        "fail_load": "Failure opening/loading BPF (XDP)",
        "fail_attach": "Failure attaching XDP program to interface",
    },
    "TC": {
        "loaded": "BPF program loaded (TC)!",
        "attached": "TC egress attached to",
        "fail_load": "Failure opening/loading BPF (TC)",
        "fail_attach": "Failure attaching TC egress to",
    },
    "cgroup_skb": {
        "loaded": "BPF loaded (cgroup_skb)!",
        "attached": "BPF program attached (CGROUP_SKB)!",
        "fail_load": "Failed to load cgroup_skb BPF",
        "fail_attach": "Failure attaching BPF (CGROUP_SKB)",
    },
}

WARN_PATTERN = re.compile(r"\[WARN\] 0/\d+ (TCP|UDP|TCP-6|UDP-6) sockets matched")
CAPACITY_PATTERN = re.compile(
    r"^Capacity:\s*(\d+)\s+bps\s+\(test=(\d+)\s+sysfs=(\d+)\)"
)
OVERRIDE_PATTERN = re.compile(
    r"capacity\s+overridden\s+by\s+CAPACITY_BPS=(\d+)\s+bps"
)
PID_PATTERN = re.compile(
    r"^PID=(\S+)\((\S+)\)\s+TX=([\d.]+)\s+B/s\s+RX=([\d.]+)\s+B/s\s+sockets=(\d+)"
)

STATS_FIELDS = [
    "EGRESS_BPS", "EGRESS_BYTES",
    "INGRESS_BPS", "INGRESS_BYTES",
    "OFFERED_BPS", "OFFERED_BYTES",
    "CAP_BPS",
]


def parse_stats(path):
    stats = {}
    if path and path.exists():
        for raw in path.read_text(errors="replace").splitlines():
            parts = raw.split(None, 1)
            if len(parts) == 2:
                stats[parts[0]] = parts[1]
    return stats


def analyze_log(log_text):
    attach = {name: {} for name in ATTACH_MARKERS}
    failures = []
    warnings = []
    capacities = []
    overrides = []
    per_process = []

    for name, marks in ATTACH_MARKERS.items():
        res = attach[name]
        found_load = [ln for ln in log_text if marks["loaded"] in ln]
        found_attach = [ln for ln in log_text if marks["attached"] in ln]
        res["loaded"] = bool(found_load)
        res["attached"] = bool(found_attach)
        res["fail_load"] = bool(
            any(marks["fail_load"] in ln for ln in log_text))
        res["fail_attach"] = bool(
            any(marks["fail_attach"] in ln for ln in log_text))
        if res["fail_load"]:
            failures.append([ln for ln in log_text if marks["fail_load"] in ln][0].strip())
        if res["fail_attach"]:
            failures.append([ln for ln in log_text if marks["fail_attach"] in ln][0].strip())

    for ln in log_text:
        if WARN_PATTERN.search(ln):
            warnings.append(ln.strip())
        m = CAPACITY_PATTERN.match(ln)
        if m:
            capacities.append(
                {"bps": m.group(1), "test": m.group(2), "sysfs": m.group(3)})
        if OVERRIDE_PATTERN.search(ln):
            overrides.append(ln.strip())
        p = PID_PATTERN.match(ln)
        if p:
            per_process.append(
                {"pid": p.group(1), "comm": p.group(2),
                 "tx": p.group(3), "rx": p.group(4), "sockets": p.group(5)})

    return {
        "attachment_points": attach,
        "failures": sorted(set(failures)),
        "warnings": warnings,
        "capacity": capacities,
        "overrides": overrides,
        "per_process": per_process,
    }


def analyze_case(case_dir):
    log = case_dir / "scheduler.log"
    text = [line for line in (log.read_text(errors="replace").splitlines()
                              if log.exists() else [])]
    return {
        "scheduler": analyze_log(text),
        "stats": parse_stats(case_dir / "stats.txt"),
    }


def collect_suite(root):
    cases = {}
    if root.is_dir():
        for child in sorted(root.iterdir()):
            if child.is_dir():
                cases[child.name] = analyze_case(child)
    return cases


def analyze_outputs(root):
    root = Path(root)
    tree = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "results_root": str(root),
        "correctness": collect_suite(root / "correctness"),
        "rate_limit": collect_suite(root / "rate-limit"),
    }
    for suite, key in (("correctness", "correctness"),
                       ("rate-limit", "rate_limit")):
        summary = root / suite / "summary.txt"
        if summary.exists():
            tree[key]["_summary"] = summary.read_text(errors="replace").strip()
    return tree


def human(n_str):
    try:
        n = int(n_str)
    except (TypeError, ValueError):
        return n_str or "-"
    units = ["", "k", "M", "G", "T"]
    for i, u in enumerate(units):
        if abs(n) < 1000 or i == len(units) - 1:
            return f"{n}{u}"
        n //= 1000
    return str(n)


def render_report(tree, sink):
    w = sink.write
    w("flow-scheduler diagnostic report (evidence from run logs)\n")
    w(f"generated: {tree['generated']}\nsource:    {tree['results_root']}\n")

    for suite_key, title in (("correctness", "CORRECTNESS"),
                             ("rate_limit", "RATE-LIMIT")):
        body = tree.get(suite_key, {})
        names = sorted(k for k in body if not k.startswith("_"))
        w(f"\n## {title}\n")
        if not names:
            w("  (no cases)\n")
            continue
        if "_summary" in body:
            w(f"summary:\n{body['_summary']}\n")
        for name in names:
            case = body[name]
            log = case["scheduler"]
            stats = case["stats"]
            w(f"\n  --- {suite_key}/{name}\n")
            w("  attachments:\n")
            for comp, st in log["attachment_points"].items():
                w("    {:<10} {} / {}\n".format(
                    comp,
                    "loaded" if st["loaded"] else "NOT loaded",
                    "attached" if st["attached"] else "NOT attached"))
            if log["failures"]:
                w("  failure lines (literal):\n")
                for f in log["failures"]:
                    w(f"    {f}\n")
            else:
                w("  failures: none\n")
            if log["warnings"]:
                w(f"  warnings (literal, {len(log['warnings'])}):\n")
                for wa in log["warnings"]:
                    w(f"    {wa}\n")
            else:
                w("  warnings: none\n")
            if log["capacity"]:
                c = log["capacity"][-1]
                w("  capacity (last): {0} bps  test={1}  sysfs={2}\n".format(
                    human(c["bps"]), human(c["test"]), human(c["sysfs"])))
            else:
                w("  capacity: no Capacity line\n")
            for ov in log["overrides"]:
                w(f"  override: {ov}\n")
            if log["per_process"]:
                pp = log["per_process"][-1]
                w("  per-process (last of {}): PID={} comm={} TX={} B/s"
                  " RX={} B/s sockets={}\n".format(
                    len(log["per_process"]), pp["pid"], pp["comm"],
                    pp["tx"], pp["rx"], pp["sockets"]))
            if stats:
                w("  stats:\n")
                for k in STATS_FIELDS:
                    if k in stats:
                        w("    {:<14}= {}\n".format(k, human(stats[k])))
    w("\nend of report. all values above are taken verbatim from the run logs.\n")


def main(argv):
    ap = argparse.ArgumentParser(
        description="Post-run analyzer: what the scheduler logs literally "
                    "contain, per test case.")
    ap.add_argument("results_root", nargs="?",
                    help="results tree (default: $RESULTS_ROOT or "
                         "tests/results relative to this file)")
    ap.add_argument("--json-dir", default=None,
                    help="write report files here (default: this script's "
                         "parent dir, tests/diag)")
    args = ap.parse_args(argv)

    root = args.results_root or os.environ.get("RESULTS_ROOT")
    if not root:
        root = Path(__file__).resolve().parent.parent / "results"
    root = Path(root)
    if not root.is_dir():
        ap.error(f"results root does not exist: {root}")

    out_dir = Path(args.json_dir) if args.json_dir else Path(__file__).resolve().parent
    out_dir.mkdir(parents=True, exist_ok=True)
    tree = analyze_outputs(root)

    out_json = out_dir / "diag-report.json"
    out_txt = out_dir / "diag-report.txt"
    out_json.write_text(json.dumps(tree, indent=2) + "\n")
    with open(out_txt, "w") as f:
        render_report(tree, f)

    n_bad = 0
    for suite_key in ("correctness", "rate_limit"):
        for name, case in tree.get(suite_key, {}).items():
            if isinstance(case, dict) and case["scheduler"]["failures"]:
                n_bad += 1

    print(f"[diag] report: {out_txt}")
    print(f"[diag] json:   {out_json}")
    if n_bad:
        print(f"[diag] {n_bad} case(s) with literal attach-failure lines")
        return 2
    print("[diag] no literal attach-failure lines found")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))