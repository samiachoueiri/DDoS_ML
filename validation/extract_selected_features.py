#!/usr/bin/env python3
"""
Run the offline feature extractor on a PCAP, keep only the 3 features that the
P4 program computes online (total_bytes, max_pkt_len, max_iat_us), and compare
them with the online CSV read from the pipeline registers.

The offline CSV uses the same column names as the online CSV. Both sides
measure IAT in integer microseconds, so no unit conversion is done.

Rows are matched by 5-tuple. total_bytes and max_pkt_len must match exactly;
max_iat_us passes if it is within --iat-tol-pct percent or --iat-tol-us
microseconds of the offline value, whichever is larger (replay adds jitter).

Usage:
    python3 extract_selected_features.py --pcap-file test_data_1flow/test_flows.pcap
    python3 extract_selected_features.py --pcap-file test_data/test_flows.pcap --online-file test_data/online_selected_n5.csv
    python3 extract_selected_features.py --pcap-file X.pcap --n-packets 3 --no-compare
"""

import argparse
import contextlib
import csv
import io
import statistics
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "preprocessing"))
import extract_first_n_flow_features_streaming as extractor  # noqa: E402

FLOW_COLUMNS = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
FEATURES = ["total_bytes", "max_pkt_len", "max_iat_us"]
OUTPUT_COLUMNS = FLOW_COLUMNS + ["npackets"] + FEATURES

PROTO_NUMBERS = {"TCP": 6, "UDP": 17}


# --------------------------------------------------------------------------
# Offline extraction
# --------------------------------------------------------------------------

def extract_offline(pcap, n_packets):
    """Run the streaming extractor with the training settings and return selected rows."""
    with tempfile.TemporaryDirectory() as tmp:
        full_csv = Path(tmp) / "all_features.csv"
        # Same settings as the training data: directional flows, 120 s timeout.
        with contextlib.redirect_stdout(io.StringIO()):
            extractor.process_pcap(
                pcap_path=str(pcap), output_file=str(full_csv), n_packets=n_packets,
                label="", bidirectional=False, flow_timeout=120.0, progress_interval=0,
                cleanup_interval=100000, flush_interval=0, write_incomplete_at_end=False,
            )
        with open(full_csv) as f:
            rows = list(csv.DictReader(f))

    return [{
        **{c: r[c] for c in FLOW_COLUMNS},
        "npackets": int(r["packet_count"]),
        "total_bytes": int(r["total_bytes"]),
        "max_pkt_len": int(r["packet_length_max"]),
        "max_iat_us": int(r["iat_max"]),  # extractor outputs IAT in integer us
    } for r in rows]


def write_offline(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        w.writeheader()
        w.writerows(rows)


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

def offline_key(r):
    proto = PROTO_NUMBERS.get(r["protocol"], r["protocol"])
    return (r["src_ip"], r["dst_ip"], int(proto), int(r["src_port"]), int(r["dst_port"]))


def read_online(path):
    """Read the online CSV, skipping lines that are not valid data rows."""
    rows, skipped = [], 0
    with open(path) as f:
        for r in csv.DictReader(f):
            try:
                rows.append({
                    "flow_id": r["flow_id"],
                    "key": (r["src_ip"], r["dst_ip"], int(r["proto"]),
                            int(r["src_port"]), int(r["dst_port"])),
                    "packets": int(r["packets"]),
                    "npackets": int(r["npackets"]),
                    **{c: int(r[c]) for c in FEATURES},
                })
            except (KeyError, TypeError, ValueError):
                skipped += 1
    return rows, skipped


def fmt_key(k):
    src, dst, proto, sport, dport = k
    return f"{src}:{sport} -> {dst}:{dport} proto {proto}"


def pct(diff, ref):
    return 100.0 * diff / ref if ref else None


def compare(offline_rows, online_rows, n_packets, iat_tol_pct, iat_tol_us):
    # Offline can have several rows per 5-tuple (flow restarted after the 120 s
    # timeout). The P4 program has no timeout, so it matches the first one.
    offline_by_key = {}
    offline_restarts = []
    for r in offline_rows:
        k = offline_key(r)
        if k in offline_by_key:
            offline_restarts.append(k)
        else:
            offline_by_key[k] = r

    online_by_key = {r["key"]: r for r in online_rows}

    matched, failures = [], 0
    for k, on in online_by_key.items():
        off = offline_by_key.get(k)
        if off is None:
            continue
        result = {"key": k, "flow_id": on["flow_id"], "online": on, "offline": off, "checks": {}}
        for feat in FEATURES:
            diff = on[feat] - off[feat]
            if feat == "max_iat_us":
                ok = abs(diff) <= max(iat_tol_us, iat_tol_pct / 100.0 * off[feat])
            else:
                ok = diff == 0
            result["checks"][feat] = (diff, pct(diff, off[feat]), ok)
            failures += not ok
        matched.append(result)

    online_only = [r for k, r in online_by_key.items() if k not in offline_by_key]
    offline_only = [r for k, r in offline_by_key.items() if k not in online_by_key]
    return matched, online_only, offline_only, offline_restarts, failures


def print_report(matched, online_only, offline_only, offline_restarts, failures,
                 n_packets, skipped, iat_tol_pct, iat_tol_us):
    line = "=" * 105
    print(line)
    print(f"ONLINE vs OFFLINE FEATURE DRIFT REPORT   (N = {n_packets})")
    print(line)
    print(f"Matched flows:            {len(matched)}")
    print(f"Online only (no offline): {len(online_only)}")
    print(f"Offline only (no online): {len(offline_only)}")
    print(f"Offline timeout restarts: {len(offline_restarts)}")
    if skipped:
        print(f"Skipped online lines:     {skipped} (not valid data rows)")
    print(f"IAT tolerance:            max({iat_tol_pct}%, {iat_tol_us} us)")

    if matched:
        print()
        print("Per-flow comparison (online - offline)")
        print("-" * 105)
        print(f"{'flow':50} {'feature':12} {'offline':>10} {'online':>10} {'diff':>9} {'drift %':>8}  ")
        print("-" * 105)
        for m in matched:
            label = f"{fmt_key(m['key'])} [{m['flow_id']}]"
            for i, feat in enumerate(FEATURES):
                diff, p, ok = m["checks"][feat]
                p_str = f"{p:+.2f}" if p is not None else "n/a"
                print(f"{label if i == 0 else '':50} {feat:12} {m['offline'][feat]:>10} "
                      f"{m['online'][feat]:>10} {diff:>+9} {p_str:>8}  {'OK' if ok else 'FAIL'}")
            print()

        print("Drift summary per feature")
        print("-" * 105)
        print(f"{'feature':12} {'pass':>8} {'exact':>7} {'mean |diff|':>12} {'max |diff|':>11} "
              f"{'mean drift %':>13} {'max |drift %|':>14}")
        print("-" * 105)
        for feat in FEATURES:
            checks = [m["checks"][feat] for m in matched]
            diffs = [abs(d) for d, _, _ in checks]
            pcts = [p for _, p, _ in checks if p is not None]
            passed = sum(ok for _, _, ok in checks)
            exact = sum(d == 0 for d in diffs)
            mean_pct = f"{statistics.mean(pcts):+.3f}" if pcts else "n/a"
            max_pct = f"{max(abs(p) for p in pcts):.3f}" if pcts else "n/a"
            print(f"{feat:12} {f'{passed}/{len(checks)}':>8} {exact:>7} {statistics.mean(diffs):>12.1f} "
                  f"{max(diffs):>11} {mean_pct:>13} {max_pct:>14}")

    if online_only:
        print()
        print("Online only")
        print("-" * 105)
        for r in online_only:
            why = (f"incomplete: {r['npackets']} < N packets, offline writes no row"
                   if r["npackets"] < n_packets else "no offline row (check parser / 5-tuple)")
            print(f"  {fmt_key(r['key'])} [{r['flow_id']}]: {why}")

    if offline_only:
        print()
        print("Offline only")
        print("-" * 105)
        for r in offline_only:
            k = offline_key(r)
            why = "IPv6, not parsed by the P4 program" if ":" in r["src_ip"] else "not seen online"
            print(f"  {fmt_key(k)}: {why}")

    if offline_restarts:
        print()
        print("Offline timeout restarts (P4 has no flow timeout, so these have no online row)")
        print("-" * 105)
        for k in offline_restarts:
            print(f"  {fmt_key(k)}")

    print()
    print(line)
    verdict = "PASS" if failures == 0 and matched else "FAIL"
    print(f"RESULT: {verdict}  ({failures} feature check(s) failed on {len(matched)} matched flow(s))")
    print(line)
    return verdict == "PASS"


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap-file", required=True)
    ap.add_argument("--n-packets", type=int, default=5, help="First N packets per flow (default: 5)")
    ap.add_argument("--output-file", help="Offline CSV. Default: offline_selected_n{N}.csv next to the PCAP")
    ap.add_argument("--online-file", help="Online CSV. Default: online_selected_n{N}.csv next to the PCAP")
    ap.add_argument("--no-compare", action="store_true", help="Only write the offline CSV")
    ap.add_argument("--iat-tol-pct", type=float, default=5.0, help="IAT tolerance in percent (default: 5)")
    ap.add_argument("--iat-tol-us", type=float, default=100.0, help="IAT tolerance floor in us (default: 100)")
    args = ap.parse_args()

    pcap = Path(args.pcap_file)
    out = Path(args.output_file or pcap.parent / f"offline_selected_n{args.n_packets}.csv")

    offline_rows = extract_offline(pcap, args.n_packets)
    write_offline(out, offline_rows)
    print(f"{len(offline_rows)} flows, N={args.n_packets} -> {out}")

    if args.no_compare:
        return

    online_path = Path(args.online_file or pcap.parent / f"online_selected_n{args.n_packets}.csv")
    if not online_path.exists():
        sys.exit(f"Online CSV not found: {online_path} (use --online-file or --no-compare)")
    online_rows, skipped = read_online(online_path)
    print(f"{len(online_rows)} flows read from {online_path}")
    print()

    results = compare(offline_rows, online_rows, args.n_packets, args.iat_tol_pct, args.iat_tol_us)
    ok = print_report(*results, args.n_packets, skipped, args.iat_tol_pct, args.iat_tol_us)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
