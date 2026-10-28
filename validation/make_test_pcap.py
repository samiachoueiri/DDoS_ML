#!/usr/bin/env python3
"""
Build a small, deterministic test PCAP plus the feature rows that the offline
extractor (preprocessing/extract_first_n_flow_features_streaming.py, directional
mode, default flow timeout) is expected to produce from it.

The expected rows are computed here from the declared packet specs, without
calling the extractor, so they can be used as ground truth for both the
offline extractor and the online feature extraction.

Usage:
    python3 make_test_pcap.py                       # writes test_flows.pcap + expected_features_n{3,4,5}.csv
    python3 make_test_pcap.py --check               # also runs the offline extractor and diffs
    python3 make_test_pcap.py --n-values 3 --out-dir /some/dir
    python3 make_test_pcap.py --flows tcp_exact_n --out-dir test_data_1flow --check   # single flow, no ARP
    python3 make_test_pcap.py --flows tcp_exact_n --packets-per-flow 32 --out-dir test_data_1flow --check
"""

import argparse
import csv
import socket
import statistics
import sys
from pathlib import Path

import dpkt

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "preprocessing"))

# Only the column list is shared with the extractor; the feature math below is independent.
from extract_first_n_flow_features_streaming import FIELDNAMES  # noqa: E402

BASE_TS = 1_700_000_000.0
MIN_FRAME = 60  # Ethernet minimum without FCS; NICs pad shorter frames on replay
LABEL = "test"

SRC_MAC = b"\x00\x00\x00\x00\x00\x01"
DST_MAC = b"\x00\x00\x00\x00\x00\x21"

SYN, ACK, FIN, RST, PSH, URG = (
    dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN,
    dpkt.tcp.TH_RST, dpkt.tcp.TH_PUSH, dpkt.tcp.TH_URG,
)


# --------------------------------------------------------------------------
# Packet builders: each returns raw Ethernet bytes of exactly `frame_len`.
# --------------------------------------------------------------------------

def _eth(payload, eth_type):
    return bytes(dpkt.ethernet.Ethernet(src=SRC_MAC, dst=DST_MAC, type=eth_type, data=payload))


def build_frame(pkt):
    """pkt: dict with proto, src, dst, sport, dport, flags, frame_len, v6."""
    v6 = pkt.get("v6", False)
    l3_hdr = 40 if v6 else 20
    proto = pkt["proto"]

    if proto == "TCP":
        l4_hdr = 20
    elif proto == "UDP":
        l4_hdr = 8
    elif proto == "ICMP":
        l4_hdr = 8
    else:
        raise ValueError(proto)

    payload_len = pkt["frame_len"] - 14 - l3_hdr - l4_hdr
    if payload_len < 0:
        raise ValueError(f"frame_len {pkt['frame_len']} too small for {proto}")
    payload = bytes(i % 251 for i in range(payload_len))

    if proto == "TCP":
        l4 = dpkt.tcp.TCP(sport=pkt["sport"], dport=pkt["dport"], seq=1000, ack=0,
                          flags=pkt["flags"], off=5, win=65535, data=payload)
        ip_p = dpkt.ip.IP_PROTO_TCP
    elif proto == "UDP":
        l4 = dpkt.udp.UDP(sport=pkt["sport"], dport=pkt["dport"], data=payload)
        l4.ulen = 8 + payload_len
        ip_p = dpkt.ip.IP_PROTO_UDP
    else:
        l4 = dpkt.icmp.ICMP(type=8, code=0, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=payload))
        ip_p = dpkt.ip.IP_PROTO_ICMP

    if v6:
        ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, pkt["src"]),
                          dst=socket.inet_pton(socket.AF_INET6, pkt["dst"]),
                          nxt=ip_p, hlim=64, data=l4)
        ip.plen = len(bytes(l4))
        frame = _eth(ip, dpkt.ethernet.ETH_TYPE_IP6)
    else:
        ip = dpkt.ip.IP(src=socket.inet_aton(pkt["src"]), dst=socket.inet_aton(pkt["dst"]),
                        p=ip_p, ttl=64, data=l4)
        ip.len = 20 + len(bytes(l4))
        frame = _eth(ip, dpkt.ethernet.ETH_TYPE_IP)

    assert len(frame) == pkt["frame_len"], (len(frame), pkt["frame_len"])
    return frame


def build_arp_frame():
    arp = dpkt.arp.ARP(sha=SRC_MAC, spa=socket.inet_aton("10.0.0.1"),
                       tha=b"\x00" * 6, tpa=socket.inet_aton("10.0.0.2"), op=dpkt.arp.ARP_OP_REQUEST)
    frame = _eth(arp, dpkt.ethernet.ETH_TYPE_ARP)
    return frame + b"\x00" * max(0, MIN_FRAME - len(frame))


# --------------------------------------------------------------------------
# Scenarios. Each flow is a list of (time_offset_seconds, frame_len, tcp_flags).
# Time offsets are in whole microseconds so the PCAP stores them exactly.
# `segments` says which slices of the flow's packets become output rows.
# --------------------------------------------------------------------------

def scenarios(n):
    """
    Returns list of dicts:
        name, proto, src, dst, sport, dport, v6, packets [(t, len, flags)],
        segments: list of packet-index lists that must each produce one row
    """
    s = []

    def add(name, proto, src, dst, sport, dport, packets, segments, v6=False):
        s.append(dict(name=name, proto=proto, src=src, dst=dst, sport=sport, dport=dport,
                      v6=v6, packets=packets, segments=segments))

    first_n = list(range(n))

    # 1. TCP handshake-ish flow, exactly N packets, varied sizes and IATs, several flags.
    #    Packets after the 5th are a data exchange (alternating PSH|ACK / ACK).
    head = [  # (iat, len, flags)
        (0.0, 74, SYN), (0.001250, 66, ACK), (0.004000, 590, PSH | ACK),
        (0.000500, 1514, FIN | ACK), (0.020000, 60, ACK),
    ]
    tail = [
        (0.001000, 1514, PSH | ACK), (0.000200, 66, ACK), (0.003000, 1200, PSH | ACK),
        (0.000150, 66, ACK), (0.010000, 800, PSH | ACK),
    ]
    t, pk = 0.0, []
    for i in range(n):
        iat, flen, flags = head[i] if i < len(head) else tail[(i - len(head)) % len(tail)]
        t += iat
        pk.append((t, flen, flags))
    add("tcp_exact_n", "TCP", "10.0.0.1", "10.0.0.2", 40001, 80, pk, [first_n])

    # 2. Reverse direction of flow 1 -> separate flow in directional mode.
    pk = [(0.000300 + i * 0.002000, 60 + 10 * i, SYN | ACK if i == 0 else ACK) for i in range(n)]
    add("tcp_reverse_dir", "TCP", "10.0.0.2", "10.0.0.1", 80, 40001, pk, [first_n])

    # 3. UDP flow with N+3 packets: only the first N count, rest are skipped.
    pk = [(0.010000 + i * 0.003000 + (i % 2) * 0.000700, 100 + 37 * i, 0) for i in range(n + 3)]
    add("udp_more_than_n", "UDP", "10.0.1.1", "10.0.1.2", 5353, 53, pk, [first_n])

    # 4. Incomplete UDP flow (N-1 packets): no row unless --write-incomplete-at-end.
    pk = [(0.020000 + i * 0.001000, 200, 0) for i in range(n - 1)]
    add("udp_incomplete", "UDP", "10.0.2.1", "10.0.2.2", 12345, 9999, pk, [])

    # 5. TCP flood-like: all packets in the same microsecond -> duration 0, pps/bps 0.
    pk = [(0.030000, 60, SYN) for _ in range(n)]
    add("tcp_zero_duration", "TCP", "10.0.3.1", "10.0.3.2", 1024, 443, pk, [first_n])

    # 6. TCP flags URG/RST/PSH counting.
    flag_cycle = [URG | ACK, RST, PSH | URG | ACK, RST | ACK, FIN]
    pk = [(0.040000 + i * 0.000900, 60 + i, flag_cycle[i % len(flag_cycle)]) for i in range(n)]
    add("tcp_flags_mix", "TCP", "10.0.4.1", "10.0.4.2", 5555, 22, pk, [first_n])

    # 7. ICMP echo: protocol column is "1", ports 0.
    pk = [(0.050000 + i * 1.000000, 98, 0) for i in range(n)]
    add("icmp_echo", "ICMP", "10.0.5.1", "10.0.5.2", 0, 0, pk, [first_n])

    # 8. IPv6 UDP flow.
    pk = [(0.060000 + i * 0.010000, 90 + 100 * i, 0) for i in range(n)]
    add("udp_ipv6", "UDP", "2001:db8::1", "2001:db8::2", 7000, 7001, pk, [first_n], v6=True)

    # 9. Flow timeout: completes, gets more packets within timeout (skipped),
    #    then goes idle > 120 s and restarts -> second row from the new packets.
    seg1 = [(0.070000 + i * 0.005000, 120, 0) for i in range(n)]
    extra = [(0.200000, 120, 0), (0.300000, 120, 0)]
    seg2 = [(300.000000 + i * 0.002000, 300 + i * 50, 0) for i in range(n)]
    pk = seg1 + extra + seg2
    add("udp_timeout_restart", "UDP", "10.0.6.1", "10.0.6.2", 6000, 6001, pk,
        [first_n, list(range(n + 2, n + 2 + n))])

    return s


# --------------------------------------------------------------------------
# Independent expected-feature computation.
# --------------------------------------------------------------------------

def protocol_name(proto):
    return {"TCP": "TCP", "UDP": "UDP", "ICMP": "1"}[proto]


def expected_row(sc, pkt_ts, idx):
    """pkt_ts: integer microseconds. Timing features (duration, iat_*) are in us."""
    ts = [pkt_ts[i] for i in idx]
    lens = [sc["packets"][i][1] for i in idx]
    flags = [sc["packets"][i][2] for i in idx]
    iats = [b - a for a, b in zip(ts, ts[1:])]
    dur = ts[-1] - ts[0]
    count = len(idx)
    total = sum(lens)

    def mean(v): return statistics.mean(v) if v else 0
    def std(v): return statistics.stdev(v) if len(v) > 1 else 0

    def cnt(bit): return sum(1 for f in flags if f & bit)

    return {
        "src_ip": sc["src"], "dst_ip": sc["dst"],
        "src_port": sc["sport"], "dst_port": sc["dport"],
        "protocol": protocol_name(sc["proto"]),
        "packet_count": count,
        "duration": dur,
        "total_bytes": total,
        "packets_per_second": count * 1_000_000 / dur if dur > 0 else 0,
        "bytes_per_second": total * 1_000_000 / dur if dur > 0 else 0,
        "packet_length_min": min(lens), "packet_length_max": max(lens),
        "packet_length_mean": mean(lens), "packet_length_std": std(lens),
        "iat_min": min(iats) if iats else 0, "iat_max": max(iats) if iats else 0,
        "iat_mean": mean(iats), "iat_std": std(iats),
        "tcp_syn_count": cnt(SYN), "tcp_ack_count": cnt(ACK), "tcp_fin_count": cnt(FIN),
        "tcp_rst_count": cnt(RST), "tcp_psh_count": cnt(PSH), "tcp_urg_count": cnt(URG),
        "label": LABEL,
    }


def to_usec(t):
    return round(t * 1_000_000)


def select(scs, flows):
    return [sc for sc in scs if flows is None or sc["name"] in flows]


def build(n, flows=None):
    """Return the list of (ts_usec_offset, frame), sorted by time."""
    events = []
    for sc in select(scenarios(n), flows):
        for (t, flen, flags) in sc["packets"]:
            if flen < MIN_FRAME:
                raise ValueError(f"{sc['name']}: frame {flen} < {MIN_FRAME}")
            events.append((to_usec(t), build_frame(dict(sc, flags=flags, frame_len=flen))))

    # A couple of non-IP frames that must be ignored (only in the full test).
    if flows is None:
        events.append((to_usec(0.000100), build_arp_frame()))
        events.append((to_usec(0.045000), build_arp_frame()))

    events.sort(key=lambda e: e[0])  # stable: keeps per-flow order for equal timestamps
    return events


def write_pcap(path, events):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f, linktype=dpkt.pcap.DLT_EN10MB)
        for ts_us, frame in events:
            sec, usec = divmod(int(BASE_TS * 1_000_000) + ts_us, 1_000_000)
            w.writepkt(frame, ts=sec + usec / 1e6)


def write_expected(path, rows):
    fields = ["_scenario"] + FIELDNAMES
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def expected_for_n(n, n_max, flows=None):
    """
    Expected rows when the PCAP built for n_max is processed with --n-packets n.

    Flows built for n_max have >= n packets where they had n_max, so the first n
    of each segment form the row. Segment boundaries come from the n_max layout.
    The incomplete flow has n_max-1 packets, which is >= n when n < n_max, so it
    does produce a row at smaller n.
    """
    rows = []
    for sc in select(scenarios(n_max), flows):
        pkt_ts = [to_usec(t) for (t, _, _) in sc["packets"]]

        segs = sc["segments"]
        if sc["name"] == "udp_incomplete":
            segs = [list(range(n_max - 1))]
        for seg in segs:
            if len(seg) < n:
                continue
            idx = seg[:n]
            row = expected_row(sc, pkt_ts, idx)
            row["_scenario"] = sc["name"]
            row["_emit_us"] = pkt_ts[idx[-1]]
            rows.append(row)
    rows.sort(key=lambda r: r["_emit_us"])
    return rows


# --------------------------------------------------------------------------
# Comparison (usable for the offline CSV or an online-extracted CSV).
# --------------------------------------------------------------------------

def compare(expected_csv, actual_csv, rel_tol=1e-6, abs_tol=1e-6):
    """Match rows by 5-tuple + occurrence and compare every feature column."""
    import math

    def load(p):
        with open(p) as f:
            return list(csv.DictReader(f))

    exp, act = load(expected_csv), load(actual_csv)
    key_cols = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]

    def keyed(rows):
        out, seen = {}, {}
        for r in rows:
            k = tuple(r[c] for c in key_cols)
            seen[k] = seen.get(k, 0) + 1
            out[k + (seen[k],)] = r
        return out

    e, a = keyed(exp), keyed(act)
    ok = True
    for k in sorted(set(e) | set(a)):
        if k not in a:
            print(f"  MISSING in actual: {k}  ({e[k].get('_scenario')})"); ok = False; continue
        if k not in e:
            print(f"  UNEXPECTED row in actual: {k}"); ok = False; continue
        for col in FIELDNAMES:
            if col in key_cols or col == "label":
                continue
            ev, av = e[k][col], a[k][col]
            try:
                same = math.isclose(float(ev), float(av), rel_tol=rel_tol, abs_tol=abs_tol)
            except ValueError:
                same = ev == av
            if not same:
                print(f"  MISMATCH {k} {col}: expected={ev} actual={av}"); ok = False
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "test_data"))
    ap.add_argument("--n-values", type=int, nargs="+", default=[3, 4, 5])
    ap.add_argument("--check", action="store_true",
                    help="Run the offline streaming extractor on the PCAP and compare to expected.")
    ap.add_argument("--packets-per-flow", type=int,
                    help="Packets per flow in the PCAP (default: largest N). Must be >= every N.")
    ap.add_argument("--flows", nargs="+", metavar="NAME",
                    help="Only include these scenarios (default: all). Names: "
                         + ", ".join(sc["name"] for sc in scenarios(3)))
    args = ap.parse_args()

    if args.flows:
        unknown = set(args.flows) - {sc["name"] for sc in scenarios(3)}
        if unknown:
            raise SystemExit(f"unknown flow(s): {', '.join(sorted(unknown))}")

    if min(args.n_values) < 2:
        raise SystemExit("--n-values must be >= 2")

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # The PCAP is built for the largest N so one file serves every N
    # (flows just have extra packets for smaller N).
    n_max = args.packets_per_flow or max(args.n_values)
    if n_max < max(args.n_values):
        raise SystemExit("--packets-per-flow must be >= every --n-values entry")
    events = build(n_max, args.flows)
    pcap_path = out / "test_flows.pcap"
    write_pcap(pcap_path, events)
    print(f"Wrote {pcap_path} ({len(events)} packets)")

    all_ok = True
    for n in args.n_values:
        rows = expected_for_n(n, n_max, args.flows)
        exp_path = out / f"expected_features_n{n}.csv"
        write_expected(exp_path, rows)
        print(f"Wrote {exp_path} ({len(rows)} rows)")

        if args.check:
            import extract_first_n_flow_features_streaming as ex
            act_path = out / f"offline_features_n{n}.csv"
            ex.process_pcap(pcap_path=str(pcap_path), output_file=str(act_path), n_packets=n,
                            label=LABEL, bidirectional=False, flow_timeout=120.0,
                            progress_interval=0, cleanup_interval=100000, flush_interval=0,
                            write_incomplete_at_end=False)
            ok = compare(exp_path, act_path)
            print(f"n={n}: {'PASS' if ok else 'FAIL'}")
            all_ok &= ok

    if args.check and not all_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
