#!/usr/bin/env python3
"""
Build attack-only PCAPs from CICDDoS2019 for replay into the P4 pipeline.

For each input PCAP, this writes:
    <stem>_attack.pcap         packets of the flows labelled as an attack
    <stem>_ground_truth.csv    one row per kept flow (5-tuple, label, start time)

Flows are split and labelled exactly like extract_first_n_flow_features_streaming_labeled.py
(directional 5-tuple, flow timeout, cleanup interval, labeler.lookup on the first
packet's timestamp). A flow is kept when it reaches N packets (so it is a
training row) and its label is not in exclude_labels (BENIGN, unknown).
Kept flows keep all their packets and original timestamps, so the offline
extractor on the output PCAP gives the same rows as the training CSV.

The PCAP is read twice: pass 1 labels the flows, pass 2 writes the packets of
the kept flows in their original order (tcpreplay needs time-ordered packets).

From the notebook, reusing the cached labeler:
    import make_attack_replay_pcap as replay
    replay.build_replay_pcap(pcap_file, REPLAY_DIR, labeler, n_packets=N_PACKETS)
    replay.build_replay_batch(pcap_files, REPLAY_DIR, labeler, n_packets=N_PACKETS)

Standalone (loads the label CSVs itself, which is slow):
    python3 make_attack_replay_pcap.py --pcap-file F.pcap --label-csv-dir DIR --out-dir replay
"""

import argparse
import csv
from pathlib import Path

import dpkt

import extract_first_n_flow_features_streaming_labeled as extractor

DEFAULT_EXCLUDE_LABELS = ("BENIGN", "unknown")

GROUND_TRUTH_FIELDS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "flow_start_us", "label", "label_source", "csv_match_time_diff", "packets_written",
]


def _flow_instances(pcap_path, n_packets, flow_timeout, cleanup_interval):
    """
    Yield (ts, buf, event, flow_id, flow_key, first_ts) for every packet of the PCAP.

    Same state machine as process_pcap in the labeled extractor. flow_id numbers
    each flow instance in order of creation, so both passes get the same ids.
    event is:
        None        not an IP packet, or its flow never reaches N packets (yet)
        "pending"   one of the first N packets of an incomplete flow
        "complete"  the Nth packet: the flow becomes a training row
        "tail"      a later packet of a completed flow (within the timeout)
    """
    flows = {}            # key -> {"id", "first_ts", "count", "last_seen"}
    completed = {}        # key -> [last_seen, id]
    next_id = 0
    packet_index = 0

    f, reader = extractor.open_pcap_reader(pcap_path)
    try:
        for ts, buf in reader:
            packet_index += 1

            if cleanup_interval > 0 and packet_index % cleanup_interval == 0:
                for key in [k for k, fl in flows.items() if ts - fl["last_seen"] > flow_timeout]:
                    del flows[key]
                for key in [k for k, (last, _) in completed.items() if ts - last > flow_timeout]:
                    del completed[key]

            pkt = extractor.get_packet_info(ts, buf)
            if pkt is None:
                yield ts, buf, None, None, None, None
                continue

            key = extractor.directional_flow_key(pkt)

            done = completed.get(key)
            if done is not None:
                if ts - done[0] <= flow_timeout:
                    done[0] = ts
                    yield ts, buf, "tail", done[1], key, None
                    continue
                del completed[key]

            flow = flows.get(key)
            if flow is None:
                flow = {"id": next_id, "first_ts": ts, "count": 0, "last_seen": ts}
                flows[key] = flow
                next_id += 1

            flow["count"] += 1
            flow["last_seen"] = ts

            if flow["count"] >= n_packets:
                del flows[key]
                completed[key] = [ts, flow["id"]]
                yield ts, buf, "complete", flow["id"], key, flow["first_ts"]
            else:
                yield ts, buf, "pending", flow["id"], key, flow["first_ts"]
    finally:
        f.close()


def _writer_for(pcap_path, out_file):
    """dpkt PCAP writer with the same link type, snaplen and time resolution as the input."""
    f, reader = extractor.open_pcap_reader(pcap_path)
    try:
        if isinstance(reader, dpkt.pcap.Reader):
            kwargs = {
                "snaplen": reader.snaplen,
                "linktype": reader.datalink(),
                "nano": getattr(reader, "_divisor", 1e6) == 1e9,
            }
        else:
            kwargs = {"snaplen": 262144, "linktype": dpkt.pcap.DLT_EN10MB}
    finally:
        f.close()
    out = open(out_file, "wb")
    return out, dpkt.pcap.Writer(out, **kwargs)


def build_replay_pcap(
    pcap_path,
    out_dir,
    labeler,
    n_packets=5,
    flow_timeout=120.0,
    cleanup_interval=100_000,
    exclude_labels=DEFAULT_EXCLUDE_LABELS,
    first_n_only=False,
):
    """
    Write <stem>_attack.pcap and <stem>_ground_truth.csv for one PCAP.

    Use the same n_packets, flow_timeout and cleanup_interval as the feature
    extraction, so the flows match the training rows. first_n_only=True writes
    only the first N packets of each flow (smaller files, lower replay rate);
    the P4 program ignores later packets for the features anyway.
    """
    pcap_path = Path(pcap_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_pcap = out_dir / f"{pcap_path.stem}_attack.pcap"
    out_csv = out_dir / f"{pcap_path.stem}_ground_truth.csv"
    excluded = {label.lower() for label in exclude_labels}

    # Pass 1: label every flow that reaches N packets.
    kept = {}                 # flow_id -> ground-truth row
    label_counts = {}
    for ts, buf, event, flow_id, key, first_ts in _flow_instances(
            pcap_path, n_packets, flow_timeout, cleanup_interval):
        if event != "complete":
            continue
        label, label_source, diff = labeler.lookup(key, first_ts)
        label_counts[label] = label_counts.get(label, 0) + 1
        if label.strip().lower() in excluded:
            continue
        src_ip, dst_ip, src_port, dst_port, protocol = key
        kept[flow_id] = {
            "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
            "protocol": extractor.PROTO_NUM_TO_NAME.get(protocol, protocol),
            "flow_start_us": extractor.to_usec(first_ts),
            "label": label, "label_source": label_source, "csv_match_time_diff": diff,
            "packets_written": 0,
        }

    # Pass 2: write the packets of the kept flows, in the original order.
    packets_read = packets_written = 0
    out, writer = _writer_for(pcap_path, out_pcap)
    try:
        for ts, buf, event, flow_id, key, first_ts in _flow_instances(
                pcap_path, n_packets, flow_timeout, cleanup_interval):
            packets_read += 1
            if flow_id not in kept:
                continue
            if event == "tail" and first_n_only:
                continue
            writer.writepkt(buf, ts=ts)
            kept[flow_id]["packets_written"] += 1
            packets_written += 1
    finally:
        out.close()

    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=GROUND_TRUTH_FIELDS)
        w.writeheader()
        w.writerows(kept.values())

    kept_labels = {}
    for row in kept.values():
        kept_labels[row["label"]] = kept_labels.get(row["label"], 0) + 1

    print(f"{pcap_path.name}: {packets_read:,} packets read, {packets_written:,} written "
          f"({packets_written / packets_read:.1%})" if packets_read else f"{pcap_path.name}: empty")
    print(f"  flows with >= {n_packets} packets: {sum(label_counts.values()):,} {label_counts}")
    print(f"  flows kept: {len(kept):,} {kept_labels}")
    print(f"  -> {out_pcap}")
    print(f"  -> {out_csv}")

    return {
        "pcap_file": str(pcap_path), "replay_pcap": str(out_pcap), "ground_truth": str(out_csv),
        "packets_read": packets_read, "packets_written": packets_written, "flows_kept": len(kept),
    }


def build_replay_batch(pcap_files, out_dir, labeler, skip_existing=True, **kwargs):
    """build_replay_pcap for each PCAP. Returns a list of result dicts (one per file)."""
    results = []
    total = len(pcap_files)
    for i, pcap_file in enumerate(pcap_files, start=1):
        pcap_file = Path(pcap_file)
        out_csv = Path(out_dir) / f"{pcap_file.stem}_ground_truth.csv"
        print("=" * 80)
        print(f"[{i}/{total}] {pcap_file.name}")
        # The ground-truth CSV is written last, so it marks a finished file.
        if skip_existing and out_csv.exists():
            print("Skipping because output already exists.")
            results.append({"pcap_file": str(pcap_file), "status": "skipped_existing"})
            continue
        try:
            results.append({**build_replay_pcap(pcap_file, out_dir, labeler, **kwargs), "status": "done"})
        except Exception as e:
            print("FAILED:", e)
            results.append({"pcap_file": str(pcap_file), "status": "failed", "error": str(e)})
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap-file", required=True, nargs="+")
    ap.add_argument("--label-csv-dir", required=True)
    ap.add_argument("--out-dir", default="replay")
    ap.add_argument("--n-packets", type=int, default=5)
    ap.add_argument("--flow-timeout", type=float, default=120.0)
    ap.add_argument("--cleanup-interval", type=int, default=100_000)
    ap.add_argument("--csv-time-tolerance", type=float, default=30.0)
    ap.add_argument("--csv-time-offset", type=float, default=10800.0)
    ap.add_argument("--exclude-labels", nargs="+", default=list(DEFAULT_EXCLUDE_LABELS))
    ap.add_argument("--first-n-only", action="store_true", help="Write only the first N packets of each flow")
    args = ap.parse_args()

    # Same labeler settings as the notebook.
    labeler = extractor.CsvFlowLabeler(
        csv_dir=Path(args.label_csv_dir),
        tolerance_seconds=args.csv_time_tolerance,
        csv_time_offset_seconds=args.csv_time_offset,
        allow_reverse=True,
    )
    labeler.load()

    build_replay_batch(
        args.pcap_file, args.out_dir, labeler, skip_existing=False,
        n_packets=args.n_packets, flow_timeout=args.flow_timeout,
        cleanup_interval=args.cleanup_interval, exclude_labels=args.exclude_labels,
        first_n_only=args.first_n_only,
    )


if __name__ == "__main__":
    main()
