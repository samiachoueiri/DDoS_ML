#!/usr/bin/env python3

import argparse
import bisect
import csv
import socket
import statistics
from datetime import datetime
from pathlib import Path

import dpkt


FIELDNAMES = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "flow_start_time",
    "flow_end_time",
    "packet_count",
    "duration",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "packet_length_min",
    "packet_length_max",
    "packet_length_mean",
    "packet_length_std",
    "iat_min",
    "iat_max",
    "iat_mean",
    "iat_std",
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_fin_count",
    "tcp_rst_count",
    "tcp_psh_count",
    "tcp_urg_count",
    "label",
    "label_source",
    "csv_match_time_diff",
]

PROTO_NAME_TO_NUM = {
    "TCP": "6",
    "UDP": "17",
}

PROTO_NUM_TO_NAME = {
    "6": "TCP",
    "17": "UDP",
}


def normalize_column_name(name):
    return " ".join(name.strip().lower().replace("_", " ").split())


def get_value(row, normalized_columns, candidates, default=""):
    for candidate in candidates:
        key = normalize_column_name(candidate)
        original_name = normalized_columns.get(key)
        if original_name is not None:
            return row.get(original_name, default)
    return default


def parse_timestamp(value):
    """
    Parse common CICFlowMeter timestamp formats.

    Returns epoch seconds as float, or None if parsing fails.
    """
    if value is None:
        return None

    value = str(value).strip()
    if not value:
        return None

    # Numeric epoch timestamps, if present.
    try:
        return float(value)
    except ValueError:
        pass

    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %I:%M:%S.%f %p",
        "%d/%m/%Y %I:%M:%S %p",
        "%m/%d/%Y %I:%M:%S.%f %p",
        "%m/%d/%Y %I:%M:%S %p",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).timestamp()
        except ValueError:
            continue

    return None


class CsvFlowLabeler:
    """
    Loads official CICFlowMeter CSV labels and matches extracted flows by:
      src_ip, dst_ip, src_port, dst_port, protocol, nearest timestamp.

    Flow ID alone is intentionally not used because duplicate Flow IDs are normal.
    """

    def __init__(self, csv_dir, tolerance_seconds=1.0, csv_time_offset_seconds=0.0, allow_reverse=True):
        self.csv_dir = Path(csv_dir)
        self.tolerance_seconds = float(tolerance_seconds)
        self.csv_time_offset_seconds = float(csv_time_offset_seconds)
        self.allow_reverse = allow_reverse
        self.index = {}
        self.rows_loaded = 0
        self.rows_skipped = 0
        self.files_loaded = 0

    @staticmethod
    def make_key(src_ip, dst_ip, src_port, dst_port, protocol):
        protocol = str(protocol).strip().upper()
        protocol = PROTO_NAME_TO_NUM.get(protocol, protocol)
        return (
            str(src_ip).strip(),
            str(dst_ip).strip(),
            int(src_port),
            int(dst_port),
            str(protocol).strip(),
        )

    @staticmethod
    def reverse_key(key):
        src_ip, dst_ip, src_port, dst_port, protocol = key
        return (dst_ip, src_ip, dst_port, src_port, protocol)

    def load(self):
        csv_files = sorted(self.csv_dir.rglob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found under: {self.csv_dir}")

        print(f"Loading label CSV files from: {self.csv_dir}", flush=True)

        for csv_file in csv_files:
            self._load_one_csv(csv_file)
            self.files_loaded += 1
            print(
                f"Loaded labels from {csv_file} "
                f"total_rows_loaded={self.rows_loaded:,} skipped={self.rows_skipped:,}",
                flush=True,
            )

        for values in self.index.values():
            values.sort(key=lambda item: item[0])

        print(
            "Finished loading label index: "
            f"files={self.files_loaded:,}, rows_loaded={self.rows_loaded:,}, "
            f"rows_skipped={self.rows_skipped:,}, unique_5tuples={len(self.index):,}",
            flush=True,
        )

    def _load_one_csv(self, csv_file):
        with csv_file.open("r", newline="", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return

            normalized_columns = {
                normalize_column_name(name): name for name in reader.fieldnames
            }

            for row in reader:
                try:
                    src_ip = get_value(row, normalized_columns, ["Source IP", "Src IP", "src_ip"])
                    dst_ip = get_value(row, normalized_columns, ["Destination IP", "Dst IP", "dst_ip"])
                    src_port = get_value(row, normalized_columns, ["Source Port", "Src Port", "src_port"])
                    dst_port = get_value(row, normalized_columns, ["Destination Port", "Dst Port", "dst_port"])
                    protocol = get_value(row, normalized_columns, ["Protocol", "protocol"])
                    timestamp_raw = get_value(row, normalized_columns, ["Timestamp", "timestamp"])
                    label = get_value(row, normalized_columns, ["Label", "label"], default="unknown")

                    if not src_ip or not dst_ip or not src_port or not dst_port or not protocol:
                        self.rows_skipped += 1
                        continue

                    timestamp = parse_timestamp(timestamp_raw)
                    if timestamp is None:
                        self.rows_skipped += 1
                        continue
                    timestamp += self.csv_time_offset_seconds

                    key = self.make_key(src_ip, dst_ip, src_port, dst_port, protocol)
                    self.index.setdefault(key, []).append((timestamp, str(label).strip(), str(csv_file)))
                    self.rows_loaded += 1

                except Exception:
                    self.rows_skipped += 1

    def lookup(self, flow_key, flow_start_ts):
        src_ip, dst_ip, src_port, dst_port, protocol = flow_key
        protocol_num = PROTO_NAME_TO_NUM.get(str(protocol).upper(), str(protocol))
        key = self.make_key(src_ip, dst_ip, src_port, dst_port, protocol_num)

        best = self._lookup_key(key, flow_start_ts)

        if best is None and self.allow_reverse:
            best = self._lookup_key(self.reverse_key(key), flow_start_ts)

        if best is None:
            return "unknown", "csv_no_match", ""

        label, diff, csv_file = best
        return label, f"csv:{Path(csv_file).name}", diff

    def _lookup_key(self, key, flow_start_ts):
        values = self.index.get(key)
        if not values:
            return None

        timestamps = [item[0] for item in values]
        pos = bisect.bisect_left(timestamps, flow_start_ts)

        candidates = []
        if pos < len(values):
            candidates.append(values[pos])
        if pos > 0:
            candidates.append(values[pos - 1])

        if not candidates:
            return None

        closest = min(candidates, key=lambda item: abs(item[0] - flow_start_ts))
        diff = abs(closest[0] - flow_start_ts)

        if diff <= self.tolerance_seconds:
            return closest[1], diff, closest[2]

        return None
    
    def lookup_by_5tuple_only(self, flow_key):
        records = self.index.get(flow_key)

        if not records and self.allow_reverse:
            src_ip, dst_ip, src_port, dst_port, protocol = flow_key
            reverse_key = (dst_ip, src_ip, dst_port, src_port, protocol)
            records = self.index.get(reverse_key)

        if not records:
            return "unknown", "csv_5tuple_no_match", ""

        # records are stored as:
        # (timestamp, label, csv_path)
        last_record = records[-1]

        timestamp = last_record[0]
        label = last_record[1]
        csv_path = last_record[2]

        return str(label), f"csv_5tuple_last_match:{csv_path}", str(timestamp)


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def get_packet_info(ts, buf):
    """
    Extract basic packet info from an Ethernet frame.

    Returns:
        dict or None
    """

    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None

    ip = eth.data

    if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return None

    src_ip = inet_to_str(ip.src)
    dst_ip = inet_to_str(ip.dst)
    proto = ip.p

    src_port = 0
    dst_port = 0
    tcp_flags = 0

    if isinstance(ip.data, dpkt.tcp.TCP):
        transport = ip.data
        src_port = transport.sport
        dst_port = transport.dport
        proto_name = "6"
        tcp_flags = transport.flags

    elif isinstance(ip.data, dpkt.udp.UDP):
        transport = ip.data
        src_port = transport.sport
        dst_port = transport.dport
        proto_name = "17"

    else:
        proto_name = str(proto)

    pkt_len = len(buf)

    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto_name,
        "packet_length": pkt_len,
        "tcp_flags": tcp_flags,
    }


def directional_flow_key(pkt):
    """
    Directional 5-tuple flow:
    src_ip, dst_ip, src_port, dst_port, protocol

    A -> B and B -> A are treated as different flows.
    """

    return (
        pkt["src_ip"],
        pkt["dst_ip"],
        pkt["src_port"],
        pkt["dst_port"],
        pkt["protocol"],
    )


def bidirectional_flow_key(pkt):
    """
    Bidirectional 5-tuple flow:
    A <-> B is treated as one flow.
    """

    endpoint1 = (pkt["src_ip"], pkt["src_port"])
    endpoint2 = (pkt["dst_ip"], pkt["dst_port"])

    if endpoint1 <= endpoint2:
        return (
            pkt["src_ip"],
            pkt["dst_ip"],
            pkt["src_port"],
            pkt["dst_port"],
            pkt["protocol"],
        )
    else:
        return (
            pkt["dst_ip"],
            pkt["src_ip"],
            pkt["dst_port"],
            pkt["src_port"],
            pkt["protocol"],
        )


def safe_mean(values):
    return statistics.mean(values) if values else 0


def safe_stdev(values):
    return statistics.stdev(values) if len(values) > 1 else 0


def safe_min(values):
    return min(values) if values else 0


def safe_max(values):
    return max(values) if values else 0


def extract_features(flow_key, packets, label, label_source="manual", csv_match_time_diff=""):
    """
    Extract flow features from the stored first N packets.
    """

    src_ip, dst_ip, src_port, dst_port, protocol = flow_key

    timestamps = [p["timestamp"] for p in packets]
    lengths = [p["packet_length"] for p in packets]

    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0

    inter_arrival_times = []
    for i in range(1, len(timestamps)):
        inter_arrival_times.append(timestamps[i] - timestamps[i - 1])

    total_bytes = sum(lengths)
    packet_count = len(packets)

    packets_per_second = packet_count / duration if duration > 0 else 0
    bytes_per_second = total_bytes / duration if duration > 0 else 0

    tcp_syn_count = 0
    tcp_ack_count = 0
    tcp_fin_count = 0
    tcp_rst_count = 0
    tcp_psh_count = 0
    tcp_urg_count = 0

    for p in packets:
        flags = p["tcp_flags"]

        if flags:
            if flags & dpkt.tcp.TH_SYN:
                tcp_syn_count += 1
            if flags & dpkt.tcp.TH_ACK:
                tcp_ack_count += 1
            if flags & dpkt.tcp.TH_FIN:
                tcp_fin_count += 1
            if flags & dpkt.tcp.TH_RST:
                tcp_rst_count += 1
            if flags & dpkt.tcp.TH_PUSH:
                tcp_psh_count += 1
            if flags & dpkt.tcp.TH_URG:
                tcp_urg_count += 1

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "flow_start_time": datetime.fromtimestamp(timestamps[0]).strftime("%Y-%m-%d %H:%M:%S.%f"),
        "flow_end_time": datetime.fromtimestamp(timestamps[-1]).strftime("%Y-%m-%d %H:%M:%S.%f"),
        "packet_count": packet_count,
        "duration": duration,
        "total_bytes": total_bytes,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "packet_length_min": safe_min(lengths),
        "packet_length_max": safe_max(lengths),
        "packet_length_mean": safe_mean(lengths),
        "packet_length_std": safe_stdev(lengths),
        "iat_min": safe_min(inter_arrival_times),
        "iat_max": safe_max(inter_arrival_times),
        "iat_mean": safe_mean(inter_arrival_times),
        "iat_std": safe_stdev(inter_arrival_times),
        "tcp_syn_count": tcp_syn_count,
        "tcp_ack_count": tcp_ack_count,
        "tcp_fin_count": tcp_fin_count,
        "tcp_rst_count": tcp_rst_count,
        "tcp_psh_count": tcp_psh_count,
        "tcp_urg_count": tcp_urg_count,
        "label": label,
        "label_source": label_source,
        "csv_match_time_diff": csv_match_time_diff,
    }


def open_pcap_reader(pcap_path):
    """
    Supports normal .pcap and .pcapng files.
    """

    f = open(pcap_path, "rb")

    try:
        return f, dpkt.pcap.Reader(f)
    except ValueError:
        f.seek(0)
        return f, dpkt.pcapng.Reader(f)


def cleanup_old_flows(flows, completed_flows, current_ts, flow_timeout):
    """
    Remove stale incomplete flows and old completed-flow cache entries.

    completed_flows is used to avoid writing the same active flow more than once.
    It is also expired after flow_timeout, so a later packet with the same 5-tuple
    after a long idle gap can start a new flow.
    """

    expired_incomplete = [
        key for key, flow in flows.items()
        if current_ts - flow["last_seen"] > flow_timeout
    ]
    for key in expired_incomplete:
        del flows[key]

    expired_completed = [
        key for key, last_seen in completed_flows.items()
        if current_ts - last_seen > flow_timeout
    ]
    for key in expired_completed:
        del completed_flows[key]

    return len(expired_incomplete), len(expired_completed)


def resolve_label(flow_key, packets, labeler, fallback_label):
    if labeler is None:
        return fallback_label, "manual", ""
    return labeler.lookup(flow_key, packets[0]["timestamp"])


def process_pcap(
    pcap_path,
    output_file,
    n_packets,
    label,
    bidirectional,
    flow_timeout,
    progress_interval,
    cleanup_interval,
    flush_interval,
    write_incomplete_at_end,
    labeler,
):
    flows = {}
    completed_flows = {}

    if bidirectional:
        key_function = bidirectional_flow_key
    else:
        key_function = directional_flow_key

    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"Reading PCAP: {pcap_path}", flush=True)
    print(f"Writing CSV while reading: {output_file}", flush=True)
    print(f"Using first {n_packets} packets per flow", flush=True)
    print(f"Flow timeout: {flow_timeout} seconds", flush=True)

    f, reader = open_pcap_reader(pcap_path)

    packet_index = 0
    ip_packet_count = 0
    written_rows = 0
    expired_incomplete_total = 0
    expired_completed_total = 0
    skipped_completed_packets = 0
    current_ts = None
    label_counts = {}

    try:
        with output_file.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES)
            writer.writeheader()

            for ts, buf in reader:
                packet_index += 1
                current_ts = ts

                if progress_interval > 0 and packet_index % progress_interval == 0:
                    print(
                        "Processed "
                        f"{packet_index:,} packets... "
                        f"active_incomplete_flows={len(flows):,}, "
                        f"completed_cache={len(completed_flows):,}, "
                        f"rows_written={written_rows:,}",
                        flush=True,
                    )

                if cleanup_interval > 0 and packet_index % cleanup_interval == 0:
                    expired_incomplete, expired_completed = cleanup_old_flows(
                        flows=flows,
                        completed_flows=completed_flows,
                        current_ts=ts,
                        flow_timeout=flow_timeout,
                    )
                    expired_incomplete_total += expired_incomplete
                    expired_completed_total += expired_completed

                pkt = get_packet_info(ts, buf)

                if pkt is None:
                    continue

                ip_packet_count += 1
                flow_key = key_function(pkt)

                if flow_key in completed_flows:
                    if ts - completed_flows[flow_key] <= flow_timeout:
                        completed_flows[flow_key] = ts
                        skipped_completed_packets += 1
                        continue
                    else:
                        del completed_flows[flow_key]

                flow = flows.get(flow_key)
                if flow is None:
                    flow = {"packets": [], "last_seen": ts}
                    flows[flow_key] = flow

                flow["packets"].append(pkt)
                flow["last_seen"] = ts

                if len(flow["packets"]) >= n_packets:
                    row_label, label_source, csv_match_time_diff = resolve_label(flow_key, flow["packets"], labeler, label)
                    # row_label, label_source, csv_match_time_diff = labeler.lookup_by_5tuple_only(flow_key)
                    row = extract_features(
                        flow_key,
                        flow["packets"],
                        row_label,
                        label_source=label_source,
                        csv_match_time_diff=csv_match_time_diff,
                    )
                    writer.writerow(row)
                    written_rows += 1
                    label_counts[row_label] = label_counts.get(row_label, 0) + 1

                    del flows[flow_key]
                    completed_flows[flow_key] = ts

                if flush_interval > 0 and packet_index % flush_interval == 0:
                    csvfile.flush()

            if write_incomplete_at_end:
                for flow_key, flow in flows.items():
                    row_label, label_source, csv_match_time_diff = resolve_label(
                        flow_key, flow["packets"], labeler, label
                    )
                    row = extract_features(
                        flow_key,
                        flow["packets"],
                        row_label,
                        label_source=label_source,
                        csv_match_time_diff=csv_match_time_diff,
                    )
                    writer.writerow(row)
                    written_rows += 1
                    label_counts[row_label] = label_counts.get(row_label, 0) + 1
                flows.clear()

            csvfile.flush()

    finally:
        f.close()

    if current_ts is not None:
        expired_incomplete, expired_completed = cleanup_old_flows(
            flows=flows,
            completed_flows=completed_flows,
            current_ts=current_ts,
            flow_timeout=flow_timeout,
        )
        expired_incomplete_total += expired_incomplete
        expired_completed_total += expired_completed

    print("Finished reading packets.", flush=True)
    print(f"Total packets read: {packet_index:,}", flush=True)
    print(f"IP packets used: {ip_packet_count:,}", flush=True)
    print(f"Rows written: {written_rows:,}", flush=True)
    print(f"Label counts: {label_counts}", flush=True)
    print(f"Incomplete flows still in memory: {len(flows):,}", flush=True)
    print(f"Completed-flow cache entries still in memory: {len(completed_flows):,}", flush=True)
    print(f"Expired incomplete flows removed: {expired_incomplete_total:,}", flush=True)
    print(f"Expired completed-flow cache entries removed: {expired_completed_total:,}", flush=True)
    print(f"Packets skipped because flow was already written: {skipped_completed_packets:,}", flush=True)
    print(f"Feature CSV written to: {output_file}", flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="Extract first-N-packet flow features from a PCAP file and optionally label flows using CICFlowMeter CSV files."
    )

    parser.add_argument(
        "--pcap-file",
        required=True,
        help="Path to the input PCAP file.",
    )

    parser.add_argument(
        "--output-file",
        required=True,
        help="Path to the output CSV file.",
    )

    parser.add_argument(
        "--n-packets",
        type=int,
        required=True,
        help="Number of first packets to use per flow.",
    )

    parser.add_argument(
        "--label",
        default="unknown",
        help="Fallback label used when --label-csv-dir is not provided or no CSV match is found.",
    )

    parser.add_argument(
        "--label-csv-dir",
        default=None,
        help="Directory containing official CICFlowMeter CSV files. The script searches recursively for *.csv.",
    )

    parser.add_argument(
        "--csv-time-tolerance",
        type=float,
        default=1.0,
        help="Maximum allowed absolute time difference in seconds when matching extracted flows to CSV rows.",
    )

    parser.add_argument(
        "--csv-time-offset",
        type=float,
        default=0.0,
        help="Seconds added to CSV timestamps before matching. Use this if PCAP and CSV timestamps are shifted by a timezone or clock offset.",
    )

    parser.add_argument(
        "--no-reverse-csv-match",
        action="store_true",
        help="Disable reverse-direction CSV matching. By default, the script tries A->B and B->A.",
    )

    parser.add_argument(
        "--bidirectional",
        action="store_true",
        help="Treat A->B and B->A as the same flow.",
    )

    parser.add_argument(
        "--flow-timeout",
        type=float,
        default=120.0,
        help="Seconds of inactivity after which an incomplete or completed flow is expired.",
    )

    parser.add_argument(
        "--progress-interval",
        type=int,
        default=100000,
        help="Print progress every this many packets. Use 0 to disable.",
    )

    parser.add_argument(
        "--cleanup-interval",
        type=int,
        default=100000,
        help="Remove stale flows every this many packets. Use 0 to disable.",
    )

    parser.add_argument(
        "--flush-interval",
        type=int,
        default=100000,
        help="Flush the output CSV every this many packets. Use 0 to disable periodic flushing.",
    )

    parser.add_argument(
        "--write-incomplete-at-end",
        action="store_true",
        help="Also write flows that have fewer than --n-packets when the PCAP ends.",
    )

    args = parser.parse_args()

    if args.n_packets <= 0:
        raise ValueError("--n-packets must be greater than 0")

    if args.flow_timeout <= 0:
        raise ValueError("--flow-timeout must be greater than 0")

    if args.progress_interval < 0:
        raise ValueError("--progress-interval cannot be negative")

    if args.cleanup_interval < 0:
        raise ValueError("--cleanup-interval cannot be negative")

    if args.flush_interval < 0:
        raise ValueError("--flush-interval cannot be negative")

    if args.csv_time_tolerance < 0:
        raise ValueError("--csv-time-tolerance cannot be negative")

    labeler = None
    if args.label_csv_dir:
        labeler = CsvFlowLabeler(
            csv_dir=args.label_csv_dir,
            tolerance_seconds=args.csv_time_tolerance,
            csv_time_offset_seconds=args.csv_time_offset,
            allow_reverse=not args.no_reverse_csv_match,
        )
        labeler.load()

    process_pcap(
        pcap_path=args.pcap_file,
        output_file=args.output_file,
        n_packets=args.n_packets,
        label=args.label,
        bidirectional=args.bidirectional,
        flow_timeout=args.flow_timeout,
        progress_interval=args.progress_interval,
        cleanup_interval=args.cleanup_interval,
        flush_interval=args.flush_interval,
        write_incomplete_at_end=args.write_incomplete_at_end,
        labeler=labeler,
    )


if __name__ == "__main__":
    main()
