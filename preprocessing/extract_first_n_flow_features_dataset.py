#!/usr/bin/env python3

import argparse
import csv
import socket
import statistics
from pathlib import Path

import dpkt


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def open_pcap_reader(pcap_path):
    f = open(pcap_path, "rb")

    try:
        return f, dpkt.pcap.Reader(f)
    except ValueError:
        f.seek(0)
        return f, dpkt.pcapng.Reader(f)


def get_packet_info(ts, buf):
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None

    ip = eth.data

    if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return None

    src_ip = inet_to_str(ip.src)
    dst_ip = inet_to_str(ip.dst)

    src_port = 0
    dst_port = 0
    tcp_flags = 0

    if isinstance(ip.data, dpkt.tcp.TCP):
        transport = ip.data
        src_port = transport.sport
        dst_port = transport.dport
        protocol = "TCP"
        tcp_flags = transport.flags

    elif isinstance(ip.data, dpkt.udp.UDP):
        transport = ip.data
        src_port = transport.sport
        dst_port = transport.dport
        protocol = "UDP"

    else:
        protocol = str(ip.p)

    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_length": len(buf),
        "tcp_flags": tcp_flags,
    }


def directional_flow_key(pkt):
    return (
        pkt["src_ip"],
        pkt["dst_ip"],
        pkt["src_port"],
        pkt["dst_port"],
        pkt["protocol"],
    )


def bidirectional_flow_key(pkt):
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


def get_traffic_type(dataset_path, pcap_path):
    """
    Uses the first directory under the dataset root as the traffic type.

    Example:
    DDoS-AT-2022/TCP-SYN-flood/TCP-SYN-flood/tcp syn flood.pcap
    traffic_type = TCP-SYN-flood
    """

    relative_parts = pcap_path.relative_to(dataset_path).parts

    if len(relative_parts) > 1:
        return relative_parts[0]

    return "unknown"


def infer_label_from_path(pcap_path):
    """
    Simple automatic label:
    - Legitimate traffic -> Benign
    - everything else -> DDoS

    You can modify this if your dataset uses different labeling.
    """

    path_text = str(pcap_path).lower()

    if "legitimate traffic" in path_text:
        return "Benign"

    return "DDoS"


def extract_features(flow_key, packets, label, pcap_path, dataset_path):
    src_ip, dst_ip, src_port, dst_port, protocol = flow_key

    timestamps = [p["timestamp"] for p in packets]
    lengths = [p["packet_length"] for p in packets]

    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0

    inter_arrival_times = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

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
        "pcap_file": pcap_path.name,
        "relative_path": str(pcap_path.relative_to(dataset_path)),
        "traffic_type": get_traffic_type(dataset_path, pcap_path),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
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
    }


def process_one_pcap(pcap_path, dataset_path, n_packets, bidirectional):
    flows = {}

    key_function = bidirectional_flow_key if bidirectional else directional_flow_key

    f, reader = open_pcap_reader(pcap_path)

    packet_index = 0

    try:
        for ts, buf in reader:
            packet_index += 1

            if packet_index % 100000 == 0:
                print(f"    processed {packet_index:,} packets...", flush=True)

            pkt = get_packet_info(ts, buf)

            if pkt is None:
                continue

            flow_key = key_function(pkt)

            if flow_key not in flows:
                flows[flow_key] = []

            if len(flows[flow_key]) < n_packets:
                flows[flow_key].append(pkt)

    finally:
        f.close()

    label = infer_label_from_path(pcap_path)

    rows = []
    for flow_key, packets in flows.items():
        rows.append(
            extract_features(
                flow_key=flow_key,
                packets=packets,
                label=label,
                pcap_path=pcap_path,
                dataset_path=dataset_path,
            )
        )

    return rows, packet_index, len(flows)


def main():
    parser = argparse.ArgumentParser(
        description="Extract first-N-packet flow features from all PCAP files under a dataset directory."
    )

    parser.add_argument(
        "--dataset-path",
        required=True,
        help="Path to dataset root directory.",
    )

    parser.add_argument(
        "--output-file",
        required=True,
        help="Path to output CSV file.",
    )

    parser.add_argument(
        "--n-packets",
        type=int,
        required=True,
        help="Number of first packets to use per flow.",
    )

    parser.add_argument(
        "--bidirectional",
        action="store_true",
        help="Treat A->B and B->A as one flow.",
    )

    args = parser.parse_args()

    if args.n_packets <= 0:
        raise ValueError("--n-packets must be greater than 0")

    dataset_path = Path(args.dataset_path).expanduser().resolve()
    output_file = Path(args.output_file).expanduser().resolve()

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset path does not exist: {dataset_path}")

    if not dataset_path.is_dir():
        raise NotADirectoryError(f"Dataset path is not a directory: {dataset_path}")

    pcap_files = sorted(dataset_path.rglob("*.pcap"))

    print(f"Found {len(pcap_files)} PCAP files under {dataset_path}", flush=True)

    fieldnames = [
        "pcap_file",
        "relative_path",
        "traffic_type",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
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
    ]

    with output_file.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        csvfile.flush()

        for i, pcap_path in enumerate(pcap_files, start=1):
            print()
            print(f"[{i}/{len(pcap_files)}] Processing: {pcap_path}", flush=True)

            try:
                rows, total_packets, flow_count = process_one_pcap(
                    pcap_path=pcap_path,
                    dataset_path=dataset_path,
                    n_packets=args.n_packets,
                    bidirectional=args.bidirectional,
                )

                for row in rows:
                    writer.writerow(row)

                csvfile.flush()

                print(
                    f"    done: {total_packets:,} packets, {flow_count:,} flows",
                    flush=True,
                )

            except Exception as e:
                print(f"    ERROR processing {pcap_path}: {e}", flush=True)

    print()
    print(f"Done. Feature CSV written to: {output_file}", flush=True)


if __name__ == "__main__":
    main()