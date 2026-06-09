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
        proto_name = "TCP"
        tcp_flags = transport.flags

    elif isinstance(ip.data, dpkt.udp.UDP):
        transport = ip.data
        src_port = transport.sport
        dst_port = transport.dport
        proto_name = "UDP"

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


def extract_features(flow_key, packets, label):
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


def process_pcap(pcap_path, output_file, n_packets, label, bidirectional):
    flows = {}

    if bidirectional:
        key_function = bidirectional_flow_key
    else:
        key_function = directional_flow_key

    print(f"Reading PCAP: {pcap_path}", flush=True)
    print(f"Using first {n_packets} packets per flow", flush=True)

    f, reader = open_pcap_reader(pcap_path)

    packet_index = 0

    try:
        for ts, buf in reader:
            packet_index += 1

            if packet_index % 100000 == 0:
                print(f"Processed {packet_index:,} packets...", flush=True)

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

    print(f"Finished reading packets.", flush=True)
    print(f"Number of flows found: {len(flows)}", flush=True)

    fieldnames = [
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

    output_file = Path(output_file)

    with output_file.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for flow_key, packets in flows.items():
            row = extract_features(flow_key, packets, label)
            writer.writerow(row)

    print(f"Feature CSV written to: {output_file}", flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="Extract first-N-packet flow features from a PCAP file."
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
        help="Optional class label, for example DDoS or Benign.",
    )

    parser.add_argument(
        "--bidirectional",
        action="store_true",
        help="Treat A->B and B->A as the same flow.",
    )

    args = parser.parse_args()

    if args.n_packets <= 0:
        raise ValueError("--n-packets must be greater than 0")

    process_pcap(
        pcap_path=args.pcap_file,
        output_file=args.output_file,
        n_packets=args.n_packets,
        label=args.label,
        bidirectional=args.bidirectional,
    )


if __name__ == "__main__":
    main()