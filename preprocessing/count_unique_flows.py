#!/usr/bin/env python3
# usage: python3 count_unique_flows.py --dataset-path "/home/ubuntu/datasets/DDoS-AT-2022" --output-file "count_unique_flows-DDoS-AT-2022.csv"

import argparse
import csv
from pathlib import Path

from scapy.config import conf

# Prevent Scapy from loading unnecessary layers like Kerberos/TLS/SMB
conf.load_layers = []

from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


def packet_to_flow(pkt):
    """
    Flow definition:
    src_ip, dst_ip, protocol, src_port, dst_port
    """

    src_port = ""
    dst_port = ""

    if IP in pkt:
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.proto

    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.nh

    else:
        return None

    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        proto = "TCP"

    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        proto = "UDP"

    return src_ip, dst_ip, proto, src_port, dst_port


def count_unique_flows(pcap_path):
    flows = set()
    total_packets = 0
    ip_packets = 0

    try:
        with PcapReader(str(pcap_path)) as packets:
            for pkt in packets:
                total_packets += 1

                if total_packets % 100000 == 0:
                    print(f"  processed {total_packets:,} packets...", flush=True)

                flow = packet_to_flow(pkt)

                if flow is not None:
                    ip_packets += 1
                    flows.add(flow)

        return len(flows), total_packets, ip_packets, ""

    except Exception as e:
        return None, total_packets, ip_packets, str(e)


def main():
    parser = argparse.ArgumentParser(
        description="Count unique flows in every PCAP file under a dataset directory."
    )

    parser.add_argument(
        "--dataset-path",
        required=True,
        help="Path to the root dataset directory, for example: /home/user/DDoS-AT-2022",
    )

    parser.add_argument(
        "--output-file",
        required=True,
        help="Path/name of the output CSV file, for example: flow_counts.csv",
    )

    args = parser.parse_args()

    dataset_path = Path(args.dataset_path).expanduser().resolve()
    output_file = Path(args.output_file).expanduser().resolve()

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset path does not exist: {dataset_path}")

    if not dataset_path.is_dir():
        raise NotADirectoryError(f"Dataset path is not a directory: {dataset_path}")

    pcap_files = sorted(dataset_path.rglob("*.pcap"))
    print(f"Found {len(pcap_files)} PCAP files under {dataset_path}", flush=True)

    with output_file.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "pcap_file",
                "relative_path",
                "unique_flows",
                "total_packets",
                "ip_packets",
                "error",
            ],
        )

        writer.writeheader()

        for i, pcap_path in enumerate(pcap_files, start=1):
            print(f"[{i}/{len(pcap_files)}] Processing: {pcap_path}", flush=True)

            unique_flows, total_packets, ip_packets, error = count_unique_flows(pcap_path)

            writer.writerow(
                {
                    "pcap_file": pcap_path.name,
                    "relative_path": str(pcap_path.relative_to(dataset_path)),
                    "unique_flows": unique_flows,
                    "total_packets": total_packets,
                    "ip_packets": ip_packets,
                    "error": error,
                }
            )

            if error:
                print(f"[ERROR] {pcap_path}: {error}")
            else:
                print(f"[OK] {pcap_path.name}: {unique_flows} unique flows")

    print(f"\nCSV written to: {output_file}")


if __name__ == "__main__":
    main()