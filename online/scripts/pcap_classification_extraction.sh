#!/bin/bash

echo "Extracting custom headers from PCAP files..."
echo "--------------------------------------------"

for pcap in *.pcap; do
    echo "Processing file: $pcap" | tee -a results.txt

    /usr/bin/python3 - >> results.txt <<EOF
import dpkt

pcap_file = "$pcap"

with open(pcap_file, 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    for idx, (ts, buf) in enumerate(pcap):
        try:
            if len(buf) < 18:
                continue  # skip short packets

            # Extract bytes 14 to 17 (immediately after Ethernet header)
            custom = buf[14:18]
            val = int.from_bytes(custom, 'big')

            print(f"Packet #{idx+1} | Custom Header: {val} (hex: {custom.hex()})")

        except Exception as e:
            print(f"{pcap_file} | Packet #{idx+1} | Error: {e}")
EOF

    echo "--------------------------------------------"
done