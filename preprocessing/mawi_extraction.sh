#!/bin/bash

# chmod +x mawi_extraction.sh
# nohup ./mawi_extraction.sh > mawi_extraction.log 2>&1 &

PCAP="/home/ubuntu/datasets/mawi_ditl2026/202604080000.pcap"
OUT_DIR="/home/ubuntu/DDoS_ML/preprocessing/features_out"

for n in 3 4 5; do
  echo "=== Starting n=$n at $(date) ==="
  python3 extract_first_n_flow_features_streaming.py \
    --pcap-file "$PCAP" \
    --output-file "$OUT_DIR/benign_features_n${n}.csv" \
    --n-packets "$n" \
    --label "Benign"
  echo "=== Finished n=$n at $(date), exit code $? ==="
done