# Preprocessing Scripts

All scripts are run from this directory (`DDoS_ML/preprocessing/`). Output CSVs go to `features_out/`.

---

## count_unique_flows.py

Walks a dataset directory, opens every `.pcap` file with Scapy, and counts unique directional 5-tuple flows and total packets. Writes one CSV row per PCAP file. Useful for getting dataset statistics before committing to feature extraction.

```bash
python3 count_unique_flows.py \
  --dataset-path "/home/ubuntu/datasets/DDoS-AT-2022" \
  --output-file "count_unique_flows-DDoS-AT-2022.csv"
```

---

## extract_first_n_flow_features.py

Loads an entire PCAP into memory, groups packets by flow key, and keeps only the first `N` packets per flow to compute flow-level features (duration, byte/packet rates, IAT stats, TCP flag counts). Writes one CSV row per flow. Use only for small-to-medium PCAPs that fit in RAM.

```bash
python3 extract_first_n_flow_features.py \
  --pcap-file "/home/ubuntu/datasets/DDoS-AT-2022/UDP flood/UDP flood/udp flood random port.pcap" \
  --output-file "udp_flood_first3_features.csv" \
  --n-packets 3 \
  --label "UDP-Flood" \
  [--bidirectional]
```

---

## extract_first_n_flow_features_dataset.py

Same feature extraction as above, but recurses over all `.pcap` files under a directory and concatenates results into a single output CSV. The label for each row is derived from the subdirectory name.

```bash
python3 extract_first_n_flow_features_dataset.py --dataset-path "/home/ubuntu/datasets/DDoS-AT-2022/HTTP-Low volume-slow rate-slow header/HTTP-Low volume-slow rate-slow header" --output-file "HTTP-slow-header_first5_features.csv" --n-packets 5
```

```bash
python3 extract_first_n_flow_features_dataset.py \
  --dataset-path "/home/ubuntu/datasets/DDoS-AT-2022" \
  --output-file "DDoS_AT_2022_first10_bidirectional_flow_features.csv" \
  --n-packets 10 \
  [--bidirectional]
```

---

## extract_first_n_flow_features_streaming.py

Streaming variant for large PCAPs (tens of GB+). Reads packets one at a time, flushes completed flows to disk incrementally, and expires inactive flows after a configurable timeout — keeping memory bounded. Use this for the MAWI DITL trace or any PCAP too large to fit in RAM.

```bash
python3 extract_first_n_flow_features_streaming.py \
  --pcap-file "/home/ubuntu/datasets/mawi_ditl2026/202604080000.pcap" \
  --output-file "mawi20260000_first3_features.csv" \
  --n-packets 3 \
  --label "Benign" \
  [--flow-timeout 120] \
  [--progress-interval 100000] \
  [--cleanup-interval 100000] \
  [--flush-interval 100000]
```

---

## extract_first_n_flow_features_streaming_labeled.py

Streaming variant that additionally joins each extracted flow against ground-truth labels from CICDDoS2019 CSV files using timestamp matching with a configurable tolerance. Outputs extra columns: `label`, `label_source`, and `csv_match_time_diff`. Use for CICDDoS2019 where labels come from separate CSVs, not directory names.

```bash
python3 extract_first_n_flow_features_streaming_labeled.py \
  --pcap-file /home/ubuntu/datasets/CICDDoS2019/PCAP-03-11/SAT-03-11-2018_0.pcap \
  --output-file SAT-03-11-2018_0_features_labeled.csv \
  --n-packets 3 \
  --label-csv-dir /home/ubuntu/datasets/CICDDoS2019/CSV-03-11 \
  [--csv-time-tolerance 1]
```

---

## cicddos2019_cached_label_extraction.ipynb

Notebook that ties together PCAP parsing, feature extraction, and CICDDoS2019 label joining with caching so large files are not re-parsed on rerun.

## dataset_check.ipynb

Notebook for exploratory inspection of extracted feature CSVs and dataset statistics.
