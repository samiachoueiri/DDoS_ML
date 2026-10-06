#!/usr/bin/env bash
# count_flows.sh - run Zeek on a pcap, count unique flows, log packets per flow.
#
# Usage: ./count_flows.sh <file.pcap> [output_dir] [top_n]
#   output_dir defaults to ./zeek_out_<pcapname>
#   top_n      defaults to 10 (how many busiest flows to print)
# ./count_flows.sh /home/ubuntu/datasets/mawi/202604080000.pcap

set -euo pipefail

PCAP="${1:-}"
if [[ -z "$PCAP" || ! -f "$PCAP" ]]; then
    echo "Usage: $0 <file.pcap> [output_dir] [top_n]" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZEEK_SCRIPT="$SCRIPT_DIR/flow_count.zeek"
PCAP_ABS="$(realpath "$PCAP")"
NAME="$(basename "$PCAP" | sed 's/\.[^.]*$//')"
OUT_DIR="${2:-./zeek_out_${NAME}}"
TOP_N="${3:-10}"

# Find zeek even if PATH wasn't updated
ZEEK_BIN="$(command -v zeek || echo /opt/zeek/bin/zeek)"
ZEEK_CUT="$(command -v zeek-cut || echo /opt/zeek/bin/zeek-cut)"
[[ -x "$ZEEK_BIN" ]] || { echo "zeek not found. Is /opt/zeek/bin in PATH?" >&2; exit 1; }
[[ -f "$ZEEK_SCRIPT" ]] || { echo "Missing $ZEEK_SCRIPT" >&2; exit 1; }

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

echo "== Processing $PCAP_ABS"
echo "== Logs will be written to $(pwd)"
echo

# -C : ignore bad checksums (common with NIC offloading in captures)
# -r : read from pcap instead of a live interface
"$ZEEK_BIN" -C -r "$PCAP_ABS" "$ZEEK_SCRIPT"

echo
echo "== Top $TOP_N flows by packet count"
printf "%-16s %-40s %-40s %-5s %10s %10s %10s\n" \
    "UID" "SOURCE" "DESTINATION" "PROTO" "ORIG_PKTS" "RESP_PKTS" "TOTAL"
"$ZEEK_CUT" uid orig_h orig_p resp_h resp_p proto orig_pkts resp_pkts total_pkts \
    < flow_packets.log \
  | sort -t$'\t' -k9,9nr \
  | head -n "$TOP_N" \
  | awk -F'\t' '{printf "%-16s %-40s %-40s %-5s %10s %10s %10s\n",
                 $1, $2":"$3, $4":"$5, $6, $7, $8, $9}'

echo
echo "Files:"
echo "  $(pwd)/flow_packets.log   (packets per flow)"
echo "  $(pwd)/flow_summary.log   (totals)"
echo "  $(pwd)/conn.log           (standard Zeek connection log)"
