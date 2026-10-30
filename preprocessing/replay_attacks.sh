#!/usr/bin/env bash
# Rewrite the MAC addresses of each attack PCAP and replay it with tcpreplay.
# Runs on server1. The PCAPs come from make_attack_replay_pcap.py.
#
# Between files it waits for Enter, so you can save the registers on server2
# (python3 features/telnet.py) and restart the pipeline. Use -y to not wait.
#
# Usage:
#   sudo ./replay_attacks.sh [-d DIR] [-i IFACE] [-s SRC_MAC] [-m DST_MAC] [-y]
#
#   -d DIR      directory with the *_attack.pcap files   (default: .)
#   -i IFACE    interface to send on                     (default: enp7s0np0)
#   -s SRC_MAC  source MAC                               (default: 00:00:00:00:00:01)
#   -m DST_MAC  destination MAC                          (default: 00:00:00:00:00:21)
#   -y          don't wait between files

set -euo pipefail

DIR="."
IFACE="enp7s0np0"
SRC_MAC="00:00:00:00:00:01"
DST_MAC="00:00:00:00:00:21"
WAIT=1

while getopts "d:i:s:m:yh" opt; do
    case "$opt" in
        d) DIR="$OPTARG" ;;
        i) IFACE="$OPTARG" ;;
        s) SRC_MAC="$OPTARG" ;;
        m) DST_MAC="$OPTARG" ;;
        y) WAIT=0 ;;
        *) sed -n '2,16p' "$0"; exit 1 ;;
    esac
done

for tool in tcprewrite tcpreplay; do
    command -v "$tool" >/dev/null || { echo "$tool not found: sudo apt-get install -y tcpreplay"; exit 1; }
done

shopt -s nullglob
PCAPS=("$DIR"/*_attack.pcap)
[ ${#PCAPS[@]} -gt 0 ] || { echo "No *_attack.pcap files in $DIR"; exit 1; }

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="replay_$(date +%Y%m%d_%H%M%S).log"
echo "Replaying ${#PCAPS[@]} PCAP(s) from $DIR on $IFACE ($SRC_MAC -> $DST_MAC), log: $LOG"

i=0
for pcap in "${PCAPS[@]}"; do
    i=$((i + 1))
    name=$(basename "$pcap")
    rewritten="$TMP_DIR/$name"

    echo "================================================================" | tee -a "$LOG"
    echo "[$i/${#PCAPS[@]}] $name  ($(date '+%F %T'))" | tee -a "$LOG"

    tcprewrite --enet-smac="$SRC_MAC" --enet-dmac="$DST_MAC" \
        --infile="$pcap" --outfile="$rewritten" 2>&1 | tee -a "$LOG"

    # No --topspeed / -M / -x: keep the original gaps between packets (IAT features).
    tcpreplay -i "$IFACE" "$rewritten" 2>&1 | tee -a "$LOG"
    rm -f "$rewritten"

    if [ "$WAIT" -eq 1 ] && [ "$i" -lt ${#PCAPS[@]} ]; then
        read -r -p "Save the registers and restart the pipeline on server2, then press Enter for the next file... " </dev/tty
    fi
done

echo "Done. tcpreplay stats are in $LOG (check 'Failed packets')."
