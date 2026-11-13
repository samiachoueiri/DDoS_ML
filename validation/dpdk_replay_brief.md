# Brief: timestamp-accurate DPDK PCAP replay on server1

Read this first. It is the context for building a DPDK app on server1 that
replays a PCAP at its original timing, fast enough for MAWI traffic.

## Why

We check that a P4 program (DPDK SWX pipeline on server2) computes the same
per-flow features as an offline Python extractor. One feature is the largest
gap between a flow's first 5 packets (`max_iat_us`), so the replay must keep
the PCAP's original packet timing.

tcpreplay is too slow for MAWI. The 5-second slice took 6.75 s:

```
$ sudo tcpreplay -i enp7s0np0 --preload-pcap benign5s.pcap
Actual: 1052588 packets (52879849 bytes) sent in 6.75 seconds
Rated: 7827951.6 Bps, 62.62 Mbps, 155817.54 pps
Failed packets: 0
```

The trace needs about 210,000 packets per second on average, with higher
peaks. tcpreplay tops out at about 156,000, so every gap is stretched about
1.35x. The online `max_iat_us` comes out a median 1.39x the offline value.
pktgen is fast but ignores PCAP timestamps.

## Goal

A small DPDK app that loads a PCAP into memory and sends each packet when its
timestamp comes due (relative to the first packet), at several million packets
per second if needed, and reports how closely it kept to the schedule.

## Environment (server1)

| Item | Value |
|---|---|
| DPDK | 25.11.4 (dpdk-stable), installed; `pkg-config libdpdk` should work |
| Pktgen | 26.03.0 (`sudo pktgen -l 0,1 -n 4 -a 07:00.0 -- -P -m "1.0"` works) |
| NIC | ConnectX-6, PCI `07:00.0`, kernel name `enp7s0np0`, mlx5 driver |
| Hugepages | Already set up (pktgen runs) |

mlx5 is a bifurcated driver: DPDK uses the port without unbinding it from the
kernel, so tcpreplay and the DPDK app can both use it (not at the same time).

Older Pktgen 24.07.1 with DPDK 24.07.0-rc4 failed PCAP mode with
`rte_zmalloc_socket() failed for pcap_info_t`. Not relevant to this app, but
don't use that DPDK build.

## Files on server1 (`~/mawi/`)

| File | Contents |
|---|---|
| `202604080000_first5s_ipv4.pcap` | First 5.000 s of MAWI 2026-04-08, IPv4 only. 1,052,588 packets, 450,120 flows, snaplen 96 |
| `benign5s.pcap` | Same, MACs rewritten to `00:00:00:00:00:01` -> `00:00:00:00:00:21` (tcprewrite) |

Small test PCAP: `test_flows.pcap` (from `validation/make_test_pcap.py`), one TCP
flow with 32 packets. The expected `max_iat_us` for its first 5 packets is exactly
20000; tcpreplay gave 20101 online.

MAWI keeps only the first 96 bytes of each packet (payload removed). Send the
packets as stored. Some frames are shorter than 60 bytes (34 bytes seen), so
pad them with zeros to 60 bytes. The P4 program reads packet length from the
IP header (`ipv4.totalLen + 14`), so truncation and padding don't change the
features.

## Requirements

- **Input**: classic pcap (not pcapng), microsecond and nanosecond magic, both
  byte orders. Parse it directly (24-byte global header, 16-byte record
  headers); no libpcap needed.
- **Memory**: load the whole file before sending. Store the packet bytes in one
  contiguous buffer plus an array of (offset, length, time offset in ns). At
  send time allocate an mbuf, copy, send. Don't pre-build 1M mbufs with
  2 KB data rooms.
- **Timing**:
  - Convert each packet's time offset to TSC cycles (`rte_get_tsc_hz()`).
  - Start a few ms after loading.
  - In the TX loop, busy-wait on `rte_get_tsc_cycles()`. Send every packet
    that is due in one burst (up to 32), with no sleeps.
  - Run the loop on a dedicated worker lcore.
  - The order and spacing must match the PCAP.
- **No drops**: if `rte_eth_tx_burst` sends fewer than asked, retry the rest
  and count the retries. Never drop silently.
- **Options**:
  - `--pcap FILE` (required)
  - `--port N` (default 0)
  - `--speed F` (default 1.0, multiplies the rate)
  - `--loops N` (default 1)
  - `--smac/--dmac MAC`: optional rewrite, so tcprewrite isn't needed
  - `--pad N` (default 60)
- **Report at the end**:
  - packets and bytes sent;
  - PCAP duration vs actual duration;
  - average pps / Mbps;
  - lateness of the send time against the schedule (p50, p99, max, in µs);
  - tx retries.
- **Build**: a Makefile using `pkg-config libdpdk`, the same pattern as
  `DDoS_ML/online/scripts/code/dpdk_app/Makefile` (the reflector app). Suggested
  location: `~/dpdk_replay/` (or `DDoS_ML/online/scripts/code/dpdk_replay/` if the
  repo is on server1).
- **Run**, like pktgen:
  `sudo ./dpdk_replay -l 0,1 -n 4 -a 07:00.0 -- --pcap ~/mawi/benign5s.pcap`

## How to check it

1. **Small test:** replay `test_flows.pcap` (32 packets). The report should show
   a duration matching the PCAP and lateness of a few µs. On server2, read the
   registers with `telnet.py`: `max_iat_us` should be close to 20000.
2. **MAWI:** replay `benign5s.pcap`. The actual duration should be about 5.00 s
   (tcpreplay: 6.75 s) with 0 drops. Lateness p99 should be in the low µs.
3. **Restart the server2 pipeline** before each replay. Its registers keep
   their values and it has no flow timeout.
4. **Compare on gpu-node** (`DDoS_ML/validation`):
   ```bash
   python3 extract_selected_features.py \
     --pcap-file /home/ubuntu/datasets/mawi_ditl2026/202604080000_first5s_ipv4.pcap \
     --online-file benign5s.csv --output-file offline_benign5s_5n.csv --show 20
   ```
   The median online/offline `max_iat_us` ratio was 1.39 with tcpreplay; it
   should move close to 1.00.

`total_bytes` and `max_pkt_len` will still fail in that report. The offline
extractor counts the stored (truncated) bytes while the P4 program uses the IP
header length. That is a known extractor issue, separate from the replay.

## Server2 side (unchanged, for reference)

```bash
sudo dpdk/examples/pipeline/build/pipeline -c 0x1F -- -s /home/ubuntu/features/features.cli
python3 features/telnet.py      # dumps the registers to CSV
```

The flow table has 2^20 slots with no timeout. The 5-second slice (450,120
flows) causes some hash collisions, which show up as online-only flows. That
is expected.

## Ground rules

- Don't commit or push to git; the user does that.
- Don't change the server2 pipeline or the P4 program.
