# Online feature extraction test

This test checks that the P4 data-plane program computes the same flow features
as the offline extractor used to build the training data
(`preprocessing/extract_first_n_flow_features_streaming.py`). It has to pass
before the classifier runs on these features online.

The test works in four steps:

1. Generate a test PCAP whose expected features are already known
   (`validation/make_test_pcap.py`).
2. Replay it from server1 into the P4-DPDK pipeline on server2.
3. Read the per-flow registers from the pipeline over telnet and save them as
   CSV.
4. Compare the CSV with the expected features.

## Workflow

```
 local machine                      server1                     server2
 ─────────────                      ───────                     ───────
 make_test_pcap.py                                              p4c-dpdk features.p4
   ├─ test_flows.pcap ──upload──▶  tcpreplay ── enp7s0np0 ──▶   pipeline (features.cli)
   └─ expected_features_n5.csv                                     │ registers
                                                                   ▼
                                                                telnet.py ──▶ *_flows.csv
                                                                                 │
 compare expected vs online ◀────────────────────────────────────────────────────┘
```

## Folder contents

| File | Purpose |
|---|---|
| `features.p4` | P4 program (PNA architecture). Parses Ethernet/IPv4/TCP/UDP/ICMP, hashes the 5-tuple into a flow ID, and updates per-flow feature registers for the first `N_PACKETS` (= 5) packets of each flow. It also swaps the MAC and IP addresses and sends each packet back out of the port it arrived on (reflector). |
| `features.spec` | Output of `p4c-dpdk`: the SWX pipeline specification that DPDK loads. Regenerate it whenever `features.p4` changes. |
| `features.cli` | DPDK `pipeline` app script. Builds the spec into a shared object, creates the mempool and the two ethdevs (`0000:07:00.0`, `0000:08:00.0`, promiscuous), builds `PIPELINE0` and runs it on thread 1. |
| `ethdev0.io` | Binds the pipeline's input and output ports 0/1 to the two ethdevs. |
| `1_flows.csv` | Online result for the single-flow test PCAP (`validation/test_data_1flow/test_flows.pcap`, 1 TCP flow, 32 packets). |
| `8_flows.csv` | Online result for the full test PCAP (`validation/test_data/test_flows.pcap`, 9 flows). |
| `steps.txt` | Original plain-text notes; this README replaces them. |

`telnet.py`, which reads the registers and writes the CSV, is on server2
(`/home/ubuntu/features/telnet.py`) and is not in this folder yet.

On server2, this folder is copied to `/home/ubuntu/features/`. The paths in
`features.cli` point there.

## What the P4 program extracts

Each packet is assigned a flow ID: a CRC32 hash of
(src IP, dst IP, protocol, src port, dst port), reduced to
`FLOW_TABLE_SIZE` = 2^20 slots. Flows are one-directional, as in the training
data, so A→B and B→A are different flows. ICMP uses ports 0.

| Register | Meaning | Offline equivalent |
|---|---|---|
| `reg_pkt_count` | All packets seen for the flow | none (debug) |
| `reg_npkt_count` | Packets used for features; stops at `N_PACKETS` | `packet_count` |
| `reg_total_bytes` | Sum of frame lengths (`ipv4.totalLen + 14`) | `total_bytes` |
| `reg_max_pkt_len` | Largest frame length | `packet_length_max` |
| `reg_last_ts`, `reg_max_iat` | Previous arrival time; largest gap between packets (µs) | `iat_max` (seconds) |
| `reg_unique_flows`, `reg_flow_list` | Number of flows, and their flow IDs in arrival order, so the control plane can find active slots without scanning 2^20 entries | none |
| `reg_last_flow_id` | Flow ID of the most recent packet | none (debug) |

Only packets 1 to `N_PACKETS` update the features. Later packets increase
`reg_pkt_count` only. Timestamps come from the patched DPDK SWX build, which
converts the CPU cycle counter (TSC) to microseconds in 32 bits. The value
wraps every ~71 minutes, but subtracting two timestamps still gives the right
gap across the wrap.

## Running the test

### Server2: compile and start the pipeline

```bash
cd /home/ubuntu/features && p4c-dpdk --arch pna features.p4 -o features.spec && cd
sudo dpdk/examples/pipeline/build/pipeline -c 0x1F -- -s /home/ubuntu/features/features.cli
```

In a second terminal on server2, while the PCAP is replayed:

```bash
python3 features/telnet.py
```

### Server1: replay the PCAP

```bash
sudo tcpreplay -i enp7s0np0 test_flows.pcap
sudo tcpreplay -i enp7s0np0 --limit=3 test_flows.pcap   # only the first 3 packets of the file
```

Use tcpreplay, not pktgen. tcpreplay keeps the original gaps between packets,
which the IAT feature depends on. Restart the pipeline between runs, because
the registers keep their values.

## Results

### Single flow (`1_flows.csv`)

| Feature | Expected (N=5) | Online | |
|---|---|---|---|
| packets seen | 32 | 32 | ✓ |
| npackets | 5 | 5 | ✓ |
| total_bytes | 2304 | 2304 | ✓ |
| max_pkt_len | 1514 | 1514 | ✓ |
| max_iat | 20000 µs | 20101 µs | ✓ within replay jitter (+0.5%) |

The program stops updating after packet 5, even though 32 packets arrive.

### Full test (`8_flows.csv`)

| Flow (online ID) | Scenario | Bytes / max len | max_iat expected → online | |
|---|---|---|---|---|
| 983881 | `tcp_exact_n` | 2304 / 1514 | 20000 → 20440 µs | ✓ |
| 104045 | `tcp_reverse_dir` | 400 / 100 | 2000 → 2088 µs | ✓ |
| 388784 | `udp_more_than_n` (8 pkts) | 870 / 248 | 3700 → 3740 µs | ✓ |
| 593662 | `tcp_zero_duration` | 300 / 60 | 0 → 32 µs | ✓ see below |
| 691653 | `tcp_flags_mix` | 310 / 64 | 900 → 936 µs | ✓ |
| 337019 | `icmp_echo` | 490 / 98 | 1,000,000 → 1,021,892 µs | ✓ (+2.2%) |
| 222850 | `udp_incomplete` (4 pkts) | 800 / 200 | no offline row at N=5 | expected difference |
| 766551 | `udp_timeout_restart` (12 pkts) | 600 / 120 | 5000 → 5093 µs | expected difference |
| — | `udp_ipv6` | — | — | not parsed |

Byte and length features match exactly for every IPv4 flow. IAT values are all
slightly larger than expected. The differences come from tcpreplay's timing,
not from the P4 program.

Known differences from the offline extractor:

- **IPv6 is ignored.** The parser only accepts EtherType `0x0800`, so the IPv6
  flow never gets a row. This is fine if the deployed traffic is IPv4 only.
- **Incomplete flows are visible.** A flow with fewer than N packets still has
  partial values in the registers (`npackets` = 4). The offline extractor never
  writes such a flow, so inference should only run on flows with
  `npackets == N_PACKETS`.
- **No flow timeout.** Offline, a flow that is idle for more than 120 s starts
  again as a new flow. The P4 program has no timeout, so the second half of
  `udp_timeout_restart` is counted under the same flow (12 packets, one row).
  The features still match the first segment.
- **Packets with the same timestamp.** tcpreplay can't send packets at exactly
  the same time, so a gap of 0 becomes a few µs online.
- **Hash collisions.** Two flows whose hashes land in the same slot would share
  registers. With 2^20 slots this is unlikely for small tests but becomes
  possible at high flow counts.

## Next steps

- Add the remaining training features to `features.p4`: minimum and mean
  packet length, minimum and mean IAT, duration, and TCP flag counts.
- Export the 5-tuple (or the flow-ID-to-5-tuple mapping) with each row, and
  compare automatically with `make_test_pcap.compare()` instead of by eye.
