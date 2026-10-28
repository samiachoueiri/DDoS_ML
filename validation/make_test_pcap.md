# make_test_pcap.py

Generates a small test PCAP and writes the features that the offline extractor
(`preprocessing/extract_first_n_flow_features_streaming.py`) should produce for it.
Use it to check that the online feature extraction matches the offline features
before running inference.

The expected features are calculated directly from the packets the script builds,
without calling the extractor, so they serve as an independent reference.

## Quick start

Run from `validation/`:

```bash
# Single TCP flow with 32 packets (simplest test)
python3 make_test_pcap.py --flows tcp_exact_n --packets-per-flow 32 --out-dir test_data_1flow --check

# Full test: all 9 flows
python3 make_test_pcap.py --check
```

`--check` runs the offline extractor on the PCAP and compares its output with the
expected features. Each N should print `PASS`.

## Options

| Option | Default | Meaning |
|---|---|---|
| `--out-dir DIR` | `test_data/` | Where to write the files |
| `--n-values N ...` | `3 4 5` | N values (first N packets per flow) to write expected features for |
| `--packets-per-flow K` | largest N | Packets per flow in the PCAP. Must be at least every N |
| `--flows NAME ...` | all | Include only these flows. Selecting any flow also drops the ARP frames |
| `--check` | off | Run the offline extractor and compare its output with the expected features |

## Output files

| File | Contents |
|---|---|
| `test_flows.pcap` | The test traffic. Source MAC `00:00:00:00:00:01`, destination MAC `00:00:00:00:00:21` |
| `expected_features_n{N}.csv` | Expected feature rows (same columns as the training CSVs, plus `_scenario`) |
| `offline_features_n{N}.csv` | What the offline extractor produced (only with `--check`) |

## Available flows

| Name | What it tests |
|---|---|
| `tcp_exact_n` | TCP flow with different packet sizes, gaps and flags (SYN, ACK, PSH, FIN) |
| `tcp_reverse_dir` | Reverse direction of `tcp_exact_n`, which must be a separate flow |
| `udp_more_than_n` | More than N packets; only the first N count |
| `udp_incomplete` | Fewer packets than the largest N; no row at that N |
| `tcp_zero_duration` | All packets with the same timestamp; duration and rates are 0 |
| `tcp_flags_mix` | URG, RST, PSH and FIN flag counts |
| `icmp_echo` | ICMP; protocol is `1` and both ports are 0 |
| `udp_ipv6` | IPv6 flow |
| `udp_timeout_restart` | Flow that is idle for more than 120 s, then restarts as a new row |

## Comparing online results

For the 3 features the P4 program computes, use `extract_selected_features.py`.
It runs the offline extractor, matches rows with the online CSV by 5-tuple, and
prints a drift report (exact match for bytes and lengths, a tolerance for IAT):

```bash
python3 extract_selected_features.py --pcap-file test_data_1flow/test_flows.pcap \
  --online-file test_data_1flow/online_selected_n5.csv
```

To compare a CSV that has all the training columns, use `compare()`. It applies
one tolerance to every column, so keep it strict:

```bash
python3 -c "import make_test_pcap as m; m.compare('test_data_1flow/expected_features_n3.csv', 'other_n3.csv')"
```

## Replaying on the testbed

Server1 sends and server2 receives. Server2 runs the DPDK pipeline with the
reflector.

### 1. Start the pipeline on server2

```bash
sudo examples/pipeline/build/pipeline -c 0x1F -- -s /home/ubuntu/reflector/reflector.cli
```

In a new terminal on server2, open the pipeline CLI to watch the packet counters:

```bash
telnet 0.0.0.0 8086
pipeline> pipeline PIPELINE1 stats
```

Run `pipeline PIPELINE1 stats` before and after sending. The counters should go
up by the number of packets sent.

### 2. Copy the PCAP to server1

```python
server1.upload_file('/home/ubuntu/DDoS_ML/validation/test_data_1flow/test_flows.pcap', 'test_flows.pcap')
```

### 3a. Replay the PCAP with tcpreplay (server1)

```bash
sudo apt-get install -y tcpreplay     # if needed
sudo tcpreplay -i enp7s0np0 -v test_flows.pcap
```

tcpreplay keeps the original gaps between packets, so timing features can be
compared. Don't use `--topspeed`, `-t`, `-M`, `-p` or `-x`, because they change
the timing.

### 3b. Replay the PCAP with pktgen (server1)

```bash
sudo pktgen -l 0,1 -n 4 -a 07:00.0 -- -P -m "1.0" -s 0:test_flows.pcap
```

Then, at the pktgen prompt:

```
Pktgen:/> enable 0 pcap        # turn on PCAP mode for port 0 (may already be on after -s)
Pktgen:/> set 0 count 32       # send 32 packets, then stop
Pktgen:/> set 0 rate 1         # 1% of line rate, keeps it gentle
Pktgen:/> start 0
```

Set `count` to the number of packets in the PCAP (32 for the single-flow test).
Without it, pktgen loops through the PCAP until `stop 0`, and the same flow
repeats.

Pktgen ignores the timestamps in the PCAP, so only lengths, flags and packet
counts can be compared, not timing features.

### 3c. Send generated packets with pktgen (server1)

This doesn't use the PCAP. It's useful to check the link and pipeline:

```bash
sudo pktgen -l 0,1 -n 4 -a 07:00.0 -- -P -m "1.0"
```

```
set 0 src mac 00:00:00:00:00:01
set 0 dst mac 00:00:00:00:00:21
set 0 src ip 192.168.10.1/24
set 0 dst ip 192.168.10.2
set 0 size 1500
start 0
stop 0
```

### Versions

PCAP replay with pktgen (`-s`) works with:

| Component | Version |
|---|---|
| Pktgen-DPDK | 26.03.0 |
| DPDK | 25.11.4 |

With Pktgen 24.07.1 and DPDK 24.07.0-rc4, `-s` failed at startup with
`pktgen_pcap_open: rte_zmalloc_socket() failed for pcap_info_t structure`.

## Notes

- Packet length is the full Ethernet frame without the checksum (FCS). Every
  frame is at least 60 bytes, so replaying doesn't add padding.
- Timing features (`duration`, `iat_*`) are in integer microseconds, the same
  unit the P4 program uses, so offline and online values compare directly
  (for example `iat_max = 20000`). `packets_per_second` and `bytes_per_second`
  are still per second. After a replay, use a tolerance of a few hundred µs on
  timing columns to allow for replay jitter.
- Flows are one-directional and use a 120 s timeout, the same settings as the
  training data.
