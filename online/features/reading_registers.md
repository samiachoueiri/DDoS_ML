# Reading flow features over telnet

The pipeline's CLI listens on telnet port 8086. Every feature in `flows.csv` comes from a register
indexed by `flow_id`, so you can read any flow by hand while the pipeline is running.
`regrd` only reads, so it is safe to use on the live pipeline.

## 1. Connect

From a second terminal, while the pipeline is running:

```bash
telnet 0.0.0.0 8086
```

## 2. Read a flow's features

Take the `flow_id` from the CSV. The index can be decimal, as the CSV shows it (`983881`), or hex
(`0xF0349`).

```
pipeline PIPELINE0 regrd reg_pkt_count_0 index 983881
pipeline PIPELINE0 regrd reg_npkt_count_0 index 983881
pipeline PIPELINE0 regrd reg_total_bytes_0 index 983881
pipeline PIPELINE0 regrd reg_max_pkt_len_0 index 983881
pipeline PIPELINE0 regrd reg_max_iat_0 index 983881
```

Replies are always in hex. For the CSV row
`983881,32,5,2304,1514,20108` you should get:

| Register | Reply | Decimal | CSV column | Meaning |
|---|---|---|---|---|
| `reg_pkt_count_0` | `0x20` | 32 | `packets` | All packets seen for the flow |
| `reg_npkt_count_0` | `0x5` | 5 | `npackets` | Packets used for features (stops at N = 5) |
| `reg_total_bytes_0` | `0x900` | 2304 | `total_bytes` | Sum of frame lengths, first N packets |
| `reg_max_pkt_len_0` | `0x5ea` | 1514 | `max_pkt_len` | Largest frame length, first N packets |
| `reg_max_iat_0` | `0x4e8c` | 20108 | `max_iat_us` | Largest inter-arrival time in µs, first N packets |

## 3. Other useful registers

```
pipeline PIPELINE0 regrd reg_unique_flows_0 index 0
pipeline PIPELINE0 regrd reg_flow_list_0 index 0
pipeline PIPELINE0 regrd reg_last_flow_id_0 index 0
pipeline PIPELINE0 regrd reg_last_ts_0 index 983881
```

- `reg_unique_flows_0` (index 0) is the number of flows seen.
- `reg_flow_list_0` is the flow IDs in arrival order. Index `i` holds the (i+1)th new flow, so valid
  indices run from 0 to `unique_flows - 1`. This is how `telnet.py` finds the rows to write to the CSV.
- `reg_last_flow_id_0` (index 0) is the flow ID of the most recent packet.
- `reg_last_ts_0` is the clock reading (µs) for the flow's last counted packet (packet N).
  It is a raw clock value, only meaningful as the reference that `max_iat` subtracts from.

## 4. Convert a hex reply to decimal

```bash
python3 -c "print(0x4e8c)"     # 20108
```

## 5. Quit telnet

Press `Ctrl+]`, then type `quit`.

## Notes

- Register names are those in `features.spec`; p4c-dpdk adds `_0` to the names in `features.p4`.
- If a command replies `Command failed.`, the register name doesn't exist in the running pipeline.
  That usually means the pipeline was started from an older `features.spec`.
- Registers keep their values until the pipeline restarts, so a second pcap replay adds to the first.
