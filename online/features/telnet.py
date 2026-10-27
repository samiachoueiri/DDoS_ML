import csv
import re
import telnetlib
import time

# Telnet server details
host = "0.0.0.0"
port = 8086
timeout = 1
sps = 1

pipeline = "PIPELINE0"
prompt = b"pipeline> "
csv_path = "flows.csv"

# Commands sent per write when dumping; replies are read back in the same order
batch_size = 1000

# Register names as they appear in features.spec (p4c-dpdk appends "_0")
REG_LAST_FLOW_ID = "reg_last_flow_id_0"
REG_UNIQUE_FLOWS = "reg_unique_flows_0"
REG_FLOW_LIST = "reg_flow_list_0"

# One CSV column per per-flow register (indexed by flow_id).
# To add a feature: add its register in features.p4, then add a line here.
FEATURES = [
    ("packets", "reg_pkt_count_0"),
    ("npackets", "reg_npkt_count_0"),   # packets used for features, capped at N_PACKETS
    ("total_bytes", "reg_total_bytes_0"),  # sum of frame lengths over the first N_PACKETS
    ("max_pkt_len", "reg_max_pkt_len_0"),  # largest frame length among the first N_PACKETS
    ("max_iat_us", "reg_max_iat_0"),       # largest inter-arrival time (microseconds) among the first N_PACKETS
]

hex_value = re.compile(rb"0x[0-9a-fA-F]+")


# Read many slots of one register. The server writes its prompt once per socket read,
# not once per command, so parse the 0x... values in order rather than splitting on the prompt.
def regrd_many(tn, reg, indices):
    values = []
    for start in range(0, len(indices), batch_size):
        chunk = indices[start:start + batch_size]
        cmds = "".join(f"pipeline {pipeline} regrd {reg} index {i}\n" for i in chunk)
        tn.write(cmds.encode())

        got = []
        while len(got) < len(chunk):
            line = tn.read_until(b"\n", timeout)
            if not line:
                raise RuntimeError(f"timeout reading {reg}: got {len(got)}/{len(chunk)} replies")
            if b"failed" in line or b"Invalid" in line or b"Error" in line:
                raise RuntimeError(f"{reg}: {line.decode().strip()}")
            got += [int(v, 16) for v in hex_value.findall(line)]
        values += got
    return values


def regrd(tn, reg, index):
    return regrd_many(tn, reg, [index])[0]


def dump_csv(tn):
    n_flows = regrd(tn, REG_UNIQUE_FLOWS, 0)
    print(f"Dumping {n_flows} flows to {csv_path} ...")

    flow_ids = regrd_many(tn, REG_FLOW_LIST, list(range(n_flows)))
    columns = {name: regrd_many(tn, reg, flow_ids) for name, reg in FEATURES}

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["flow_id"] + [name for name, _ in FEATURES])
        for row, flow_id in enumerate(flow_ids):
            writer.writerow([flow_id] + [columns[name][row] for name, _ in FEATURES])

    print(f"Wrote {n_flows} rows to {csv_path}")


# Function to connect to telnet server and send command
def telnet_session(host, port, timeout):
    tn = None
    try:
        # Connect to the telnet server and consume the welcome banner
        tn = telnetlib.Telnet(host, port, timeout)
        tn.read_until(prompt, timeout)

        try:
            while True:
                unique_flows = regrd(tn, REG_UNIQUE_FLOWS, 0)
                last_flow_id = regrd(tn, REG_LAST_FLOW_ID, 0)
                last_flow = {name: regrd(tn, reg, last_flow_id) for name, reg in FEATURES}

                print("------ Flows")
                print("Unique flows seen:", unique_flows)
                print("Last flow_id:", hex(last_flow_id),
                      " ".join(f"{name}: {value}" for name, value in last_flow.items()))
                print("++++++++++++++++++++++++++++++++++++++++++++++++")
                time.sleep(1/sps)

        except KeyboardInterrupt:
            print("\nProcess interrupted.")

        # Drain any reply left over from a command interrupted mid-read
        time.sleep(0.2)
        tn.read_very_eager()
        dump_csv(tn)

    except Exception as e:
        print(f"Error: {e}")

    finally:
        if tn:
            tn.close()  # Ensure tn.close() is executed

# Start the telnet session
telnet_session(host, port, timeout)
