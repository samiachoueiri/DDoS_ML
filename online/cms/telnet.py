import telnetlib
import time

# Telnet server details
host = "0.0.0.0"
port = 8086
timeout = 1
sps = 1

# Command to send
# get_index = b"pipeline PIPELINE0 regrd reg_index_0 index 0\n"
# attack0 = b"pipeline PIPELINE0 regrd attack index 0\n"
# attack1 = b"pipeline PIPELINE1 regrd attack index 0\n"
# attack2 = b"pipeline PIPELINE2 regrd attack index 0\n"
# attack3 = b"pipeline PIPELINE3 regrd attack index 0\n"

# proto0 = b"pipeline PIPELINE0 regrd proto_0 index 0\n"
# proto1 = b"pipeline PIPELINE1 regrd proto_0 index 0\n"
# proto2 = b"pipeline PIPELINE2 regrd proto_0 index 0\n"
# proto3 = b"pipeline PIPELINE3 regrd proto_0 index 0\n"

flow0 = b"pipeline PIPELINE0 regrd flow_id0_0 index 0\n"
flow1 = b"pipeline PIPELINE0 regrd flow_id1_0 index 0\n"
flow2 = b"pipeline PIPELINE0 regrd flow_id2_0 index 0\n"
flow3 = b"pipeline PIPELINE0 regrd flow_id3_0 index 0\n"

# ht0_tcp = b"pipeline PIPELINE1 regrd ht0 index 0x330C\n"
# ht1_tcp = b"pipeline PIPELINE1 regrd ht1 index 0x3370\n"
# ht2_tcp = b"pipeline PIPELINE1 regrd ht2 index 0x33D4\n"
# ht3_tcp = b"pipeline PIPELINE1 regrd ht3 index 0x3438\n"

# Function to connect to telnet server and send command
def telnet_session(host, port, timeout):
    try:
        # Connect to the telnet server
        tn = telnetlib.Telnet(host, port, timeout)
        tn.read_until(b"Escape character is", timeout)

        # tn.write(get_index)
        # output = tn.read_until(b"\n", timeout)

        tn.write(flow0)
        output = tn.read_until(b"\n", timeout)
        
        while True:
            try:
                print("------ main")
                # tn.write(attack0)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # attack0_hex = string_output.split(' ')[1].strip()

                # tn.write(attack1)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # attack1_hex = string_output.split(' ')[1].strip()

                # tn.write(attack2)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # attack2_hex = string_output.split(' ')[1].strip()

                # tn.write(attack3)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # attack3_hex = string_output.split(' ')[1].strip()
                
                # print("attack:","P0",attack0_hex,"P1",attack1_hex,"P2",attack2_hex,"P3",attack3_hex)

                # tn.write(proto0)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # proto0_hex = string_output.split(' ')[1].strip()

                # tn.write(proto1)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # proto1_hex = string_output.split(' ')[1].strip()

                # tn.write(proto2)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # proto2_hex = string_output.split(' ')[1].strip()

                # tn.write(proto3)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # proto3_hex = string_output.split(' ')[1].strip()
                
                # print("proto:","P0",proto0_hex,"P1",proto1_hex,"P2",proto2_hex,"P3",proto3_hex)

                print("------ TCP")

                tn.write(flow0)
                output = tn.read_until(b"\n", timeout)
                string_output = output.decode('utf-8')
                flow0_hex = string_output.split(' ')[1].strip()
                flow0_dec = int(flow0_hex, 16)

                tn.write(flow1)
                output = tn.read_until(b"\n", timeout)
                string_output = output.decode('utf-8')
                flow1_hex = string_output.split(' ')[1].strip()
                flow1_dec = int(flow1_hex, 16)

                tn.write(flow2)
                output = tn.read_until(b"\n", timeout)
                string_output = output.decode('utf-8')
                flow2_hex = string_output.split(' ')[1].strip()
                flow2_dec = int(flow2_hex, 16)

                tn.write(flow3)
                output = tn.read_until(b"\n", timeout)
                string_output = output.decode('utf-8')
                flow3_hex = string_output.split(' ')[1].strip()
                flow3_dec = int(flow3_hex, 16)

                print("TCP flow:","h0",flow0_hex,"h1",flow1_hex,"h2",flow2_hex,"h3",flow3_hex)

                # tn.write(ht0_tcp)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # ht0_hex = string_output.split(' ')[1].strip()
                # ht0_dec = int(ht0_hex, 16)

                # tn.write(ht1_tcp)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # ht1_hex = string_output.split(' ')[1].strip()
                # ht1_dec = int(ht1_hex, 16)

                # tn.write(ht2_tcp)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # ht2_hex = string_output.split(' ')[1].strip()
                # ht2_dec = int(ht2_hex, 16)

                # tn.write(ht3_tcp)
                # output = tn.read_until(b"\n", timeout)
                # string_output = output.decode('utf-8')
                # ht3_hex = string_output.split(' ')[1].strip()
                # ht3_dec = int(ht3_hex, 16)

                # print("TCP count:","h0",ht0_dec,"h1",ht1_dec,"h2",ht2_dec,"h3",ht3_dec)

                print("++++++++++++++++++++++++++++++++++++++++++++++++")
                time.sleep(1/sps)
            
            except KeyboardInterrupt:
                print("\nProcess interrupted. Closing...")
                break  # Exit the loop on interrupt

    except Exception as e:
        print(f"Error: {e}")

    finally:
        tn.close()  # Ensure tn.close() is executed

# Start the telnet session
telnet_session(host, port, timeout)