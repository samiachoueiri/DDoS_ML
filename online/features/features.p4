#include <core.p4>
#include <dpdk/pna.p4>


typedef bit<48>  EthernetAddress;
typedef bit<32>  flow_id_t;
typedef bit<32>  packet_count_t;
typedef bit<32>  byte_count_t;
// Microseconds. This DPDK build's patched SWX turns a read of istd.timestamp into TSC -> us
// (wraps every ~71 min; unsigned subtraction still gives correct IATs across the wrap).
typedef bit<32>  timestamp_t;

// Number of per-flow register slots. Must be a power of two.
// 2^20 = 1,048,576 slots; each register array costs 8 bytes/slot in DPDK SWX (8 MB here).
const bit<32> FLOW_TABLE_SIZE = 1048576;

// Only the first N_PACKETS packets of each flow are used for feature extraction.
const bit<32> N_PACKETS = 5;

// Ethernet header (dst MAC 6 + src MAC 6 + EtherType 2), added to ipv4.totalLen to get frame length.
const bit<32> ETH_HEADER_LEN = 14;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

// Only the fixed first 4 bytes; the rest of the ICMP header depends on the type.
header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

struct empty_metadata_t {
}


//////////////////////////////////////////////////////////////////////
// Struct types for holding user-defined collections of headers and
// metadata in the P4 developer's program.
//
// Note: The names of these struct types are completely up to the P4
// developer, as are their member fields, with the only restriction
// being that the structs intended to contain headers should only
// contain members whose types are header, header stack, or
// header_union.
//////////////////////////////////////////////////////////////////////

struct main_metadata_t {
    flow_id_t      flow_id;
    packet_count_t pkt_count;
    packet_count_t npkt_count;
    byte_count_t   pkt_len;        // frame length of the current packet
    byte_count_t   total_bytes;
    byte_count_t   max_pkt_len;
    timestamp_t    now;            // arrival time of the current packet (us)
    timestamp_t    last_ts;        // arrival time of the previous packet of this flow
    timestamp_t    iat;
    timestamp_t    max_iat;
    // L4 ports, filled by the parser from whichever of TCP/UDP is present (0 for ICMP).
    bit<16>        src_port;
    bit<16>        dst_port;
}

// User-defined struct containing all of those headers parsed in the
// main parser.
struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
}

control PreControlImpl(
    in    headers_t  hdr,
    inout main_metadata_t meta,
    in    pna_pre_input_metadata_t  istd,
    inout pna_pre_output_metadata_t ostd)
{
    apply {
        }
}

parser MainParserImpl(
    packet_in pkt,
    out   headers_t       hdr,
    inout main_metadata_t main_meta,
    in    pna_main_parser_input_metadata_t istd)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            1: parse_icmp;
            17: parse_udp;
            default: accept;
        }
    
    } 
    state parse_tcp {
        pkt.extract(hdr.tcp);
        main_meta.src_port = hdr.tcp.srcPort;
        main_meta.dst_port = hdr.tcp.dstPort;
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        main_meta.src_port = hdr.udp.srcPort;
        main_meta.dst_port = hdr.udp.dstPort;
        transition accept;
    }
    state parse_icmp {
        // ICMP has no ports: all ICMP between two hosts is one flow (src, dst, proto=1).
        pkt.extract(hdr.icmp);
        main_meta.src_port = 0;
        main_meta.dst_port = 0;
        transition accept;
    }
}

control MainControlImpl(
    inout headers_t       hdr,           // from main parser
    inout main_metadata_t user_meta,     // from main parser, to "next block"
    in    pna_main_input_metadata_t  istd,
    inout pna_main_output_metadata_t ostd)
{
    // p4c-dpdk maps every CRC variant to DPDK's crc32, so ask for CRC32 explicitly.
    Hash<flow_id_t>(PNA_HashAlgorithm_t.CRC32) flow_hash;

    // Per-flow packet counter, indexed by flow_id.
    Register<packet_count_t, flow_id_t>(FLOW_TABLE_SIZE) reg_pkt_count;

    // Per-flow counter of packets used for feature extraction; saturates at N_PACKETS.
    Register<packet_count_t, flow_id_t>(FLOW_TABLE_SIZE) reg_npkt_count;

    // Feature: sum of frame lengths (Ethernet + IP + payload, as shown by Wireshark) over the first N_PACKETS packets.
    Register<byte_count_t, flow_id_t>(FLOW_TABLE_SIZE) reg_total_bytes;

    // Feature: largest frame length among the first N_PACKETS packets.
    Register<byte_count_t, flow_id_t>(FLOW_TABLE_SIZE) reg_max_pkt_len;

    // Feature: largest inter-arrival time (us) between consecutive packets among the first N_PACKETS.
    Register<timestamp_t, flow_id_t>(FLOW_TABLE_SIZE) reg_last_ts;
    Register<timestamp_t, flow_id_t>(FLOW_TABLE_SIZE) reg_max_iat;

    // Flow key (5-tuple), written on the flow's first packet so the CSV can be matched against
    // an offline extractor. If two flows collide on one slot, this holds the first flow's tuple.
    Register<bit<32>, flow_id_t>(FLOW_TABLE_SIZE) reg_src_ip;
    Register<bit<32>, flow_id_t>(FLOW_TABLE_SIZE) reg_dst_ip;
    Register<bit<8>,  flow_id_t>(FLOW_TABLE_SIZE) reg_proto;
    Register<bit<16>, flow_id_t>(FLOW_TABLE_SIZE) reg_src_port;
    Register<bit<16>, flow_id_t>(FLOW_TABLE_SIZE) reg_dst_port;

    // Debug registers (single slot, index 0) so we can watch the pipeline over telnet.
    Register<flow_id_t, bit<32>>(1) reg_last_flow_id;    // flow_id of the most recent packet
    Register<bit<32>, bit<32>>(1)   reg_unique_flows;    // slots that went 0 -> 1 (new flows)

    // Append-only list of flow_ids in arrival order: entries [0, unique_flows) are valid.
    // Lets the control plane find the active slots without scanning all FLOW_TABLE_SIZE of them.
    Register<flow_id_t, bit<32>>(FLOW_TABLE_SIZE) reg_flow_list;

    action compute_flow_id() {
        // 5-tuple hash (protocol keeps TCP and UDP flows on the same ports apart), reduced to [0, FLOW_TABLE_SIZE) so it is a valid register index.
        user_meta.flow_id = flow_hash.get_hash((flow_id_t)0,
            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol,
             user_meta.src_port, user_meta.dst_port},
            FLOW_TABLE_SIZE);
    }

    apply {
        if (hdr.ipv4.isValid() && (hdr.tcp.isValid() || hdr.udp.isValid() || hdr.icmp.isValid())) {
            compute_flow_id();

            user_meta.pkt_count = reg_pkt_count.read(user_meta.flow_id) + 1;
            reg_pkt_count.write(user_meta.flow_id, user_meta.pkt_count);

            if (user_meta.pkt_count == 1) {
                bit<32> n_flows = reg_unique_flows.read(0);
                reg_flow_list.write(n_flows, user_meta.flow_id);
                reg_unique_flows.write(0, n_flows + 1);

                reg_src_ip.write(user_meta.flow_id, hdr.ipv4.srcAddr);
                reg_dst_ip.write(user_meta.flow_id, hdr.ipv4.dstAddr);
                reg_proto.write(user_meta.flow_id, hdr.ipv4.protocol);
                reg_src_port.write(user_meta.flow_id, user_meta.src_port);
                reg_dst_port.write(user_meta.flow_id, user_meta.dst_port);
            }

            user_meta.npkt_count = reg_npkt_count.read(user_meta.flow_id);
            if (user_meta.npkt_count < N_PACKETS) {
                user_meta.npkt_count = user_meta.npkt_count + 1;
                reg_npkt_count.write(user_meta.flow_id, user_meta.npkt_count);

                // Feature extraction goes here: only runs for packets 1..N_PACKETS of a flow.
                user_meta.pkt_len = (byte_count_t)hdr.ipv4.totalLen + ETH_HEADER_LEN;

                user_meta.total_bytes = reg_total_bytes.read(user_meta.flow_id) + user_meta.pkt_len;
                reg_total_bytes.write(user_meta.flow_id, user_meta.total_bytes);

                // Register starts at 0, so the first packet always becomes the max.
                user_meta.max_pkt_len = reg_max_pkt_len.read(user_meta.flow_id);
                if (user_meta.pkt_len > user_meta.max_pkt_len) {
                    user_meta.max_pkt_len = user_meta.pkt_len;
                    reg_max_pkt_len.write(user_meta.flow_id, user_meta.max_pkt_len);
                }

                // Read the clock exactly once. Each read of istd.timestamp in the spec samples the TSC
                // again, and p4c's copy propagation would re-insert the read at every use of a variable
                // holding it. Register.write arguments and Register.read results are exempt, so take
                // the reading inside the write and get it back with a read.
                // Timestamp_t is a P4 `type` over bit<64>: cast to bit<64> first, then keep the low 32 bits.
                user_meta.last_ts = reg_last_ts.read(user_meta.flow_id);
                reg_last_ts.write(user_meta.flow_id, ((bit<64>)istd.timestamp)[31:0]);
                user_meta.now = reg_last_ts.read(user_meta.flow_id);

                // IAT needs a previous packet, so packets 2..N_PACKETS give N_PACKETS-1 IATs.
                if (user_meta.npkt_count > 1) {
                    user_meta.iat = user_meta.now - user_meta.last_ts;

                    user_meta.max_iat = reg_max_iat.read(user_meta.flow_id);
                    if (user_meta.iat > user_meta.max_iat) {
                        user_meta.max_iat = user_meta.iat;
                        reg_max_iat.write(user_meta.flow_id, user_meta.max_iat);
                    }
                }
            }
            reg_last_flow_id.write(0, user_meta.flow_id);
        }

        bit<32> tmp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = tmp_ip;
        
        bit<48> tmp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp_mac;
        
        if (istd.input_port == (PortId_t) 0){
            send_to_port((PortId_t) 0);
        }
        else if (istd.input_port == (PortId_t) 1){
            send_to_port((PortId_t) 1);
        }
    }
}

control MainDeparserImpl(
    packet_out pkt,
    inout    headers_t hdr,                // from main control
    in    main_metadata_t user_meta,    // from main control
    in    pna_main_output_metadata_t ostd)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.icmp);
    }
}

PNA_NIC(
    MainParserImpl(),
    PreControlImpl(),
    MainControlImpl(),
    MainDeparserImpl()
    ) main;