##! flow_count.zeek
##! Counts unique flows in a pcap and logs how many packets each flow carried.
##!
##! Outputs:
##!   flow_packets.log  - one line per flow with packet counts per direction
##!   flow_summary.log  - totals (flows, unique 5-tuples, packets)
##!
##! Usage: zeek -C -r capture.pcap flow_count.zeek

@load base/protocols/conn

module FlowCount;

export {
    redef enum Log::ID += { LOG, SUMMARY_LOG };

    ## One record per flow (Zeek connection).
    type Info: record {
        ts:         time            &log;  ## First packet of the flow
        uid:        string          &log;  ## Zeek unique flow ID (matches conn.log)
        orig_h:     addr            &log;
        orig_p:     port            &log;
        resp_h:     addr            &log;
        resp_p:     port            &log;
        proto:      transport_proto &log;
        orig_pkts:  count           &log;  ## Packets originator -> responder
        resp_pkts:  count           &log;  ## Packets responder -> originator
        total_pkts: count           &log;
        orig_bytes: count           &log;  ## IP-level bytes, originator side
        resp_bytes: count           &log;  ## IP-level bytes, responder side
        duration:   interval        &log;
    };

    ## Single summary record written when Zeek finishes.
    type Summary: record {
        pcap_flows:         count &log;  ## Total flows Zeek tracked
        unique_5tuples:     count &log;  ## Distinct (src, sport, dst, dport, proto)
        total_packets:      count &log;
        tcp_flows:          count &log;
        udp_flows:          count &log;
        icmp_flows:         count &log;
    };
}

global flow_total = 0;
global packet_total = 0;
global proto_counts: table[transport_proto] of count &default=0;
# Port values carry the transport protocol (e.g. 53/udp), so this is a 5-tuple.
global unique_tuples: set[addr, port, addr, port];

event zeek_init()
    {
    Log::create_stream(FlowCount::LOG,
        [$columns=Info, $path="flow_packets"]);
    Log::create_stream(FlowCount::SUMMARY_LOG,
        [$columns=Summary, $path="flow_summary"]);
    }

# Fires once for every flow when it ends (or when the pcap finishes).
event connection_state_remove(c: connection)
    {
    local op = c$orig?$num_pkts ? c$orig$num_pkts : 0;
    local rp = c$resp?$num_pkts ? c$resp$num_pkts : 0;
    local ob = c$orig?$num_bytes_ip ? c$orig$num_bytes_ip : 0;
    local rb = c$resp?$num_bytes_ip ? c$resp$num_bytes_ip : 0;
    local proto = get_port_transport_proto(c$id$resp_p);

    ++flow_total;
    packet_total += op + rp;
    ++proto_counts[proto];
    add unique_tuples[c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p];

    Log::write(FlowCount::LOG, [
        $ts=c$start_time,
        $uid=c$uid,
        $orig_h=c$id$orig_h,
        $orig_p=c$id$orig_p,
        $resp_h=c$id$resp_h,
        $resp_p=c$id$resp_p,
        $proto=proto,
        $orig_pkts=op,
        $resp_pkts=rp,
        $total_pkts=op + rp,
        $orig_bytes=ob,
        $resp_bytes=rb,
        $duration=c$duration
    ]);
    }

event zeek_done()
    {
    local s: Summary = [
        $pcap_flows=flow_total,
        $unique_5tuples=|unique_tuples|,
        $total_packets=packet_total,
        $tcp_flows=proto_counts[tcp],
        $udp_flows=proto_counts[udp],
        $icmp_flows=proto_counts[icmp]
    ];
    Log::write(FlowCount::SUMMARY_LOG, s);

    print fmt("Total flows:          %d", flow_total);
    print fmt("Unique 5-tuples:      %d", |unique_tuples|);
    print fmt("Total packets:        %d", packet_total);
    print fmt("TCP / UDP / ICMP:     %d / %d / %d",
              proto_counts[tcp], proto_counts[udp], proto_counts[icmp]);
    }
