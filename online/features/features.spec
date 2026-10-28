















struct ethernet_t {
	bit<48> dstAddr
	bit<48> srcAddr
	bit<16> etherType
}

struct ipv4_t {
	bit<8> version_ihl
	bit<8> diffserv
	bit<16> totalLen
	bit<16> identification
	bit<16> flags_fragOffset
	bit<8> ttl
	bit<8> protocol
	bit<16> hdrChecksum
	bit<32> srcAddr
	bit<32> dstAddr
}

struct tcp_t {
	bit<16> srcPort
	bit<16> dstPort
	bit<32> seqNo
	bit<32> ackNo
	bit<16> dataOffset_res_ecn_ctrl
	bit<16> window
	bit<16> checksum
	bit<16> urgentPtr
}

struct udp_t {
	bit<16> srcPort
	bit<16> dstPort
	bit<16> length
	bit<16> checksum
}

struct icmp_t {
	bit<8> type
	bit<8> code
	bit<16> checksum
}

struct main_metadata_t {
	bit<64> pna_main_input_metadata_timestamp
	bit<32> pna_main_input_metadata_input_port
	bit<32> local_metadata_flow_id
	bit<32> local_metadata_pkt_count
	bit<32> local_metadata_npkt_count
	bit<32> local_metadata_pkt_len
	bit<32> local_metadata_total_bytes
	bit<32> local_metadata_max_pkt_len
	bit<32> local_metadata_now
	bit<32> local_metadata_last_ts
	bit<32> local_metadata_iat
	bit<32> local_metadata_max_iat
	bit<16> local_metadata_src_port
	bit<16> local_metadata_dst_port
	bit<32> pna_main_output_metadata_output_port
	bit<32> MainControlT_tmp
	bit<32> MainControlT_tmp_1
	bit<32> MainControlT_tmp_2
	bit<32> MainControlT_tmp_5
	bit<64> MainControlT_tmp_7
	bit<64> MainControlT_tmp_8
	bit<32> MainControlT_tmp_9
	bit<32> MainControlT_tmp_10
	bit<8> MainControlT_tmp_11
	bit<16> MainControlT_tmp_12
	bit<16> MainControlT_tmp_13
	bit<32> MainControlT_tmp_14
	bit<32> MainControlT_tmp_15
	bit<32> MainControlT_n_flows
	bit<32> MainControlT_tmp_ip
	bit<48> MainControlT_tmp_mac
	bit<32> MainControlT_tmp_16
	bit<32> MainControlT_tmp_17
}
metadata instanceof main_metadata_t

header ethernet instanceof ethernet_t
header ipv4 instanceof ipv4_t
header tcp instanceof tcp_t
header udp instanceof udp_t
header icmp instanceof icmp_t

regarray reg_pkt_count_0 size 0x100000 initval 0
regarray reg_npkt_count_0 size 0x100000 initval 0
regarray reg_total_bytes_0 size 0x100000 initval 0
regarray reg_max_pkt_len_0 size 0x100000 initval 0
regarray reg_last_ts_0 size 0x100000 initval 0
regarray reg_max_iat_0 size 0x100000 initval 0
regarray reg_src_ip_0 size 0x100000 initval 0
regarray reg_dst_ip_0 size 0x100000 initval 0
regarray reg_proto_0 size 0x100000 initval 0
regarray reg_src_port_0 size 0x100000 initval 0
regarray reg_dst_port_0 size 0x100000 initval 0
regarray reg_last_flow_id_0 size 0x1 initval 0
regarray reg_unique_flows_0 size 0x1 initval 0
regarray reg_flow_list_0 size 0x100000 initval 0
regarray direction size 0x100 initval 0
apply {
	rx m.pna_main_input_metadata_input_port
	extract h.ethernet
	jmpeq MAINPARSERIMPL_PARSE_IPV4 h.ethernet.etherType 0x800
	jmp MAINPARSERIMPL_ACCEPT
	MAINPARSERIMPL_PARSE_IPV4 :	extract h.ipv4
	jmpeq MAINPARSERIMPL_PARSE_TCP h.ipv4.protocol 0x6
	jmpeq MAINPARSERIMPL_PARSE_ICMP h.ipv4.protocol 0x1
	jmpeq MAINPARSERIMPL_PARSE_UDP h.ipv4.protocol 0x11
	jmp MAINPARSERIMPL_ACCEPT
	MAINPARSERIMPL_PARSE_UDP :	extract h.udp
	mov m.local_metadata_src_port h.udp.srcPort
	mov m.local_metadata_dst_port h.udp.dstPort
	jmp MAINPARSERIMPL_ACCEPT
	MAINPARSERIMPL_PARSE_TCP :	extract h.tcp
	mov m.local_metadata_src_port h.tcp.srcPort
	mov m.local_metadata_dst_port h.tcp.dstPort
	jmp MAINPARSERIMPL_ACCEPT
	MAINPARSERIMPL_PARSE_ICMP :	extract h.icmp
	mov m.local_metadata_src_port 0x0
	mov m.local_metadata_dst_port 0x0
	MAINPARSERIMPL_ACCEPT :	jmpnv LABEL_END h.ipv4
	jmpv LABEL_TRUE h.tcp
	jmpv LABEL_TRUE h.udp
	jmpv LABEL_TRUE h.icmp
	jmp LABEL_END
	LABEL_TRUE :	mov m.MainControlT_tmp_9 h.ipv4.srcAddr
	mov m.MainControlT_tmp_10 h.ipv4.dstAddr
	mov m.MainControlT_tmp_11 h.ipv4.protocol
	mov m.MainControlT_tmp_12 m.local_metadata_src_port
	mov m.MainControlT_tmp_13 m.local_metadata_dst_port
	hash crc32 m.local_metadata_flow_id  m.MainControlT_tmp_9 m.MainControlT_tmp_13
	and m.local_metadata_flow_id 0xFFFFF
	add m.local_metadata_flow_id 0x0
	regrd m.MainControlT_tmp_16 reg_pkt_count_0 m.local_metadata_flow_id
	mov m.local_metadata_pkt_count m.MainControlT_tmp_16
	add m.local_metadata_pkt_count 0x1
	regwr reg_pkt_count_0 m.local_metadata_flow_id m.local_metadata_pkt_count
	mov m.MainControlT_tmp m.MainControlT_tmp_16
	add m.MainControlT_tmp 0x1
	jmpneq LABEL_END_0 m.MainControlT_tmp 0x1
	regrd m.MainControlT_n_flows reg_unique_flows_0 0x0
	regwr reg_flow_list_0 m.MainControlT_n_flows m.local_metadata_flow_id
	mov m.MainControlT_tmp_14 m.MainControlT_n_flows
	add m.MainControlT_tmp_14 0x1
	regwr reg_unique_flows_0 0x0 m.MainControlT_tmp_14
	regwr reg_src_ip_0 m.local_metadata_flow_id h.ipv4.srcAddr
	regwr reg_dst_ip_0 m.local_metadata_flow_id h.ipv4.dstAddr
	regwr reg_proto_0 m.local_metadata_flow_id h.ipv4.protocol
	regwr reg_src_port_0 m.local_metadata_flow_id m.local_metadata_src_port
	regwr reg_dst_port_0 m.local_metadata_flow_id m.local_metadata_dst_port
	LABEL_END_0 :	regrd m.local_metadata_npkt_count reg_npkt_count_0 m.local_metadata_flow_id
	jmplt LABEL_TRUE_1 m.local_metadata_npkt_count 0x5
	jmp LABEL_END_1
	LABEL_TRUE_1 :	add m.local_metadata_npkt_count 0x1
	regwr reg_npkt_count_0 m.local_metadata_flow_id m.local_metadata_npkt_count
	mov m.local_metadata_pkt_len h.ipv4.totalLen
	add m.local_metadata_pkt_len 0xE
	regrd m.MainControlT_tmp_17 reg_total_bytes_0 m.local_metadata_flow_id
	mov m.MainControlT_tmp_5 h.ipv4.totalLen
	add m.MainControlT_tmp_5 0xE
	mov m.local_metadata_total_bytes m.MainControlT_tmp_17
	add m.local_metadata_total_bytes m.MainControlT_tmp_5
	regwr reg_total_bytes_0 m.local_metadata_flow_id m.local_metadata_total_bytes
	regrd m.local_metadata_max_pkt_len reg_max_pkt_len_0 m.local_metadata_flow_id
	mov m.MainControlT_tmp_1 h.ipv4.totalLen
	add m.MainControlT_tmp_1 0xE
	jmpgt LABEL_TRUE_2 m.MainControlT_tmp_1 m.local_metadata_max_pkt_len
	jmp LABEL_END_2
	LABEL_TRUE_2 :	mov m.local_metadata_max_pkt_len h.ipv4.totalLen
	add m.local_metadata_max_pkt_len 0xE
	regwr reg_max_pkt_len_0 m.local_metadata_flow_id m.local_metadata_max_pkt_len
	LABEL_END_2 :	regrd m.local_metadata_last_ts reg_last_ts_0 m.local_metadata_flow_id
	mov m.MainControlT_tmp_7 m.pna_main_input_metadata_timestamp
	and m.MainControlT_tmp_7 0xFFFFFFFF
	mov m.MainControlT_tmp_8 m.MainControlT_tmp_7
	and m.MainControlT_tmp_8 0xFFFFFFFF
	mov m.MainControlT_tmp_15 m.MainControlT_tmp_8
	regwr reg_last_ts_0 m.local_metadata_flow_id m.MainControlT_tmp_15
	regrd m.local_metadata_now reg_last_ts_0 m.local_metadata_flow_id
	jmpgt LABEL_TRUE_3 m.local_metadata_npkt_count 0x1
	jmp LABEL_END_1
	LABEL_TRUE_3 :	mov m.local_metadata_iat m.local_metadata_now
	sub m.local_metadata_iat m.local_metadata_last_ts
	regrd m.local_metadata_max_iat reg_max_iat_0 m.local_metadata_flow_id
	mov m.MainControlT_tmp_2 m.local_metadata_now
	sub m.MainControlT_tmp_2 m.local_metadata_last_ts
	jmpgt LABEL_TRUE_4 m.MainControlT_tmp_2 m.local_metadata_max_iat
	jmp LABEL_END_1
	LABEL_TRUE_4 :	mov m.local_metadata_max_iat m.local_metadata_now
	sub m.local_metadata_max_iat m.local_metadata_last_ts
	regwr reg_max_iat_0 m.local_metadata_flow_id m.local_metadata_max_iat
	LABEL_END_1 :	regwr reg_last_flow_id_0 0x0 m.local_metadata_flow_id
	LABEL_END :	mov m.MainControlT_tmp_ip h.ipv4.srcAddr
	mov h.ipv4.srcAddr h.ipv4.dstAddr
	mov h.ipv4.dstAddr m.MainControlT_tmp_ip
	mov m.MainControlT_tmp_mac h.ethernet.srcAddr
	mov h.ethernet.srcAddr h.ethernet.dstAddr
	mov h.ethernet.dstAddr m.MainControlT_tmp_mac
	jmpneq LABEL_FALSE_5 m.pna_main_input_metadata_input_port 0x0
	mov m.pna_main_output_metadata_output_port 0x0
	jmp LABEL_END_5
	LABEL_FALSE_5 :	jmpneq LABEL_END_5 m.pna_main_input_metadata_input_port 0x1
	mov m.pna_main_output_metadata_output_port 0x1
	LABEL_END_5 :	emit h.ethernet
	emit h.ipv4
	emit h.tcp
	emit h.udp
	emit h.icmp
	tx m.pna_main_output_metadata_output_port
}


