









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
	bit<8> dataOffset_res
	bit<8> ecn_flags
	bit<16> window
	bit<16> checksum
	bit<16> urgentPtr
}

struct main_metadata_t {
	bit<32> pna_main_input_metadata_input_port
	bit<16> local_metadata_flow_id0
	bit<16> local_metadata_flow_id1
	bit<16> local_metadata_flow_id2
	bit<16> local_metadata_flow_id3
	bit<32> local_metadata_count_0
	bit<32> local_metadata_count_1
	bit<32> local_metadata_count_2
	bit<32> local_metadata_count_3
	bit<32> local_metadata_minimum
	bit<32> local_metadata_dif
	bit<32> pna_main_output_metadata_output_port
	bit<32> MainControlT_tmp
	bit<32> MainControlT_tmp_0
	bit<32> MainControlT_tmp_1
	bit<32> MainControlT_tmp_2
	bit<16> MainControlT_tmp_3
	bit<16> MainControlT_tmp_4
	bit<32> MainControlT_tmp_5
	bit<32> MainControlT_tmp_6
	bit<16> MainControlT_tmp_7
	bit<16> MainControlT_tmp_8
	bit<32> MainControlT_tmp_9
	bit<32> MainControlT_tmp_10
	bit<16> MainControlT_tmp_11
	bit<16> MainControlT_tmp_12
	bit<32> MainControlT_tmp_13
	bit<32> MainControlT_tmp_14
	bit<16> MainControlT_tmp_15
	bit<16> MainControlT_tmp_16
	bit<32> MainControlT_tmp_17
	bit<32> MainControlT_tmp_18
	bit<32> MainControlT_tmp_19
	bit<32> MainControlT_tmp_20
	bit<32> MainControlT_tmp_21
	bit<32> MainControlT_tmp_22
	bit<32> MainControlT_tmp_ip
	bit<48> MainControlT_tmp_mac
}
metadata instanceof main_metadata_t

header ethernet instanceof ethernet_t
header ipv4 instanceof ipv4_t
header tcp instanceof tcp_t

regarray flow_id0_0 size 0x1 initval 0
regarray flow_id1_0 size 0x1 initval 0
regarray flow_id2_0 size 0x1 initval 0
regarray flow_id3_0 size 0x1 initval 0
regarray ht0_0 size 0x8000 initval 0
regarray ht1_0 size 0x8000 initval 0
regarray ht2_0 size 0x8000 initval 0
regarray ht3_0 size 0x8000 initval 0
regarray direction size 0x100 initval 0
apply {
	rx m.pna_main_input_metadata_input_port
	extract h.ethernet
	jmpeq MAINPARSERIMPL_PARSE_IPV4 h.ethernet.etherType 0x800
	jmp MAINPARSERIMPL_ACCEPT
	MAINPARSERIMPL_PARSE_IPV4 :	extract h.ipv4
	jmpeq MAINPARSERIMPL_PARSE_TCP h.ipv4.protocol 0x6
	jmp MAINPARSERIMPL_ACCEPT
	MAINPARSERIMPL_PARSE_TCP :	extract h.tcp
	MAINPARSERIMPL_ACCEPT :	jmpnv LABEL_FALSE h.tcp
	mov m.local_metadata_minimum 0xFFFFF
	mov m.MainControlT_tmp_3 h.tcp.srcPort
	mov m.MainControlT_tmp_4 h.tcp.dstPort
	mov m.MainControlT_tmp_5 h.ipv4.srcAddr
	mov m.MainControlT_tmp_6 h.ipv4.dstAddr
	hash crc32 m.local_metadata_flow_id0  m.MainControlT_tmp_3 m.MainControlT_tmp_6
	and m.local_metadata_flow_id0 0x7FFF
	add m.local_metadata_flow_id0 0x0
	mov m.MainControlT_tmp_7 h.tcp.srcPort
	mov m.MainControlT_tmp_8 h.tcp.dstPort
	mov m.MainControlT_tmp_9 h.ipv4.srcAddr
	mov m.MainControlT_tmp_10 h.ipv4.dstAddr
	hash crc32 m.local_metadata_flow_id1  m.MainControlT_tmp_7 m.MainControlT_tmp_10
	and m.local_metadata_flow_id1 0x7FFF
	add m.local_metadata_flow_id1 0x64
	mov m.MainControlT_tmp_11 h.tcp.srcPort
	mov m.MainControlT_tmp_12 h.tcp.dstPort
	mov m.MainControlT_tmp_13 h.ipv4.srcAddr
	mov m.MainControlT_tmp_14 h.ipv4.dstAddr
	hash crc32 m.local_metadata_flow_id2  m.MainControlT_tmp_11 m.MainControlT_tmp_14
	and m.local_metadata_flow_id2 0x7FFF
	add m.local_metadata_flow_id2 0xC8
	mov m.MainControlT_tmp_15 h.tcp.srcPort
	mov m.MainControlT_tmp_16 h.tcp.dstPort
	mov m.MainControlT_tmp_17 h.ipv4.srcAddr
	mov m.MainControlT_tmp_18 h.ipv4.dstAddr
	hash crc32 m.local_metadata_flow_id3  m.MainControlT_tmp_15 m.MainControlT_tmp_18
	and m.local_metadata_flow_id3 0x7FFF
	add m.local_metadata_flow_id3 0x12C
	regwr flow_id0_0 0x0 m.local_metadata_flow_id0
	regwr flow_id1_0 0x0 m.local_metadata_flow_id1
	regwr flow_id2_0 0x0 m.local_metadata_flow_id2
	regwr flow_id3_0 0x0 m.local_metadata_flow_id3
	regrd m.local_metadata_count_0 ht0_0 m.local_metadata_flow_id0
	regrd m.local_metadata_count_1 ht1_0 m.local_metadata_flow_id1
	regrd m.local_metadata_count_2 ht2_0 m.local_metadata_flow_id2
	regrd m.local_metadata_count_3 ht3_0 m.local_metadata_flow_id3
	mov m.local_metadata_dif 0xFFFFF
	sub m.local_metadata_dif m.local_metadata_count_0
	and m.local_metadata_dif 0xFFFFF
	mov m.MainControlT_tmp 0xFFFFF
	sub m.MainControlT_tmp m.local_metadata_count_0
	and m.MainControlT_tmp 0xFFFFF
	jmpgt LABEL_TRUE_0 m.MainControlT_tmp 0x0
	jmp LABEL_END_0
	LABEL_TRUE_0 :	mov m.local_metadata_minimum m.local_metadata_count_0
	LABEL_END_0 :	mov m.local_metadata_dif m.local_metadata_minimum
	sub m.local_metadata_dif m.local_metadata_count_1
	and m.local_metadata_dif 0xFFFFF
	mov m.MainControlT_tmp_0 m.local_metadata_minimum
	sub m.MainControlT_tmp_0 m.local_metadata_count_1
	and m.MainControlT_tmp_0 0xFFFFF
	jmpgt LABEL_TRUE_1 m.MainControlT_tmp_0 0x0
	jmp LABEL_END_1
	LABEL_TRUE_1 :	mov m.local_metadata_minimum m.local_metadata_count_1
	LABEL_END_1 :	mov m.local_metadata_dif m.local_metadata_minimum
	sub m.local_metadata_dif m.local_metadata_count_2
	and m.local_metadata_dif 0xFFFFF
	mov m.MainControlT_tmp_1 m.local_metadata_minimum
	sub m.MainControlT_tmp_1 m.local_metadata_count_2
	and m.MainControlT_tmp_1 0xFFFFF
	jmpgt LABEL_TRUE_2 m.MainControlT_tmp_1 0x0
	jmp LABEL_END_2
	LABEL_TRUE_2 :	mov m.local_metadata_minimum m.local_metadata_count_2
	LABEL_END_2 :	mov m.local_metadata_dif m.local_metadata_minimum
	sub m.local_metadata_dif m.local_metadata_count_3
	and m.local_metadata_dif 0xFFFFF
	mov m.MainControlT_tmp_2 m.local_metadata_minimum
	sub m.MainControlT_tmp_2 m.local_metadata_count_3
	and m.MainControlT_tmp_2 0xFFFFF
	jmpgt LABEL_TRUE_3 m.MainControlT_tmp_2 0x0
	jmp LABEL_END_3
	LABEL_TRUE_3 :	mov m.local_metadata_minimum m.local_metadata_count_3
	LABEL_END_3 :	jmpgt LABEL_TRUE_4 m.local_metadata_minimum 0x186A0
	mov m.MainControlT_tmp_19 m.local_metadata_count_0
	add m.MainControlT_tmp_19 0x1
	and m.MainControlT_tmp_19 0xFFFFF
	regwr ht0_0 m.local_metadata_flow_id0 m.MainControlT_tmp_19
	mov m.MainControlT_tmp_20 m.local_metadata_count_1
	add m.MainControlT_tmp_20 0x1
	and m.MainControlT_tmp_20 0xFFFFF
	regwr ht1_0 m.local_metadata_flow_id1 m.MainControlT_tmp_20
	mov m.MainControlT_tmp_21 m.local_metadata_count_2
	add m.MainControlT_tmp_21 0x1
	and m.MainControlT_tmp_21 0xFFFFF
	regwr ht2_0 m.local_metadata_flow_id2 m.MainControlT_tmp_21
	mov m.MainControlT_tmp_22 m.local_metadata_count_3
	add m.MainControlT_tmp_22 0x1
	and m.MainControlT_tmp_22 0xFFFFF
	regwr ht3_0 m.local_metadata_flow_id3 m.MainControlT_tmp_22
	mov m.MainControlT_tmp_ip h.ipv4.srcAddr
	mov h.ipv4.srcAddr h.ipv4.dstAddr
	mov h.ipv4.dstAddr m.MainControlT_tmp_ip
	mov m.MainControlT_tmp_mac h.ethernet.srcAddr
	mov h.ethernet.srcAddr h.ethernet.dstAddr
	mov h.ethernet.dstAddr m.MainControlT_tmp_mac
	jmpneq LABEL_FALSE_5 m.pna_main_input_metadata_input_port 0x0
	mov m.pna_main_output_metadata_output_port 0x0
	jmp LABEL_END
	LABEL_FALSE_5 :	jmpneq LABEL_END m.pna_main_input_metadata_input_port 0x1
	mov m.pna_main_output_metadata_output_port 0x1
	jmp LABEL_END
	LABEL_TRUE_4 :	drop
	jmp LABEL_END
	LABEL_FALSE :	mov m.pna_main_output_metadata_output_port 0x0
	LABEL_END :	emit h.ethernet
	emit h.ipv4
	emit h.tcp
	tx m.pna_main_output_metadata_output_port
}


