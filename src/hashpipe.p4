/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "include/headers.p4"
#include "include/parsers.p4"

/* MACROS */
#define ENTRIES_PER_TABLE 2040
#define ENTRY_WIDTH 136

#define HP_INIT(num) register<bit<ENTRY_WIDTH>>(ENTRIES_PER_TABLE) hp##num

#define GET_ENTRY(num, seed) \
hash(meta.currentIndex, HashAlgorithm.crc32, (bit<32>)0, {meta.flowId, seed}, (bit<32>)ENTRIES_PER_TABLE);\
hp##num.read(meta.currentEntry, meta.currentIndex);

#define WRITE_ENTRY(num, entry) hp##num.write(meta.currentIndex, entry)

#define STAGE_N(num, seed) {\
meta.flowId = meta.carriedKey;\
GET_ENTRY(num, seed);\
meta.currentKey = meta.currentEntry[135:32];\
meta.currentCount = meta.currentEntry[31:0];\
if (meta.currentKey - meta.carriedKey == 0) {\
    meta.toWriteKey = meta.currentKey;\
    meta.toWriteCount = meta.currentCount + meta.carriedCount;\
    meta.carriedKey = 0;\
    meta.carriedCount = 0;\
} else {\
    if (meta.carriedCount > meta.currentCount) {\
        meta.toWriteKey = meta.carriedKey;\
        meta.toWriteCount = meta.carriedCount;\
\
        meta.carriedKey = meta.currentKey;\
        meta.carriedCount = meta.currentCount;\
    } else {\
        meta.toWriteKey = meta.currentKey;\
        meta.toWriteCount = meta.currentCount;\
    }\
}\
bit<136> temp = meta.toWriteKey ++ meta.toWriteCount;\
WRITE_ENTRY(num, temp);\
}

/* Initialize HP*/
HP_INIT(0);
HP_INIT(1);
HP_INIT(2);
HP_INIT(3);
HP_INIT(4);
HP_INIT(5);

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }
    
    table ip_forward {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            drop;
            forward;
        }
        default_action = drop;
        const entries = {
            1 : forward(2);
            2 : forward(1);
        }
    }
    
    apply {
        if (hdr.ipv4.isValid()) {    
            ip_forward.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action extract_flow_id () {
        meta.flowId[103:72] = hdr.ipv4.srcAddr;
        meta.flowId[71:40] = hdr.ipv4.dstAddr;
        meta.flowId[39:32] = hdr.ipv4.protocol;
        
        if(hdr.tcp.isValid()) {
            meta.flowId[31:16] = hdr.tcp.srcPort;
            meta.flowId[15:0] = hdr.tcp.dstPort;
        } else if(hdr.udp.isValid()) {
            meta.flowId[31:16] = hdr.udp.srcPort;
            meta.flowId[15:0] = hdr.udp.dstPort;
        } else {
            meta.flowId[31:16] = 0;
            meta.flowId[15:0] = 0;
        }
    }

    action stage1 () {
        meta.carriedKey = meta.flowId;
        meta.carriedCount = 0;

        GET_ENTRY(0, 104w00000000000000000000);

        meta.currentKey = meta.currentEntry[135:32];
        meta.currentCount = meta.currentEntry[31:0];

        // If the flowIds are the same
        if (meta.currentKey - meta.carriedKey == 0) {
            meta.toWriteKey = meta.currentKey;
            meta.toWriteCount = meta.currentCount + 1;

            meta.carriedKey = 0;
            meta.carriedCount = 0;
        } else {
            meta.toWriteKey = meta.carriedKey;
            meta.toWriteCount = 1;

            meta.carriedKey = meta.currentKey;
            meta.carriedCount = meta.currentCount;
        }

        bit<136> temp = meta.toWriteKey ++ meta.toWriteCount;
        WRITE_ENTRY(0, temp);
    }

    action hashpipe() {
        extract_flow_id();
        stage1();
        STAGE_N(1, 104w11111111111111111111);
        STAGE_N(2, 104w22222222222222222222);
        STAGE_N(3, 104w33333333333333333333);
        STAGE_N(4, 104w44444444444444444444);
        STAGE_N(5, 104w55555555555555555555);
    }

    apply {
        hashpipe();
    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16
        );
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
