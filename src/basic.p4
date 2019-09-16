/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// TODO: Define metadata here
struct metadata {
    bit<104>    flowId;
    bit<32>     s1Index;
    bit<32>     s2Index;
    bit<104>    mKeyCarried;
    bit<32>     mCountCarried;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;
    udp_t       udp; 
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
	    transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4   : parse_ipv4;
            default     : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w7     : parse_tcp;
            8w17    : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}


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
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
	standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        if(hdr.ipv4.isValid()){
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
#define COUNTERS_PER_TABLE 1024
#define HASH_MIN 10w0
#define HASH_MAX 10w1023

// HashPipe implementation here (d=2)
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    // Register definition
    // Table 1
    register <bit<104>> (COUNTERS_PER_TABLE) s1FlowTracker;
    register <bit<32>> (COUNTERS_PER_TABLE) s1PacketCount;
    register <bit<1>> (COUNTERS_PER_TABLE) s1ValidBit;
    // Table 2
    register <bit<104>> (COUNTERS_PER_TABLE) s2FlowTracker;
    register <bit<32>> (COUNTERS_PER_TABLE) s2PacketCount;
    register <bit<1>> (COUNTERS_PER_TABLE) s2ValidBit;

    action extract_flow_id () {
        meta.flowId[31:0] = hdr.ipv4.srcAddr;
        meta.flowId[63:32] = hdr.ipv4.dstAddr;
        meta.flowId[71:64] = hdr.ipv4.protocol;
        
        if(hdr.tcp.isValid()) {
            meta.flowId[87:72] = hdr.tcp.srcPort;
            meta.flowId[103:88] = hdr.tcp.dstPort;
        }

        if(hdr.udp.isValid()) {
            meta.flowId[87:72] = hdr.udp.srcPort;
            meta.flowId[103:88] = hdr.udp.dstPort;
        }
    }

    action compute_index () {
        // different hash functions used
        hash(
            meta.s1Index, 
            HashAlgorithm.crc16, 
            HASH_MIN, 
            {
                meta.flowId
            },
            HASH_MAX
        );
        
        hash(
            meta.s2Index, 
            HashAlgorithm.crc32, 
            HASH_MIN, 
            {
                meta.flowId
            },
            HASH_MAX
        );
    }

    // variable declarations, should they be here?
    bit<104>  mDiff;
    bit<32>   mIndex;

    bit<104> mKeyToWrite;
    bit<32>  mCountToWrite;
    bit<1>   mBitToWrite;

    bit<104> mKeyTable;
    bit<32>  mCountTable;
    bit<1>   mValid;

    // First table stage
    action s1Action () {
        meta.mKeyCarried = meta.flowId;
        meta.mCountCarried = 1;
        mIndex = meta.s1Index;
        mDiff = 0;

        // read the key value at that location
        s1FlowTracker.read(mKeyTable, mIndex);
        s1PacketCount.read(mCountTable, mIndex);
        s1ValidBit.read(mValid, mIndex);
        
        // always insert at first stage
        mKeyToWrite = meta.mKeyCarried;
        mCountToWrite = meta.mCountCarried;
        mBitToWrite = 1;

        if(mValid == 1) {
            // check whether they are different
            mDiff = mKeyTable - meta.mKeyCarried;
            mCountToWrite = (mDiff == 0) ? mCountTable + 1 : mCountToWrite;
        } 

        // update hash table
        s1FlowTracker.write(mIndex, mKeyToWrite);
        s1PacketCount.write(mIndex, mCountToWrite);
        s1ValidBit.write(mIndex, mBitToWrite);

        // update metadata carried to the next table stage
        meta.mKeyCarried = (mDiff == 0) ? 0 : mKeyTable;
        meta.mCountCarried = (mDiff == 0) ? 0 : mCountTable;
    }

    //WSecond table stage
    action s2Action () {
        // mKeyCarried, mCountCarried is set
        mIndex = meta.s2Index;
        mDiff = 0;

        mKeyToWrite = 0;
        mCountToWrite = 0;
        mBitToWrite = 0;
        
        // read the key value for that location
        s2FlowTracker.read(mKeyTable, mIndex);
        s2PacketCount.read(mCountTable, mIndex);
        s2ValidBit.read(mValid, mIndex);

        // if empty
        if (mValid != 1) {
            mDiff = 1;
            mKeyToWrite = meta.mKeyCarried;
            mCountToWrite = meta.mCountCarried;
            mBitToWrite = 1;
        } else {
            // compare the values
            if (meta.mCountCarried > mCountTable) {
                // time to evict
                mDiff = 1;
                mKeyToWrite = meta.mKeyCarried;
                mCountToWrite = meta.mCountCarried;
                mBitToWrite = 1;
            }
        }       

        // no eviction, maintain current key, value, and metadata
        if (mDiff ==0) {
            mKeyToWrite = mKeyTable;
            mCountToWrite = mCountTable;
            mBitToWrite = mValid;
        } else {
            // eviction occurs, have to update metadata
            meta.mKeyCarried = mKeyTable;
            meta.mCountCarried = mCountTable;
        }

        // update hash tables
        s2FlowTracker.write(mIndex, mKeyToWrite);
        s2PacketCount.write(mIndex, mCountToWrite);
        s2ValidBit.write(mIndex, mBitToWrite);
    }

    table stage1 {
        actions = {
            s1Action();
        }
        default_action = s1Action();
    }

    table stage2 {
        actions = {
            s2Action();
        }
        default_action = s2Action();
    }

    apply {
        extract_flow_id();
        compute_index();

        stage1.apply();
        stage2.apply();
    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
	packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4);
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
