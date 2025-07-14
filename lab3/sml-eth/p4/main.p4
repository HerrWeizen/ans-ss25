/*
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <core.p4>
#include <v1model.p4>
#define CHUNK_SIZE  4
#define NUM_WORKERS 8


typedef bit<9>  sw_port_t;   /*< Switch port */
typedef bit<48> mac_addr_t;  /*< MAC address */
enum bit<8> worker_type_t {FORWARD_ONLY = 0, SWITCH_ML = 1};  /*< Worker Type */
enum bit<16> ether_type_t {ETHTYPE_ARP = 0x0806, ETHTYPE_IP = 0x0800, ETHTYPE_SML = 0x080D}; /*< Ether types used to find SML package */

register<bit<32>>(1) sum0_register;
register<bit<32>>(1) sum1_register;
register<bit<32>>(1) sum2_register;
register<bit<32>>(1) sum3_register;
register<bit<8>>(1) presence_register;
register<bit<1>>(1) presence_register_set;

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>    ether_type;
}

header sml_t {
  worker_type_t workerType;
  bit<8> worker_rank;
  bit<32> val0;
  bit<32> val1;
  bit<32> val2;
  bit<32> val3;
}

struct headers {
    ethernet_t eth;
    sml_t      sml;
}

struct metadata { /* empty */ }

parser TheParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
  
  state start {
    transition parse_ethernet;
  }
  
  state parse_ethernet {
    packet.extract(hdr.eth);
    transition parse_sml;
  }
  
  state parse_sml {
    packet.extract(hdr.sml);
    transition accept;
  }
  
}

control TheIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

    bit<32> val0;
    bit<32> val1;
    bit<32> val2;
    bit<32> val3;
    bit<8> presence;
    bit<8> starting_presence = 0b11111111;
    bit<8> expected_presence = 0b11111111;
    bit<8> mask;
    bit<8> mask_gen = 1;
    bit<1> presence_register_altered;
 
    action multicast(bit<16> mgid) {
        standard_metadata.mcast_grp = mgid;
    }
    action l2_forward(sw_port_t port) {
        standard_metadata.egress_spec = port;
    }
    action drop() {
        mark_to_drop(standard_metadata);
    }

    table ethernet_table {
    key = {
      hdr.eth.dst_addr: exact;
    }
    actions = {
      l2_forward;
      multicast;
      drop;
      NoAction;
    }
    size = 1024;
    default_action = NoAction();
    }

    apply {
        if (hdr.sml.isValid()) {
            @atomic {
                presence_register_set.read(presence_register_altered,0);
                presence_register.read(presence,0);

                if (presence_register_altered == 0) {                                       /* The register has not yet been prepared */
                    
                    bit<NUM_WORKERS> lower = expected_presence[NUM_WORKERS-1:0];            /* get number of worker bits filled with 1 */
                    mask = (bit<8>)lower;                                                   /* fill 0 in front of the ones to extend to 8 bit */
                    starting_presence = expected_presence ^ mask;                           /* set updated_presence to 1..000 Where 000 represents expected messages from hosts */

                    /* current presence is in starting position */
                
                    presence_register_set.write(0, 1);
                }

            /* Read Currently Aggregated Values (Each Register: 1 Read / 0 Write)*/
                sum0_register.read(val0, 0);
                sum1_register.read(val1, 0);
                sum2_register.read(val2, 0);
                sum3_register.read(val3, 0);
            }


            /* Aggregate Chunk Values */
            log_msg("Starting new aggregation cycle: Initializing registers.");
            val0 = val0 + hdr.sml.val0;
            val1 = val1 + hdr.sml.val1;
            val2 = val2 + hdr.sml.val2;
            val3 = val3 + hdr.sml.val3;


            if (presence == 0) {                                        /* This has not been touched beforehand, meaning this is not the first packet of the current aggregation */
            presence = starting_presence;                               /* Set the presence to the above calculated starting position */ 
            }

            mask = 0;
            mask = mask_gen << hdr.sml.worker_rank;
            presence = presence ^ mask;

            if (presence ^ expected_presence != 0) {

                /* Store the updated Values inside the Register and drop the packet (Each Register:  1 Read / 1 Write)*/
                @atomic{
                    presence_register.write(0, presence);
                    sum0_register.write(0, val0);
                    sum1_register.write(0, val1);
                    sum2_register.write(0, val2);
                    sum3_register.write(0, val3);
                }
                drop();

            } else {
                
                /* Update Header Data */
                hdr.sml.val0 = val0;
                hdr.sml.val1 = val1;
                hdr.sml.val2 = val2;
                hdr.sml.val3 = val3;

                /* Send package to all Switches in MulticastGroup 1 */
                multicast(1);

                /* Reset All Registers (Each Register: 1 Read / 1 Write)*/
                @atomic{
                    sum0_register.write(0,0);
                    sum1_register.write(0,0);
                    sum2_register.write(0,0);
                    sum3_register.write(0,0);
                    presence_register_set.write(0,0);
                    presence_register.write(0, 0); 
                }
            }
        } else if (hdr.eth.isValid()) {
            ethernet_table.apply();
        } else {
            drop();
        }
    }
}

control TheEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    apply {}
}

control TheChecksumVerification(inout headers hdr, inout metadata meta) {
    apply {}
}

control TheChecksumComputation(inout headers  hdr, inout metadata meta) {
    apply {}
}

control TheDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.sml);
    }
}

V1Switch(
    TheParser(),
    TheChecksumVerification(),
    TheIngress(),
    TheEgress(),
    TheChecksumComputation(),
    TheDeparser()
) main;
