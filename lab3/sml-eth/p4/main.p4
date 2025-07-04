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

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <core.p4>
#include <v1model.p4>
#include "numworkers.p4"
#define CHUNK_SIZE 4

typedef bit<9>  sw_port_t;   /*< Switch port */
typedef bit<48> mac_addr_t;  /*< MAC address */
enum bit<1> worker_type_t {FORWARD_ONLY = 0, SWITCH_ML = 1}  /*< Worker Type */
enum bit<16> ether_type_t {ETHTYPE_ARP = 0x0806, ETHTYPE_IP = 0x0800, ETHTYPE_SML = 0x080D} /*< Ether types used to find SML package */

header ethernet_t {
  mac_addr_t dstAddr;
  mac_addr_t srcAddr;
  ether_type_t etherType;
}

header sml_t {
  worker_type workerType
  bit<16> worker_rank;
  bit<32> val0;
  bit<32> val1;
  bit<32> val2;
  bit<32> val3;
}

struct headers {
  ethernet_t eth;
  sml_t sml;
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
    packet.etract(hdr.sml)
    transition accept
  }
  
}

control TheIngress(inout headers hdr,inout metadata meta, inout standard_metadata_t standard_metadata) {

  register<bit<8>>(1) pkt_counter;
  register<bit<32>>(4) sum_register;

  table ethernet_table {
    key = {
      hdr.eth.dstAddr: exact;
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

  action count_packet() {
    bit<4> count;
    pkt_counter.read(count,0)
    count = count +1
    pkt_counter.write(0,count)
  }

  action reset_pkt_counter() {
    bit<4> count;
    count = 0;
    pkt_counter.write(0, count)
  }

  action update_sum_register() {
    bit<32> current_val0;
    bit<32> current_val1;
    bit<32> current_val2;
    bit<32> current_val3;

    sum_register.read(current_val0, 0)
    sum_register.read(current_val1, 1)
    sum_register.read(current_val2, 2)
    sum_register.read(current_val3, 3)

    current_val0 = current_val0 + hdr.sml.val0
    current_val1 = current_val1 + hdr.sml.val1
    current_val2 = current_val2 + hdr.sml.val2
    current_val3 = current_val3 + hdr.sml.val3

    sum_register.write(0, current_val0)
    sum_register.write(1, current_val1)
    sum_register.write(2, current_val2)
    sum_register.write(3, current_val3)
  }

  action set_sml_values() {
    bit<32> current_val0;
    bit<32> current_val1;
    bit<32> current_val2;
    bit<32> current_val3;

    sum_register.read(current_val0, 0);
    sum_register.read(current_val1, 1);
    sum_register.read(current_val2, 2);
    sum_register.read(current_val3, 3);

    hdr.sml.val0 = current_val0;
    hdr.sml.val1 = current_val1;
    hdr.sml.val2 = current_val2;
    hdr.sml.val3 = current_val3;
  }

  action reset_sum_register() {
    bit<32> zero;
    zero = 0;
    sum_register.write(0, zero)
    sum_register.write(1, zero)
    sum_register.write(2, zero)
    sum_register.write(3, zero)
  }
  action drop() {
    mark_to_drop(standard_metadata);
  }

  action l2_forward(sw_port_t port) {
    standard_metadata.egress_spec = port;
  }

  action multicast(bit<16> mgid) {
    standard_metadata.mcast_grp = mgid;
  }

  apply{
    if(hdr.eth.etherType == ether_type_t.ETHTYPE_SML){
      if(hdr.sml.isValid()){
        count_packet();
        update_sum_register();
        bit<4> count;
        pkt_counter.read(count, 0);
        if(count == NUMBER_WORKES) {
          set_sml_values();
          reset_pkt_counter();
          reset_sum_register();
          multicast(1);
        } else {
          drop()
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
  apply {
    /* TODO: Implement me (if needed) */
  }
}

control TheChecksumVerification(inout headers hdr, inout metadata meta) {
  apply {
    /* TODO: Implement me (if needed) */
  }
}

control TheChecksumComputation(inout headers  hdr, inout metadata meta) {
  apply {
    /* TODO: Implement me (if needed) */
  }
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
