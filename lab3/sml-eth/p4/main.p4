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
#define NUM_WORKERS 2

typedef bit<9>  sw_port_t;   /*< Switch port */
typedef bit<48> mac_addr_t;  /*< MAC address */
enum bit<8> worker_type_t {FORWARD_ONLY = 0, SWITCH_ML = 1};  /*< Worker Type */
enum bit<16> ether_type_t {ETHTYPE_ARP = 0x0806, ETHTYPE_IP = 0x0800, ETHTYPE_SML = 0x080D}; /*< Ether types used to find SML package */

register<bit<8>>(1) pkt_counter;
register<bit<32>>(1) sum0_register;
register<bit<32>>(1) sum1_register;
register<bit<32>>(1) sum2_register;
register<bit<32>>(1) sum3_register;

header ethernet_t {
  mac_addr_t dstAddr;
  mac_addr_t srcAddr;
  ether_type_t etherType;
}

header sml_t {
  worker_type_t workerType;
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
      transition select(hdr.eth.etherType) {
          ether_type_t.ETHTYPE_SML: parse_sml;
          default: reject;
      }
  }
  
  state parse_sml {
    packet.extract(hdr.sml);
    transition accept;
  }
  
}

control AggregateAndCheck(
    in headers hdr,
    inout register<bit<8>> pkt_counter,
    inout register<bit<32>> sum0_register,
    inout register<bit<32>> sum1_register,
    inout register<bit<32>> sum2_register,
    inout register<bit<32>> sum3_register,
    out bit<8> count_result
) {
  apply {
    bit<8> count;
    bit<32> val0, val1, val2, val3;

    @atomic {
      pkt_counter.read(count, 0);
      count = count + 1;
      pkt_counter.write(0, count);

      sum0_register.read(val0, 0);
      sum1_register.read(val1, 0);
      sum2_register.read(val2, 0);
      sum3_register.read(val3, 0);

      val0 = val0 + hdr.sml.val0;
      val1 = val1 + hdr.sml.val1;
      val2 = val2 + hdr.sml.val2;
      val3 = val3 + hdr.sml.val3;

      sum0_register.write(0, val0);
      sum1_register.write(0, val1);
      sum2_register.write(0, val2);
      sum3_register.write(0, val3);
    }

    count_result = count;
  }
}

control AtomicReset32(inout register<bit<32>> register) {
  apply {
    @atomic {
      bit<32> zero = 0;
      register.write(0, zero);
    }
  }
}

control AtomicReset8(inout register<bit<8>> register) {
  apply {
    @atomic {
      bit<8> zero = 0;
      register.write(0, zero);
    }
  }
}

control SetSMLHeaderValues(inout headers hdr) {
  apply {
    bit<32> val0, val1, val2, val3;

    @atomic {
      sum0_register.read(val0, 0);
      sum1_register.read(val1, 0);
      sum2_register.read(val2, 0);
      sum3_register.read(val3, 0);
    }

    hdr.sml.val0 = val0;
    hdr.sml.val1 = val1;
    hdr.sml.val2 = val2;
    hdr.sml.val3 = val3;
  }
}

control TheIngress(inout headers hdr,inout metadata meta, inout standard_metadata_t standard_metadata) {
  
  AtomicReset32() reset_32;
  AtomicReset8() reset_8;
  AggregateAndCheck() aggregate_and_check;
  SetSMLHeaderValues() set_sml_header_values;

  action drop() {
    mark_to_drop(standard_metadata);
  }

  action l2_forward(sw_port_t port) {
    standard_metadata.egress_spec = port;
  }

  action multicast(bit<16> mgid) {
    standard_metadata.mcast_grp = mgid;
  }
  
  action reset_all_registers() {
    reset_32.apply(sum0_register);
    reset_32.apply(sum1_register);
    reset_32.apply(sum2_register);
    reset_32.apply(sum3_register);
    reset_8.apply(pkt_counter);
  }

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

  apply{
    if(hdr.eth.etherType == ether_type_t.ETHTYPE_SML){
      if(hdr.sml.isValid()){
        bit<8> count;
        aggregate_and_check.apply(hdr, pkt_counter, sum0_register, sum1_register, sum2_register, sum3_register, count);
        if(count == NUM_WORKERS) {
          set_sml_header_values(hdr);
          reset_all_registers();
          multicast(1);
        } else {
          drop();
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
