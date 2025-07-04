"""
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
 """

from lib.gen import GenInts, GenMultipleOfInRange
from lib.test import CreateTestData, RunIntTest
from lib.worker import *
from scapy.all import Packet, sendp, sniff, BitEnumField, ShortField, FieldListField, Ether
from enum import Enum
import os


NUM_ITER   = 1
CHUNK_SIZE = 4 

class WorkerType(Enum):
    FORWARD_ONLY = 0
    SWITCH_ONLY = 1

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        BitEnumField("workerType", 0, 1, {
            0: "FORWARD_ONLY",
            1: "SWITCH_ML"
        }),
        ShortField("worker_rank", 0),
        FieldListField("vals", [0]*CHUNK_SIZE, IntField("", 0), count=CHUNK_SIZE)
    ]

bind_layers(Ether, SwitchML, type=0x080D)

def send(packet, iface):
    sendp(packet, iface=iface)
    return True

def receive_sml_response(iface):
    packet = sniff(count=1, iface=iface, prn=lambda x: x.show())
    return packet[0]

def AllReduce(iface, rank, data, result):
    """
    Perform in-network all-reduce over ethernet

    :param str  iface: the ethernet interface used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int]  res: the output vector

    This function is blocking, i.e. only returns with a result or error
    """
    chunk_start = 0
    vector_length = len(data)
    result = [0]*vector_length

    while chunk_start < vector_length:
        chunk = data[chunk_start:chunk_start+CHUNK_SIZE]
        packet_out = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x080D) / SwitchML(workerType=1, worker_rank=rank, vals=chunk)
        send(packet_out, iface)
        packet_in = receive_sml_response(iface)
        result[chunk_start:chunk_start+CHUNK_SIZE] = packet_in[SwitchML].vals

def generate_p4_chunk_size(filename="chunksize.p4"):
    path = os.path.join("p4", filename)
    with open(path, "w") as f:
        f.write(f"#define CHUNK_SIZE {CHUNK_SIZE}")
        
def main():
    generate_p4_chunk_size()
    iface = 'eth0'
    rank = GetRankOrExit()
    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(2, 2048, 2 * CHUNK_SIZE) # You may want to 'fix' num_elem for debugging
        data_out = GenInts(num_elem)
        data_in = GenInts(num_elem, 0)
        CreateTestData("eth-iter-%d" % i, rank, data_out)
        AllReduce(iface, rank, data_out, data_in)
        RunIntTest("eth-iter-%d" % i, rank, data_in, True)
    Log("Done")

if __name__ == '__main__':
    main()
