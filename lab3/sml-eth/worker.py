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
from scapy.all import Packet, Ether, srp1, bind_layers, BitField, ShortField, IntField, FieldListField, get_if_hwaddr, ByteEnumField

NUM_ITER   = 1
CHUNK_SIZE = 4

ETHERTYPE_SWITCHML = 0x080D

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        ByteEnumField("workerType", 0, {
            0: "FORWARD_ONLY",
            1: "SWITCH_ML"
        }),
        BitField("worker_rank", 0, 8),
        BitField("val0", 0, 32),
        BitField("val1", 0, 32),
        BitField("val2", 0, 32),
        BitField("val3", 0, 32)
    ]

bind_layers(Ether, SwitchML, type=ETHERTYPE_SWITCHML)

def AllReduce(iface, rank, data, result):
    """
    Perform in-network all-reduce over ethernet

    :param str  iface: the ethernet interface used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int]  res: the output vector (this will be populated)

    This function is blocking, i.e. only returns with a result or error
    """
    mac = get_if_hwaddr(iface)
    chunk_start = 0
    vector_length = len(data)
    aggregated_chunk = [0] * 4
    while chunk_start < vector_length:
        chunk_to_send = data[chunk_start : chunk_start + CHUNK_SIZE]
        
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=mac, type=ETHERTYPE_SWITCHML) / SwitchML(workerType="SWITCH_ML", worker_rank=rank, val0 = chunk_to_send[0], val1 = chunk_to_send[1], val2 = chunk_to_send[2], val3 = chunk_to_send[3])
        Log(f"Chunk Sent: {chunk_to_send}")

        response = srp1(pkt, iface=iface, timeout=10, verbose=False)

        if response and response.haslayer(SwitchML):
            for index, value in enumerate(aggregated_chunk):
                aggregated_chunk[index] = 0

            aggregated_chunk[0] = response[SwitchML].val0
            aggregated_chunk[1] = response[SwitchML].val1
            aggregated_chunk[2] = response[SwitchML].val2
            aggregated_chunk[3] = response[SwitchML].val3

            Log(f"Aggregated Chunk: {aggregated_chunk}")
            result[chunk_start : chunk_start + CHUNK_SIZE] = aggregated_chunk

        chunk_start += CHUNK_SIZE

    return result

def main():
    iface = 'eth0'
    rank = GetRankOrExit()
    Log("Started...")
    for i in range(NUM_ITER):
        Log(f"Iteration {i}")
        num_elem = GenMultipleOfInRange(CHUNK_SIZE, 2048, CHUNK_SIZE)
        data_out = GenInts(num_elem)
        Log(f"Data Out: {data_out}")
        data_in = [0] * num_elem
        CreateTestData("eth-iter-%d" % i, rank, data_out)
        data_in = AllReduce(iface, rank, data_out, data_in)
        Log(f"Data In: {data_in}")
        RunIntTest("eth-iter-%d" % i, rank, data_in, True)
    Log("Done")

if __name__ == '__main__':
    main()
