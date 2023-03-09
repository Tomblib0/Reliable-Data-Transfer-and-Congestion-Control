import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle
import time 
import math
from matplotlib import pyplot as plt
BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512*1024
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024
MAX_SENDING = 0

x = []
y = []
count = 0
cwnd = 1
congestion_mode = False
ssthresh = 64

config = None
ex_output_file = None
ex_received_chunk = dict()
check_time_exceeded_retansmition = []
peers_dict = {}
finish_downloading = False
#超时重传：需要知道 [from_addr, seq, time, pkt ]
#快速重传：需要知道 retry
#如果ack了： 删掉[from_addr, seq, time, pkt ]

def process_download(sock,chunkfile, outputfile):
    global ex_output_file
    global ex_received_chunk
    global finish_downloading
    ex_download_list = []
    ex_output_file = outputfile
    finish_downloading = False
    #Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()
    with open(chunkfile, 'r') as cf:
        #index, datahash_str = cf.readline().strip().split(" ")
        lines = cf.readlines()
        for line in lines:
            index, datahash_str = line.strip().split(" ")
            ex_download_list.append(datahash_str)
    for filename in ex_download_list:
        datahash_str = filename
        ex_received_chunk[datahash_str] = bytes()
        datahash = bytes.fromhex(datahash_str)
        download_hash = datahash
        # Step2: make WHOHAS pkt
        whohas_header = struct.pack("HBBHHII", socket.htons(52305),35, 0, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(download_hash)), socket.htonl(0), socket.htonl(0))
        whohas_pkt = whohas_header + download_hash
        # Step3: flooding whohas to all peers in peer list
        peer_list = config.peers
        for p in peer_list:
            if int(p[0]) != config.identity:
                sock.sendto(whohas_pkt, (p[1], int(p[2])))

def process_inbound_udp(sock):
    global ex_received_chunk
    global check_time_exceeded_retansmition
    global finish_downloading
    global cwnd
    global ssthresh
    global congestion_mode
    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type,hlen, plen, Seq, Ack= struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    
    if from_addr not in peers_dict.keys():
        peers_dict[from_addr] = []
        ex_sending_chunkhash = ''
        retry = {}
        packet_sended = []
        sending_to_me = ""
        expected_seq = 1
        peers_dict[from_addr].append(0)  # 0
        peers_dict[from_addr].append(0) # 1
        peers_dict[from_addr].append(0) # 2
        peers_dict[from_addr].append(ex_sending_chunkhash) # 3
        peers_dict[from_addr].append(retry) # 4
        peers_dict[from_addr].append(packet_sended) # 5
        peers_dict[from_addr].append(sending_to_me) # 6
        peers_dict[from_addr].append(expected_seq) # 7
    
    if Type == 0:
        # received an WHOHAS pkt
        # see what chunk the sender has
        whohas_chunk_hash = data[:20]
        # bytes to hex_str
        chunkhash_str = bytes.hex(whohas_chunk_hash)
        print(f"whohas: {chunkhash_str}, has: {list(config.haschunks.keys())}")
        if chunkhash_str in config.haschunks:
            # send back IHAVE pkt
            ihave_header = struct.pack("HBBHHII", socket.htons(52305), 35, 1, socket.htons(HEADER_LEN),
                                       socket.htons(HEADER_LEN + len(whohas_chunk_hash)), socket.htonl(0),
                                       socket.htonl(0))
            ihave_pkt = ihave_header + whohas_chunk_hash
            sock.sendto(ihave_pkt, from_addr)
    elif Type == 1:
        # received an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash = data[:20]
        if bytes.hex(get_chunk_hash) not in config.haschunks.keys():
            get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2 , socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(get_chunk_hash)), socket.htonl(0), socket.htonl(0))
            get_pkt = get_header+get_chunk_hash
            peers_dict[from_addr][6] = bytes.hex(get_chunk_hash)
            sock.sendto(get_pkt, from_addr)
            peers_dict[from_addr][7] = 1

    elif Type == 2:
        # received a GET pkt
        peers_dict[from_addr][3] = bytes.hex(data[:20])
        chunk_data = config.haschunks[peers_dict[from_addr][3]][:MAX_PAYLOAD]
        # send back DATA
        data_header = struct.pack("HBBHHII", socket.htons(52305),35, 3, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(chunk_data)), socket.htonl(1), 0)
        sock.sendto(data_header+chunk_data, from_addr)
        # start a timer
        peers_dict[from_addr][4][1] = 0       
        peers_dict[from_addr][5].append(1)
        check_time_exceeded_retansmition.append([from_addr, 1, time.time(), data_header+chunk_data])

    elif Type == 3:
        if socket.ntohl(Seq) == peers_dict[from_addr][7]:
            peers_dict[from_addr][7] += 1
            ex_received_chunk[peers_dict[from_addr][6]] += data
            # send back ACK
            ack_pkt = struct.pack("HBBHHII", socket.htons(52305),35,  4,socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),peers_dict[from_addr][7] , Seq)
            sock.sendto(ack_pkt, from_addr)
            
            if len(ex_received_chunk[peers_dict[from_addr][6]]) == CHUNK_DATA_SIZE:
                config.haschunks[peers_dict[from_addr][6]] = ex_received_chunk[peers_dict[from_addr][6]]
            # see if finished
            for files in ex_received_chunk.keys():
                if len(ex_received_chunk[files]) == CHUNK_DATA_SIZE:
                    finish_downloading = True
                else:
                    finish_downloading = False
                    break
            if finish_downloading:
                # finished downloading this chunkdata!
                # dump your received chunk to file in dict form using pickle
                with open(ex_output_file, "wb") as wf:
                    pickle.dump(ex_received_chunk, wf)
                print(f"GOT {ex_output_file}")
                # add to this peer's haschunk:
                # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
                 
        else:
            ack_pkt = struct.pack("HBBHHII", socket.htons(52305),35,  4,socket.htons(HEADER_LEN), socket.htons(HEADER_LEN), 0 , peers_dict[from_addr][7]-1)
            sock.sendto(ack_pkt, from_addr)
    elif Type == 4:
        global temp_ack
        # received an ACK pkt 
        ack_num = socket.ntohl(Ack)
        if ack_num in peers_dict[from_addr][5]:
            if not congestion_mode:
                if cwnd < ssthresh:
                    cwnd += 1
                else:
                    congestion_mode = True
            else:
                cwnd = cwnd + 1/cwnd
            temp_ack = ack_num
            peers_dict[from_addr][4][ack_num]+=1
            for lists in check_time_exceeded_retansmition:
                if lists[0] == from_addr and lists[1] == ack_num:
                    check_time_exceeded_retansmition.remove(lists)
                    break
        else:
            return
        if peers_dict[from_addr][4][ack_num] == 3:
            if not congestion_mode:
                congestion_mode = True
                ssthresh = max(math.floor(cwnd/2), 2)
            else:
                congestion_mode = False
                cwnd = 1
                ssthresh = max(math.floor(cwnd/2), 2)
            for lists in check_time_exceeded_retansmition:
                for index in peers_dict[from_addr][5]:
                    if lists[0] == from_addr and lists[1] == index:
                        check_time_exceeded_retansmition.remove(lists)
            packet_sended_num = 0
            peers_dict[from_addr][4].clear()
            peers_dict[from_addr][5].clear()
            while packet_sended_num < math.floor(cwnd):
                if (temp_ack)*MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                    break
                else:
                    left = (temp_ack) * MAX_PAYLOAD
                    right = min((temp_ack+1)*MAX_PAYLOAD, CHUNK_DATA_SIZE)
                    next_data = config.haschunks[peers_dict[from_addr][3]][left: right]
                    # send next data
                    data_header = struct.pack("HBBHHII", socket.htons(52305),35,  3, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(next_data)), 0)
                    sock.sendto(data_header+next_data, from_addr)
                    check_time_exceeded_retansmition.append([from_addr, temp_ack+1, time.time(), data_header+next_data])
                    peers_dict[from_addr][4][temp_ack+1] = 0
                    peers_dict[from_addr][5].append(temp_ack + 1)
                    packet_sended_num += 1
                    temp_ack += 1
        else:
            peers_dict[from_addr][5].remove(ack_num)
            if len(peers_dict[from_addr][5]) == 0:
                packet_sended_num = 0
                while packet_sended_num < math.floor(cwnd) :
                    if (temp_ack)*MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                        break
                    else:
                        left = (temp_ack) * MAX_PAYLOAD
                        right = min((temp_ack+1)*MAX_PAYLOAD, CHUNK_DATA_SIZE)
                        next_data = config.haschunks[peers_dict[from_addr][3]][left: right]
                        # send next data
                        data_header = struct.pack("HBBHHII", socket.htons(52305),35,  3, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(next_data)), socket.htonl(temp_ack+1), 0)
                        sock.sendto(data_header+next_data, from_addr)
                        check_time_exceeded_retansmition.append([from_addr, temp_ack+1, time.time(), data_header+next_data])
                        peers_dict[from_addr][4][temp_ack+1] = 0
                        peers_dict[from_addr][5].append(temp_ack + 1)
                        packet_sended_num += 1
                        temp_ack += 1
    elif Type == 5:
        pass
                
def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock ,chunkf, outf)
    else:
        pass


def peer_run(config):
    global peers_dict
    global x
    global y
    global count
    global congestion_mode
    global cwnd
    
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)
    try:
        while True:
            ready = select.select([sock, sys.stdin],[],[], 0.1)
            read_ready = ready[0]
            # x.append(count)
            # count += 1
            # y.append(cwnd)
            for lists in check_time_exceeded_retansmition:
                if time.time() - lists[2] > 1:
                    if not congestion_mode:
                        congestion_mode = True
                        ssthresh = max(math.floor(cwnd/2), 2)
                    else:
                        congestion_mode = False
                        cwnd = 1
                        ssthresh = max(math.floor(cwnd/2), 2)
                    sock.sendto(lists[3], lists[0])
                    check_time_exceeded_retansmition.append([lists[0], lists[1], time.time(), lists[3]])
                    check_time_exceeded_retansmition.remove(lists)
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period 
                pass
    except KeyboardInterrupt:
        pass
    finally:
        # plt.plot(x, y)
        # plt.savefig("test1.png")
        sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
