import sys
import click
import pyshark
import os
import subprocess
import datetime


def list_interfaces():
    tsharkCall = '"' + os.environ["ProgramFiles"] + '/Wireshark/tshark.exe"' + " -D " + os.getcwd()
    print("START")
    proc = subprocess.check_output(tsharkCall, shell=True)  # Note tshark must be in $PATH
    decoded = proc.decode('ascii')
    print(type(decoded))
    interfaces = decoded.splitlines()
    print(type(interfaces))
    # print(interfaces)
    for interface in interfaces:
        print(interface)


def get_ip_version(packet):
    for layer in packet.layers:
        if layer._layer_name == 'ip':
            return 4
        elif layer._layer_name == 'ipv6':
            return 6

def dump_packets(capture):
    i = 1
    for packet in capture:
        eth = eth_packets(packet)
        print(eth)
        if packet.transport_layer == 'TCP':
            tcp = tcp_packets(packet)
            print(tcp)
            ip = None
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip = packet.ip
            elif ip_version == 6:
                ip = packet.ipv6

            time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print("\n--------- COL INFO ---------")
            col_dict = {'Time': time_stamp, 'Source IP': ip.src, 'Dest. IP': ip.dst, 'Protocol': packet.transport_layer,
                        'Source MAC': packet.eth.src, 'Dest. MAC' : packet.eth.dst,
                        'Source Port': packet.tcp.srcport, 'Dest. Port': packet.tcp.dstport
                        }
            print(col_dict)
            if packet.highest_layer == 'HTTP':

                http = http_packets(packet)
                print(http)

            #return col_dict
        elif packet.transport_layer == 'UDP':
            udp = udp_packets(packet)
            print(udp)
            ip = None
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip = packet.ip
            elif ip_version == 6:
                ip = packet.ipv6
            time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print("\n--------- COL INFO ---------")
            col_dict = {'Time': time_stamp, 'Source IP': ip.src, 'Dest. IP': ip.dst, 'Protocol': packet.transport_layer,
                        'Source MAC': packet.eth.src, 'Dest. MAC': packet.eth.dst,
                        'Source Port': packet.udp.srcport, 'Dest. Port': packet.udp.dstport
                        }
            print(col_dict)
            if packet.highest_layer == 'HTTP':

                http = http_packets(packet)
                print(http)

        i += 1

def eth_packets(packet):
    print("\n---------ETH INFO ----------")
    eth_type = {
        '0x0800': 'Internet Protocol version 4', '0x0806': 'Address Resolution Protocol (ARP)', '0x0842': 'Wake-on-LAN',
        '0x8035': 'Reverse Address Resolution Protocol (RARP)',
        '0x8100': 'VLAN-tagged frame (IEEE 802.1Q) & Shortest Path Bridging IEEE 802.1aq',
        '0x86DD': 'Internet Protocol version 6',
        '0x8808': 'Ethernet flow control', '0x8809': 'Slow Protocols (IEEE 802.3)',
        '0x8863': 'PPPoE Discovery Stage',
        '0x8864': 'PPPoE Session Stage', '0x8870': 'Jumbo Frames',
        '0x888E': 'EAP over LAN (IEEE 802.1X)',
        '0x889A': 'HyperSCSI (SCSI over Ethernet)', '0x88A8': 'Provider Bridging (IEEE 802.1ad)'
                                                              '& Shortest Path Bridging IEEE 802.1aq',
        '0x88CC': 'Link Layer Discovery Protocol (LLDP)', '0x88E5': 'MAC Security (IEEE 802.1ae)',
        '0x88F7': 'Precision Time Protocol (IEEE 1558)', '0x8906': 'Fiber Channel over Ethernet(FCOE)',
        '0x8914': 'FCoE Initialization Protocol'
    }

    eth_info = {
        'Address': packet.eth.addr.upper(),
        'Source Address': packet.eth.src.upper(),
        'Destination Address': packet.eth.dst.upper(),
        'Protocol': packet.eth.layer_name.upper(),
        #'Padding': packet.eth.padding,
        'Type': packet.eth.type
    }
    return eth_info


def tcp_packets(packet):
    print("\n---------TCP INFO ----------")
    tcp_info = {'Source Port': packet.tcp.srcport, 'Dest. Port': packet.tcp.dstport, 'Sequence Number': packet.tcp.seq,
                'Acknowledgement': packet.tcp.ack, 'Data Offset': 'N/A', 'Reserve': 'N/A',
                'Flags': {'CWR': packet.tcp.flags_cwr, 'ECN': packet.tcp.flags_ecn, 'URG': packet.tcp.flags_urg,
                          'ACK': packet.tcp.flags_ack, 'PSH': packet.tcp.flags_push, 'RST': packet.tcp.flags_reset,
                          'SYN': packet.tcp.flags_syn, 'FIN': packet.tcp.flags_fin
                          },
                'Window Size': packet.tcp.window_size, 'Window Size Value': packet.tcp.window_size_value,
                'Header Length': packet.tcp.hdr_len, 'Protocol': packet.tcp.layer_name.upper()
                , 'Checksum': packet.tcp.checksum, 'Checksum Status': packet.tcp.checksum_status, 'Urgent Pointer': packet.tcp.urgent_pointer
                #, 'Segment Data': packet.tcp.segment_data
                }  # tcp_dict
    return tcp_info


def udp_packets(packet):
    print("\n---------UDP INFO ----------")
    udp_info = {'Source Port': packet.udp.srcport, 'Dest. Port': packet.udp.dstport, 'Protocol': packet.udp.layer_name.upper(),
                'Length': packet.udp.length, 'Checksum': packet.udp.checksum, 'Checksum Status': packet.udp.checksum_status
    }
    return udp_info

def http_packets(packet):
    print("\n---------HTTP INFO ----------")
    http_info = {
        'Connection': packet.http.connection,
        'Protocol': packet.http.layer_name.upper(),
        'Request Version': packet.http.request_version,
        'Request Method': packet.http.request_method,
        'Request Number': packet.http.request_number
    }
    return http_info

def main(file):

    node = None
    capture = None
    capture = pyshark.FileCapture(file)
    if node == None:
        dump_packets(capture)



if __name__ == '__main__':
    main(file="test_http.pcap")