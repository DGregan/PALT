import datetime
import os
import subprocess
from subprocess import call
import pyshark
import datetime
import sys


def get_interfaces():
    tsharkCall = '"' +os.environ["ProgramFiles"]+'/Wireshark/tshark.exe"' +" -D "+os.getcwd()
    print("START")

    proc = subprocess.check_output(tsharkCall, shell=True)  # Note tshark must be in $PATH
    decoded = proc.decode('ascii')
    print(type(decoded))
    interfaces = decoded.splitlines()
    print(type(interfaces))
    #print(interfaces)
    for interface in interfaces:
        print(interface)
    return interfaces




def get_ip_version(packet):
    for layer in packet.layers:
        if layer._layer_name == 'ip':
            return 4
        elif layer._layer_name == 'ipv6':
            return 6


def table_packets(capture):
    for packet in capture:
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
                        'Source MAC' : packet.eth.src, 'Dest. MAC' : packet.eth.dst,
                        'Source Port' : packet.tcp.srcport, 'Dest. Port': packet.tcp.dstport
                        }
            print(col_dict)
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


'''
                'Flags': {'CWR': packet.tcp.flags.cwr, 'ECN': packet.tcp.flags.ecn, 'URG': packet.tcp.flags.urg,
                          'ACK': packet.tcp.flags.ack, 'PSH': packet.tcp.flags.psh,'RST': packet.tcp.flags.reset,
                          'SYN': packet.tcp.flags.syn, 'FIN': packet.tcp.flags.fin
                        },
                '''


def tcp_packets(packet):
    print("\n---------TCP INFO ----------")
    tcp_info = {'Source Port': packet.tcp.srcport, 'Dest. Port': packet.tcp.dstport, 'Sequence Number': packet.tcp.seq,
                'Acknowledgement': packet.tcp.ack, 'Data Offset': 'N/A', 'Reserve': 'N/A',

                'Window Size': packet.tcp.window_size, 'Window Size Value': packet.tcp.window_size_value,
                'Header Length': packet.tcp.hdr_len, 'Protocol': packet.tcp.layer_name.upper()
                , 'Checksum': packet.tcp.checksum, 'Checksum Status': packet.tcp.checksum_status, 'Urgent Pointer': packet.tcp.urgent_pointer
                #, 'Segment Data': packet.tcp.segment_data
                }  # tcp_dict
    return tcp_info


def udp_packets(packet):
    print("\n---------UDP INFO ----------")
    udp_info = {'Source Port': packet.udp.srcport, 'Dest. Port': packet.udp.dstport, 'Length': packet.udp.length
        #,'Checksum': packet.udp.checksum, 'Checksum Coverage': packet.udp.checksum_coverage,
         #       'Checksum Status': packet.udp.checksum_stats

    }
    return udp_info


interfaces = get_interfaces()
print(type(interfaces))
print("CHOSEN INTERFACE", interfaces[0])
if 'WiFi' in str(interfaces[0]):
    int_type = 'WiFi'

capture = pyshark.LiveCapture(int_type)
#dump_packets(capture)
table_packets(capture)
print("END")

