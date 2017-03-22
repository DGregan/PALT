import datetime
import os
import requests
from subprocess import check_output
import pyshark
import datetime
import sys


def get_interfaces():
    tsharkCall = '"' +os.environ["ProgramFiles"]+'/Wireshark/tshark.exe"' +" -D "+os.getcwd()
    proc = check_output(tsharkCall, shell=True)  # Note tshark must be in $PATH
    decoded = proc.decode('ascii')
    interfaces = decoded.splitlines()
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
    col_dict = []
    for packet in capture:
        if packet.transport_layer == 'TCP':
            ip = None
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip = packet.ip
            elif ip_version == 6:
                ip = packet.ipv6

            time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
           # print("\n--------- COL INFO ---------")
            tcp_dict = {'Time': time_stamp, 'Source IP': ip.src, 'Dest. IP': ip.dst, 'Protocol': packet.transport_layer,
                        'Source MAC': packet.eth.src, 'Dest. MAC': packet.eth.dst,
                        'Source Port': packet.tcp.srcport, 'Dest. Port': packet.tcp.dstport
                        }
            col_dict.append(tcp_dict)

        elif packet.transport_layer == 'UDP':
            #udp = parse_udp(packet)
            #print(udp)
            ip = None
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip = packet.ip
            elif ip_version == 6:
                ip = packet.ipv6
            time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
           # print("\n--------- COL INFO ---------")
            udp_dict = {'Time': time_stamp, 'Source IP': ip.src.upper(), 'Dest. IP': ip.dst.upper(),
                        'Protocol': packet.transport_layer, 'Source MAC': packet.eth.src.upper(),
                        'Dest. MAC': packet.eth.dst.upper(),
                        'Source Port': packet.udp.srcport, 'Dest. Port': packet.udp.dstport
                        }
            col_dict.append(udp_dict)
    return col_dict


def packet_dump(capture):
    try:
        all_ip, all_eth, all_table, all_tcp, all_udp, all_http = ([] for i in range(6))
        packet_info = []
        for packet in capture:
            eth_info = parse_eth(packet)
            all_eth.append(eth_info)
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip_info = parse_ip(packet, ip_version)
                all_ip.append(ip_info)
               # TODO - IF NONE ITERABLE STILL CONTINUES, USE TABLE_PACKETS AS IT SEEMS TO SKIP NONE VALUES
                table_info = (parse_table(packet, ip_version))
                all_table.append(table_info)
                #icmp_info = parse_icmp(packet)
                #print(icmp_info)

            elif ip_version == 6:
                ip_info = parse_ip(packet, ip_version)
                all_ip.append(ip_info)
                table_info = (parse_table(packet, ip_version))
                all_table.append(table_info)

            if packet.transport_layer == 'TCP':
                tcp_info = parse_tcp(packet)
                all_tcp.append(tcp_info)
                if packet.highest_layer == 'HTTP':
                    http_info = parse_http(packet)
                    all_http.append(http_info)
                    return all_eth, all_ip, all_table, all_tcp, all_udp, all_http

            elif packet.transport_layer == 'UDP':
                udp_info = parse_udp(packet)
                all_udp.append(udp_info)
                if packet.highest_layer == 'HTTP':
                    http_info = parse_http(packet)
                    all_http.append(http_info)
                    return all_eth, all_ip, all_table, all_tcp, all_udp, all_http



            '''
            elif packet.transport_layer == None:
                table_info = parse_table(packet, ip_version)
                #print('Transport Layer = None')
                #print(table_info)
            #print("\n***************  ***************")
            '''

        return all_eth, all_ip, all_table, all_tcp, all_udp

    except OSError as error:
        print("OS Error: {0}".format(error))
    except ValueError:
        print("TABLE INFO CAPTURE ERROR")
    except:
        print("Unexpected Error", sys.exc_info()[0])
        raise


def parse_table(packet, ip_version):
    try:
        # TODO - ERROR CHECKING IF 'NONE' VALUES ARE CAUGHT
        #print("\n---------TABLE INFO ----------")
        if ip_version == 4:
            if packet.transport_layer == 'TCP':
                time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                table_dict = {
                    'Time': time_stamp, 'Source IP': packet.ip.src.upper(), 'Dest. IP': packet.ip.dst.upper(),
                    'Protocol': packet.transport_layer,
                    'Source MAC': packet.eth.src.upper(), 'Dest. MAC': packet.eth.dst.upper(),
                    'Source Port': packet.tcp.srcport, 'Dest. Port': packet.tcp.dstport
                }
                return table_dict
            elif packet.transport_layer == 'UDP':
                time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if packet.udp.srcport == None:
                    packet.udp.srcport = 'N/A'
                table_dict = {
                    'Time': time_stamp, 'Source IP': packet.ip.src.upper(), 'Dest. IP': packet.ip.dst.upper(),
                    'Protocol': packet.transport_layer,
                    'Source MAC': packet.eth.src.upper(), 'Dest. MAC': packet.eth.dst.upper(),
                    'Source Port': packet.udp.srcport, 'Dest. Port': packet.udp.dstport
                }
                #col_dict.append(table_dict)
                return table_dict
        elif ip_version == 6:
            if packet.transport_layer == 'TCP':
                time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                table_dict = {
                    'Time': time_stamp, 'Source IP': packet.ipv6.src.upper(), 'Dest. IP': packet.ipv6.dst.upper(),
                    'Protocol': packet.transport_layer,
                    'Source MAC': packet.eth.src.upper(), 'Dest. MAC': packet.eth.dst.upper(),
                    'Source Port': packet.tcp.srcport, 'Dest. Port': packet.tcp.dstport
                }
                return table_dict
            elif packet.transport_layer == 'UDP':
                time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                table_dict = {
                    'Time': time_stamp, 'Source IP': packet.ipv6.src.upper(), 'Dest. IP': packet.ipv6.dst.upper(),
                    'Protocol': packet.transport_layer,
                    'Source MAC': packet.eth.src.upper(), 'Dest. MAC': packet.eth.dst.upper(),
                    'Source Port': packet.udp.srcport, 'Dest. Port': packet.udp.dstport
                }
                return table_dict

    except OSError as error:
        print("OS Error: {0}".format(error))
    except ValueError:
        print("TABLE INFO CAPTURE ERROR")
    except:
        print("Unexpected Error", sys.exc_info()[0])
        raise


def parse_eth(packet):
    try:
        #print("\n---------ETH INFO ----------")
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
            'Type Code': packet.eth.type
        }

        # Check eth_info['Type Code'] against eth_type for a match
        # If match, add 'english' of type code to eth_info
        cap_ethertype = eth_info['Type Code']
        sliced_ethertype = cap_ethertype[6:]
        sliced_ethertype = '0x' + sliced_ethertype.upper()
        print("SLICED ETHER", sliced_ethertype)
        if sliced_ethertype in eth_type:
            eth_info['Type Result'] = eth_type[sliced_ethertype]
        else:
            pass
        return eth_info
    except OSError as error:
        print("OS Error: {0}".format(error))
    except ValueError:
        print("ETH CAPTURE ERROR")
    except:
        print("Unexpected Error", sys.exc_info()[0])
        raise


def parse_ip(packet, ip_version):
    try:
        protocol_num = {
            '4': 'IPv4 protocol recognised.',
            '6': 'TCP protocol recognised.',
            '17': 'UDP protocol recognised.',
            '41': 'IPv6 protocol recognised.',
        }

        if ip_version == 4:
            #print("\n---------IPv4 INFO ----------")
            ip_info = {
                'Version': packet.ip.version, 'Header Length': packet.ip.hdr_len + " bytes", 'Type of Service': 'N/A',
                'Total Length': packet.ip.len + " bytes", 'Identification': packet.ip.id, 'Protocol': packet.ip.layer_name.upper(),
                'Flags': {'RB': packet.ip.flags_rb, 'D': packet.ip.flags_df, 'M': packet.ip.flags_mf},
                'Fragment Offset': packet.ip.frag_offset, 'Time To Live': packet.ip.ttl, 'Protocol Number': packet.ip.proto.upper(),
                'Header Checksum': packet.ip.checksum, 'Checksum Status': packet.ip.checksum_status,
                'Source Address': packet.ip.src, 'Destination Address': packet.ip.dst
            }

            # Check ip_info['Protocol Number'] against eth_type for a match
            # If match, add 'english' of type code to eth_info
            cap_proto_num = ip_info['Protocol Number']
            print("PROTO NUM", cap_proto_num)
            if cap_proto_num in protocol_num:
                ip_info['Protocol Number Result'] = protocol_num[cap_proto_num]
            else:
                pass

            return ip_info
        elif ip_version == 6:
            #print("\n---------IPv6 INFO ----------")
            ip_info = {
                'Version': ip_version,
                'Traffic Class': packet.ipv6.tclass,
                'Traffic Class DSCP': packet.ipv6.tclass_dscp,
                'Traffic Class ECN': packet.ipv6.tclass_ecn,
                'Flow Label': packet.ipv6.flow,
                'Payload Length': packet.ipv6.plen,
                'Next Header': packet.ipv6.nxt,
                'Hop Limit': packet.ipv6.hlim,
                'Source Address': packet.ipv6.src.upper(),
                'Destination Address': packet.ipv6.dst.upper()
            }
            return ip_info
    except OSError as error:
        print("OS Error: {0}".format(error))
    except ValueError:
        print("IPV4/6 CAPTURE ERROR")
    except:
        print("Unexpected Error", sys.exc_info()[0])
        raise


def parse_tcp(packet):
    try:
        #print("\n---------TCP INFO ----------")
        tcp_info = {'Source Port': packet.tcp.srcport, 'Dest. Port': packet.tcp.dstport, 'Sequence Number': packet.tcp.seq,
                    'Acknowledgement': packet.tcp.ack, 'Data Offset': 'N/A', 'Reserve': 'N/A',
                    'Flags': {'CWR': packet.tcp.flags_cwr, 'ECN': packet.tcp.flags_ecn, 'URG': packet.tcp.flags_urg,
                              'ACK': packet.tcp.flags_ack, 'PSH': packet.tcp.flags_push, 'RST': packet.tcp.flags_reset,
                              'SYN': packet.tcp.flags_syn, 'FIN': packet.tcp.flags_fin
                              },
                    'Window Size': packet.tcp.window_size, 'Window Size Value': packet.tcp.window_size_value,
                    'Header Length': packet.tcp.hdr_len + " bytes", 'Protocol': packet.tcp.layer_name.upper(),
                    'Checksum': packet.tcp.checksum, 'Checksum Status': packet.tcp.checksum_status,
                    'Urgent Pointer': packet.tcp.urgent_pointer
                    #, 'Segment Data': packet.tcp.segment_data
                    }  # tcp_dict
        return tcp_info
    except OSError as error:
        print("OS Error: {0}".format(error))
    except ValueError:
        print("TCP CAPTURE ERROR")
    except:
        print("Unexpected Error", sys.exc_info()[0])
        raise


def parse_udp(packet):
    try:
        #print("\n---------UDP INFO ----------")
        udp_info = {
            'Source Port': packet.udp.srcport,
            'Dest. Port': packet.udp.dstport,
            'Protocol': packet.udp.layer_name.upper(),
            'Length': packet.udp.length + " bytes",
            'Checksum': packet.udp.checksum,
            'Checksum Status': packet.udp.checksum_status
        }
        return udp_info
    except OSError as error:
        print("OS Error: {0}".format(error))
    except ValueError:
        print("UDP CAPTURE ERROR")
    except:
        print("Unexpected Error", sys.exc_info()[0])
        raise


def parse_http(packet):
    try:
        #print("\n---------HTTP INFO ----------")
        http_info = {
            'Connection': packet.http.connection,
            'Protocol': packet.http.layer_name.upper(),
            'Request Version': packet.http.request_version,
            'Request Method': packet.http.request_method,
            'Request Number': packet.http.request_number
        }
        return http_info
    except OSError as error:
        print("OS Error: {0}".format(error))
    except ValueError:
        print("HTTP CAPTURE ERROR")
    except:
        print("Unexpected Error", sys.exc_info()[0])
        raise


def parse_icmp(packet):
    try:
        # TODO CHECK FOR ICMPV6
    #if icmp_version == None:
        #print("\n---------ICMP INFO ----------")
        icmp_info = {
            #'Type': packet.icmp.checksum
            #'Code': packet.icmp.code,
            #'Checksum': packet.icmp.checksum,
        }
        return icmp_info

    except OSError as error:
        print("OS Error: {0}".format(error))
    except ValueError:
        print("ICMP CAPTURE ERROR")
    except:
        print("Unexpected Error", sys.exc_info()[0])
        raise


def main(file):
    capture = pyshark.FileCapture(file)
    (eth_info, ip_info, table_info, tcp_info, udp_info) = packet_dump(capture)
    # TODO NEED TO RETURN MERGED LIST, TO BE USED TABLE INFO
    print("IN MAIN")
    #print(len(table_info))
    #print(table_info)
   # print(merged_list)
    

if __name__== '__main__':
    main(file="test_udp.pcap")


