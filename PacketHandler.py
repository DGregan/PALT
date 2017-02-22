import pcapy
from pcapy import findalldevs, open_offline, open_live, lookupdev
import impacket
from impacket.ImpactPacket import PacketBuffer, ProtocolLayer,ProtocolPacket, TCP, UDP, Ethernet, EthernetTag, ARP, IP
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder, IP6Decoder, ICMPDecoder, IPDecoder, TCPDecoder, UDPDecoder, ARPDecoder
import ast # ast.literal_eval(_) turns unicode to string - removes unicode from strings
from threading import Thread
from impacket.ImpactPacket import *

import types
'''
    TODO
        - Find out how ImpactPacket <-interlink-> ImpactDecoder, to retrieve specific data
test
'''


class DecoderThread(Thread):
    def __init__(self, packet_capture):
        current_datalink = packet_capture.datalink()
        # TODO - check against IEEE802, ARCNET

        if current_datalink == None:
            raise Exception("Datalink not found")
        elif pcapy.DLT_EN10MB == current_datalink:
            # Checks to see if datalink is Ethernet(10Mb, 100Mb, 1000Mb and upwards)
            print("Datalink: Ethernet")
            self.decode_packets = EthDecoder()  # TODO - GO TO DECODEDCLASS?

            self.decode_ip_packets = IP()
            self.decode_tcp_packets = TCP()
        elif pcapy.DLT_LINUX_SLL == current_datalink:
            # Checks to see if datalink is a Linux "cooked" capture encapsulation
            print("Datalink: Linux 'Cooked'")
            self.decode_packets = LinuxSLLDecoder()
        else:
            raise Exception("Data link not supported:", current_datalink)
        self.pcap = packet_capture
        Thread.__init__(self)

    def run(self):
        print("Starting pcap loop")
        self.pcap.loop(0, self.packetHandler)

    def packetHandler(self, hdr, data):
        # TODO CALL DECODE CLASS?
        #ParsePacket.get_packet_datalink(data)
        print("At Packet Handler")
        print("\nEthdecoder", self.decode_packets.decode(data))
        print("\nEther Type: ", self.decode_packets.decode(data).get_ether_type())
        print("\nHeader Size: ", self.decode_packets.decode(data).get_header_size())
        print("IP SRC", self.decode_ip_packets.get_ip_src())
        print("\nIP DST", self.decode_ip_packets.get_ip_dst())
        print("IP Header size", self.decode_ip_packets.get_header_size())
        print("IP Header lenght", self.decode_ip_packets.get_ip_hl())
        print("IP DF: %s" % self.decode_ip_packets.get_ip_df())
        print("IP ID: %s" % self.decode_ip_packets.get_ip_id())
        print("IP Length: %s" % self.decode_ip_packets.get_ip_len())
        print("IP MF: %s" % self.decode_ip_packets.get_ip_mf())
        print("IP off: %s" % self.decode_ip_packets.get_ip_off())
        print("IP offmask: %s" % self.decode_ip_packets.get_ip_offmask())
        print("IP p: %s" % self.decode_ip_packets.get_ip_p())
        print("IP rf: %s" % self.decode_ip_packets.get_ip_rf())
        print("IP sum: %s" % self.decode_ip_packets.get_ip_sum())
        print("IP ttl: %s" % self.decode_ip_packets.get_ip_ttl())
        print("IP version: %s" % self.decode_ip_packets.get_ip_v())
        print("------------------------------------")
        print("TCP Source Port: %s" % self.decode_tcp_packets.get_th_sport())
        print("TCP %s" % self.decode_tcp_packets.get_th_dport())
        print("TCP Sequence Number %s" % self.decode_tcp_packets.get_th_seq())
        print("TCP Acknowledgement Number %s" %self.decode_tcp_packets.get_th_ack())
        print("TCP Data Offset %s" % self.decode_tcp_packets.get_th_off())
        print("")

        #print("TCPdecoder",self.decode_tcp_packets.decode(data).get_header_size())
        #IP.ethertype()


class PacketHandler:
    def __init__(self):
        self.capture_settings = \
            { "promiscuous_settings": True,
              "max_bytes": 65536,
              "capture_timeout": 0
            }

    def get_all_devices(self):
        '''
        Get_All_Devices - utilises pcapy's 'findalldevs' method to return all interface devices found on the machine
        :return: active_devices - contains a list of all devices that can be operated on
        '''

        all_devices = findalldevs()
        if len(all_devices) == 0:
            print("ERROR: No Interface Devices Found")
        else:
            print("Devices Found:")
            for d in all_devices:
                print(d)
            # TODO - Concat with "\n"
            print("\nChecking for operable devices...")
            return all_devices

    def get_active_devices(self):
        '''
        Get_Active_Devices - Gets devices that can be opened through pcapy's 'open_live'
        Some devices may not be applicable as the process may not have sufficient privileges
        to open the interfaces for data capture
        :return:
        '''
        test_devs = ["\\Device\\NPF_{9CA6B4A6-A4CA-48E4-AFB2-B8CCD0BCBA4C}",
                     "\\Device\\NPF_{12ECE9E6-D8EA-4EF0-8F6F-10532AD6DC08}"
                     ]
        active_devs = lookupdev()

        if len(active_devs) < 0:
            # Check if any active devices
            print("No Active Devices Found")

        print("\nOperable Interface Devices:")
        if isinstance(active_devs, str) == 1:
            print(str(active_devs))
        elif isinstance(active_devs, unicode) == 1:
            active_devs = str(active_devs)  # Convert to string to work with open_live
            print(active_devs)
        elif isinstance(active_devs, list) or isinstance(active_devs, tuple):
            # print("Checking if active devices =List/list")
            print("LIST: ", isinstance(active_devs, list))
            print("TUPLE: ", isinstance(active_devs, tuple))
            if len(active_devs) > 1:
                for devs in active_devs:
                    print(devs)
        return active_devs

    def select_active_device(self):
        # TODO - Handle through webpage?
        pass

    def start_packet_capture(self, selected_device, filter_options):
        def set_packet_capture_filter(packet_capture, filter_options):
            return packet_capture.setfilter(filter_options)

        packet_capture = open_live(selected_device, self.capture_settings["max_bytes"]
                                   , self.capture_settings["promiscuous_settings"]
                                   , self.capture_settings["capture_timeout"]
                                   )
        if len(filter_options) == 1:
            print(filter_options)
            filtered_packet_capture = set_packet_capture_filter(packet_capture, filter_options)
        # Continuous Packet capturing TODO - FIX THIS
        #display_device_info(selected_device, packet_capture)


        while(True):
            (header, packet) = packet_capture.next()


class ParsePacket:
    def __init__(self, selected_device, packet_captured):
        self.device = selected_device
        self.captured_packet = packet_captured

    def get_packet_datalink(self, captured_packet):
        self.packet_datalink = captured_packet.datalink()
        print("Datalink: ", self.packet_datalink)
        #current_datalink = captured_packets.datalink()
        # TODO - check against IEEE802, ARCNET - DO DECODER HERE

        # datalink() - int
        return self.packet_datalink

    def get_packet_network_number(self, captured_packet):
        self.packet_net_num = captured_packet.getnet()
        print("\nNetwork Number: ", self.packet_net_num)
        return self.packet_net_num
        # getnet() - int32

    def get_packet_network_mask(self, captured_packet):
        # getmask() - int32
        self.packet_net_mask = captured_packet.getmask()
        print("\nNetwork Mask: ", self.packet_net_mask)
        return self.packet_net_mask

    def get_packet_timestamp(self, captured_packet):
        '''

        :param captured_packet:
        :return: (long, long) - tuple wit 2 elements: # seconds since Epoch,  amount of microseconds
        '''
        # Pkthdr Object Reference
        self.packet_timestamp = captured_packet.getts()
        return self.packet_timestamp

    def get_packet_capture_length(self, captured_packet):
        '''

        :param captured_packet:
        :return: # of bytes of the packet that are available from the capture
        '''
        self.packet_capture_length = captured_packet.getcaplen()
        return self.packet_capture_length

    def get_packet_total_length(self, captured_packet):
        '''

        :param captured_packet:
        :return: Length of packet in bytes
        which might be more than the number of bytes available from the capture, if the length of
        the packet is larger than the maximum number of bytes to capture).
        '''
        self.packet_total_length = captured_packet.getlen()
        return self.packet_total_length

    def get_packet_stats(self, captured_packet):
        '''

        :param captured_packet:
        :return: (int32, int32, int32) = Returns stats on the current capture as tuple (recv, drop, ifdrop)
        '''
        self.packet_stats = captured_packet.stats()
        print("\n--- PACKET STATISTICS ---\n")
        print("\nRecv: ", self.packet_stats[0])
        print("\nDrop: ", self.packet_stats[1])
        print("\nIfDrop: ", self.packet_stats[2])
        return self.packet_stats

    def ethernet_addr(self):
        pass

    def ip_addr(self):
        pass

    def tcp_segment(self):
        pass

    def udp_segment(self):
        pass

    def http_segment(self):
        pass

    def snmp_segment(self):
        pass


class IPV4Parsed:
    '''
    IPv4 FORMAT
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    def __init__(self):
        self.ipv4_parsed = IP()
        self.ipv4_protocol = 8
        # TODO - Recheck total_length, flags and get_options

    def get_protocol_number(self):
        return self.ipv4_protocol

    def get_version(self):
        return self.ipv4_parsed.get_ip_v()

    def get_header_length(self):
        return self.ipv4_parsed.get_ip_hl()

    def get_type_of_service(self):
        return self.ipv4_parsed.get_ip_tos()

    def get_total_length(self):
        # TODO - PROLLY WRONG
        return self.ipv4_parsed.get_size()

    def get_identification(self):
        return self.ipv4_parsed.get_ip_id()

    # TODO - Recheck flags
    def get_flag_df(self):
        '''
        Control Flag
        Bit:
            0 = May Fragment
            1 = Don't Fragments
        '''
        return self.ipv4_parsed.get_ip_df()

    def get_flag_mf(self):
        '''
        Control Flag
        Bit:
            0 = Last Fragment
            1 = More Fragments
        '''
        return self.ipv4_parsed.get_ip_mf()

    def get_fragment_offset(self):
        return self.ipv4_parsed.get_ip_off()

    def get_time_to_live(self):
        return self.ipv4_parsed.get_ip_ttl()

    def get_header_checksum(self):
        return self.ipv4_parsed.get_ip_sum()

    def get_source_ip(self):
        return self.ipv4_parsed.get_ip_src()

    def get_destination_ip(self):
        return self.ipv4_parsed.get_ip_dst()

    def get_options(self):
        return self.ipv4_parsed.get_ip_offmask()

    def get_padding(self):
        return self.ipv4_parsed.get_ip_p()


class TCPHeaderParsed:
    '''
    TCP Header Format
      0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    '''
    def __init__(self):
        self.tcp_header_parsed = TCP()
        self.tcp_protocol = 6
        # TODO - Check what  self.tcp_header_parsed.get_ECE() - Has to do with flags
        # TODO - try out get_th_flags / get_flags

    def get_protocol_number(self):
        return self.tcp_protocol

    def get_source_port(self):
        return self.tcp_header_parsed.get_th_sport()

    def get_destination_port(self):
        return self.tcp_header_parsed.get_th_dport()

    def get_sequence_number(self):
        return self.tcp_header_parsed.get_th_seq()

    def get_acknowledgement_number(self):
        return self.tcp_header_parsed.get_th_ack()

    def get_data_offset(self):
        return self.tcp_header_parsed.get_th_off()

    def get_reserved(self):
        return self.tcp_header_parsed.get_th_reserved()

    def get_flags(self):
        return self.tcp_header_parsed.get_th_flags()

    def get_flag_urg(self):
        return self.tcp_header_parsed.get_URG()

    def get_flag_ack(self):
        return self.tcp_header_parsed.get_ACK()

    def get_flag_psh(self):
        return self.tcp_header_parsed.get_PSH()

    def get_flag_rst(self):
        return self.tcp_header_parsed.get_RST()

    def get_flag_syn(self):
        return self.tcp_header_parsed.get_SYN()

    def get_flag_fin(self):
        return self.tcp_header_parsed.get_FIN()

    def get_window(self):
        return self.tcp_header_parsed.get_th_win()

    def get_checksum(self):
            return self.tcp_header_parsed.get_th_sum()

    def get_urgent_pointer(self):
        return self.tcp_header_parsed.get_th_urp()

    def get_options(self):
        return self.tcp_header_parsed.get_options()

    def get_padding(self):
        return self.tcp_header_parsed.get_padded_options()

    def get_packet_data(self):
        ''' Returns entire packet + child data as a string. Used to extract final packet'''
        return self.tcp_header_parsed.get_packet()


class UDPHeaderParsed:
    '''
    UDP Header FORMAT
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Length             |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   .... data ....                                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    def __init__(self):
        self.udp_header_parsed = UDP()
        self.udp_protocol = 17
        # TODO - check get pseudo headers / get_packet

    def get_header_size(self):
        return self.udp_header_parsed.get_header_size()

    def get_source_port(self):
        return self.udp_header_parsed.get_uh_sport()

    def get_destination_port(self):
        return self.udp_header_parsed.get_uh_dport()

    def get_length(self):
        return self.udp_header_parsed.get_uh_ulen()

    def get_checksum(self):
        return self.udp_header_parsed.get_uh_sum()

    def get_packet_data(self):
        ''' Returns entire packet + child data as a string. Used to extract final packet'''
        return self.udp_header_parsed.get_packet()


class ICMPParsed:
    '''
    ICMP FORMAT
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    def __init__(self):
        self.icmp_parsed = ICMP()
        self.icmp_protocol = 1
        self.icmp_codes = \
            {0: {0: 'Echo Reply',
                 },
             3: {0: 'Net Unreachable',
                 1: 'Host Unreachable',
                 2: 'Destination protocol unreachable',
                 3: 'Destination port unreachable',
                 4: 'Fragmentation required, and DF flag set',
                 5: 'Source route failed',
                 6: 'Destination network unknown',
                 7: 'Destination host unknown',
                 8: 'Source host isolated',
                 9: 'Network administratively prohibited',
                 10: 'Host administratively prohibited',
                 11: 'Network unreachable for TOS',
                 12: 'Host unreachable for TOS',
                 13: 'Communication administratively prohibited',
                 14: 'Host Precedence Violation',
                 15: 'Precedence cutoff in effect',
                 },
             4: {0: 'Source quench',
                 },
             5: {0: 'Redirect Datagram for the Network',
                 1: 'Redirect Datagram for the Host',
                 2: 'Redirect Datagram for the TOS & network',
                 3: 'Redirect Datagram for the TOS & host',
                 },
             8: {0: 'Echo request',
                 },
             9: {0: 'Router Advertisement',
                 },
             10: {0: 'Router discovery/selection/solicitation',
                  },
             11: {0: 'TTL expired in transit',
                  1: 'Fragment reassembly time exceeded',
                  },
             12: {0: 'Pointer indicates the error',
                  1: 'Missing a required option',
                  2: 'Bad length',
                  },
             13: {0: 'Timestamp',
                  },
             14: {0: 'Timestamp reply',
                  },
             15: {0: 'Information request',
                  },
             16: {0: 'Information reply',
                  },
             17: {0: 'Address mask request',
                  },
             18: {0: 'Address mask reply',
                  },
             30: {0: 'Traceroute',
                  },
             } # END DICTIONARY

    def get_header_size(self):
        return self.icmp_parsed.get_header_size()

    def get_type(self):
        return self.icmp_parsed.get_icmp_type()

    def get_code(self):
        return self.icmp_parsed.get_icmp_code()

    def get_code_name(self):
        type_name = self.icmp_parsed.get_icmp_type()
        code_name = self.icmp_parsed.get_icmp_code()
        return self.icmp_parsed.get_code_name(type_name, code_name)

    def get_checksum(self):
        return self.icmp_parsed.get_icmp_cksum()

    def get_type_name(self):
        type_name = self.icmp_parsed.get_icmp_type()
        return self.icmp_parsed.get_type_name(type_name)

    def match_code(self):
        ''' Matches get_code result to icmp_codes dictionary'''
        pass


class EthernetHeaderParsed:
    '''

    '''
    def __init__(self):
        self.ethernet_parsed = Ethernet()

    def get_header_size(self):
        return self.ethernet_parsed.get_header_size()

    def get_type(self):
        ''' Ethernet Type field'''
        return self.ethernet_parsed.get_ether_type()

    def get_destination_address(self):
        return self.ethernet_parsed.get_ether_dhost()

    def get_source_address(self):
        return self.ethernet_parsed.get_ether_shost()

    def get_tag(self):
        #return self.ethernet_parsed.get_tag(index=)
        pass

    def get_packet_data(self):
        return self.ethernet_parsed.get_packet()

'''
p_handler = PacketHandler()
selected_active_device = p_handler.get_all_devices()
#captured_packets = p_handler.start_packet_capture(selected_active_device, "tcp")
#p_parse = ParsePacket(selected_active_device, captured_packets)

p = open_live(selected_active_device, 1500, 0, 100)

p.datalink()
print("Running Decoder...")
DecoderThread(p).start()
'''