import pcapy
from pcapy import findalldevs, open_offline, open_live, lookupdev
import impacket
from impacket.ImpactPacket import PacketBuffer, ProtocolLayer,ProtocolPacket, TCP, UDP, Ethernet, EthernetTag, ARP
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder, IP6Decoder, ICMPDecoder, IPDecoder, TCPDecoder, UDPDecoder, ARPDecoder
import ast # ast.literal_eval(_) turns unicode to string - removes unicode from strings
from threading import Thread

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
            self.decode_packets = EthDecoder()  # TODO - MIGHT HAVE TO PASS INTO IPDECODER?

            # TODO - HERE
            self.decode_ip_packets = EthDecoder().ip_decoder
            self.decode_tcp_packets = TCPDecoder()
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
        print("At Packet Handler")
        print("ip_decoder", self.decode_ip_packets.decode(data))
        print("\nEther Type: ",self.decode_packets.decode(data).get_ether_type())
        print("\nHeader Size: ", self.decode_packets.decode(data).get_header_size())
        # TODO - BE ABLE TO GET SPECIFIC DATA
        #print("\nIP Header Size:", self.decode_ip_packets.decode(data).get_header_size())
        #print("\nIP Header Length", self.decode_ip_packets.decode(data).get_ip_hl())
        print("\nIP Destination", self.decode_ip_packets.decode(data).get_ip_dst())
        print("\nIP Source", self.decode_ip_packets.decode(data).get_ip_src())




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
        def get_active_devices():
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

            if len(active_devs) <0:
                # Check if any active devices
                print("No Active Devices Found")

            print("\nOperable Interface Devices:")
            if isinstance(active_devs, str) == 1:
                print(str(active_devs))
            elif isinstance(active_devs, unicode) == 1:
                active_devs = str(active_devs)  # Convert to string to work with open_live
                print(active_devs)
            elif isinstance(active_devs, list) or isinstance(active_devs, tuple):
                #print("Checking if active devices =List/list")
                print("LIST: ", isinstance(active_devs, list))
                print("TUPLE: ", isinstance(active_devs, tuple))
                if len(active_devs) > 1:
                    for devs in active_devs:
                        print(devs)
            return active_devs

# -------------------GET ALL DEVICES------------------------------------------------
        all_devices = findalldevs()
        if len(all_devices) == 0:
            print("ERROR: No Interface Devices Found")
        else:
            print("Devices Found:")
            for d in all_devices:
                print(d)
            print("\nChecking for operable devices...")
            active_devices = get_active_devices()
            return active_devices

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
        current_datalink = captured_packets.datalink()
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


p_handler = PacketHandler()
selected_active_device = p_handler.get_all_devices()
#captured_packets = p_handler.start_packet_capture(selected_active_device, "tcp")
#p_parse = ParsePacket(selected_active_device, captured_packets)

p = open_live(selected_active_device, 1500, 0, 100)

p.datalink()
print("Running Decoder...")
DecoderThread(p).start()
