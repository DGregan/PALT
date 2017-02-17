from pcapy import *
from impacket import *
import types


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

            print("\nOperable Interface Devices:")
            if isinstance(active_devs, str) == 1:
                print(str(active_devs))

            elif isinstance(active_devs, list) or isinstance(active_devs, tuple):
                print("Checking if active devices =List/list")
                print("LIST: ", isinstance(active_devs, list))
                print("TUPLE: ", isinstance(active_devs, tuple))
                print()
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
            # TODO Tooltip over 'operable'
            # TODO SPINNER HERE
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
        while(True):
            (header, packet) = packet_capture.next()
            self.parse_packet(packet)

    def parse_packet(self, captured_packet):
        '''
        Method to parse through the captured packet and break down into it's components
        Ex. IP -> TCP -> HTTP
        :param captured_packet:
        :return:
        '''






PacketHandler().get_all_devices()
