import sys
import click
import pyshark
import os
import subprocess


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
        if packet.transport_layer == 'TCP':
            ip = None
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip = packet.ip
            elif ip_version == 6:
                ip = packet.ipv6
            print('Packet %d' % i)
            print("--------PACKET INFO -----------")
            print('Time', packet.sniff_time)  # "%d %b %Y  %H:%M:%S.%f")
            print("ip", ip.src)

            print('Packet Number:', packet.number)
            print('Packet Layers:', packet.layers)
            print('Highest Layer:', packet.highest_layer)
            print('Length:', packet.length)
            print("Captured Length:", packet.captured_length)
            print("-------------------------------")

            if packet.highest_layer == 'HTTP':
                print("--------HTTP INFO -----------")
                print('Time', packet.sniff_time)  # "%d %b %Y  %H:%M:%S.%f")
                print('Layer Name:', packet.http.layer_name)
                #print('Content Type:', packet.http.content_type)
               # print('Response Code:', str(packet.http.response_code))
                print('Request Verson:', packet.http.request_version)
                #print('Response Phrase:', str(packet.http.response_phrase))
                #print('Server:', packet.http.server)
                print("-------------------------------")

        elif packet.transport_layer == 'UDP':
            ip = None
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip = packet.ip
            elif ip_version == 6:
                ip = packet.ipv6
            print('Packet %d' % i)
            print("--------PACKET INFO -----------")
            print('Time', packet.sniff_time)  # "%d %b %Y  %H:%M:%S.%f")
            print("ip", ip.src)

            print('Packet Number:', packet.number)
            print('Packet Layers:', packet.layers)
            print('Highest Layer:', packet.highest_layer)
            print('Length:', packet.length)
            print("Captured Length:", packet.captured_length)
            print("-------------------------------")

        i += 1

def main(file):

    node = None
    capture = None
    capture = pyshark.FileCapture(file)
    if node == None:
        dump_packets(capture)



if __name__ == '__main__':
    main(file="test_http.pcap")