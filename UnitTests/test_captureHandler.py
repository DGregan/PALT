import unittest
from unittest import TestCase
from Handler import CaptureHandler, DeviceHandler
import pyshark


class TestCaptureHandler(TestCase):
    def __init__(self):
        super(TestCaptureHandler, self).__init__()
        self.ch = CaptureHandler()
        self.dh = DeviceHandler()
        self.ip_capture_file = "test_ipv4_tcp_smtp.cap"
        self.tcp_capture_file = "test_tcp_connection_end.cap"
        self.udp_capture_file = "test_udp.pcap"
        self.http_capture_file = "test_http2.cap"

    def test_get_ip_version(self):
        capture = pyshark.FileCapture(self.http_capture_file)
        #capture.sniff(packet_count=50, timeout=100)
        self.ch.get_ip_version(self, capture)

    def test_packet_dump(self):
        self.ch.packet_dissector(self.capture_file)

    def test_parse_eth(self):
        self.fail()

    def test_parse_ip(self):
        capture = pyshark.FileCapture(input_file=self.ip_capture_file)
        (eth, ip, table) = self.ch.packet_dissector(capture)
        # assert info in eth, ip, table

    def test_parse_tcp(self):
        capture = pyshark.FileCapture(input_file=self.ip_capture_file)
        (eth, ip, table, tcp) = self.ch.packet_dissector(capture)
        # assert info in eth, ip, table

    def test_parse_udp(self):
        self.fail()

    def test_parse_http(self):
        self.fail()

def main():
    unittest.main()


if __name__ == '__main__':
    main()