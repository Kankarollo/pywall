"""Contains rules for filtering by entropy of the payload."""
from __future__ import print_function
import socket
import netaddr
from rules import register, SimpleRule
from packets import TCPPacket
from entropy import Entropy

class EntropyRule(SimpleRule):
    """Filter TCP packets based on entropy of its payload."""

    def __init__(self, **kwargs):
        """Inherit SimpleRule commands."""
        SimpleRule.__init__(self, **kwargs)

    def filter_condition(self, pywall_packet):
        """ Calculate entropy of TCP body. """
        if pywall_packet.get_protocol() != socket.IPPROTO_TCP:
            return False

        tcp_payload = pywall_packet.get_payload()
        tcp_body = tcp_payload.get_body()
        src_port = tcp_payload.get_src_port()
        dst_port = tcp_payload.get_dst_port()
        entropyManager = Entropy()
        entropy = entropyManager.calculate_shannon(tcp_body)
        if src_port == 4444 or dst_port == 4444:
            print("[DEBUG]: TCPBody = {}".format(tcp_body))
            print("[DEBUG]: Total length = {}".format(tcp_payload._total_length))
            print("[DEBUG]: Header length = {}".format(tcp_payload.get_header_len()))
            print("[DEBUG]: Data length = {}".format(tcp_payload.get_data_len()))
            print("Entropy = {}".format(entropy))

        return False


register(EntropyRule)
