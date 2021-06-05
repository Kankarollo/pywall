"""Contains rules for filtering by entropy of the payload."""
from __future__ import print_function
import socket
import netaddr
from rules import register, SimpleRule
from packets import TCPPacket
from utils.entropy import Entropy
from utils.hedge import Hedge
from utils.protocol_classifier import TCP_APPLICATION_PROTOCOLS

ALLOWED_PROTOCOLS = [TCP_APPLICATION_PROTOCOLS.SSH,TCP_APPLICATION_PROTOCOLS.TLS,TCP_APPLICATION_PROTOCOLS.OPENVPN]
class EntropyRule(SimpleRule):
    """Filter TCP packets based on entropy of its payload."""

    def __init__(self, **kwargs):
        """Inherit SimpleRule commands."""
        SimpleRule.__init__(self, **kwargs)

    def filter_condition(self, pywall_packet):
        """ Filter packets based on protocols, entropy and AI classification. """
        if pywall_packet.get_protocol() != socket.IPPROTO_TCP:
            return False

        tcp_payload = pywall_packet.get_payload()
        tcp_body = tcp_payload.get_body()
        src_port = tcp_payload.get_src_port()
        dst_port = tcp_payload.get_dst_port()
        app_protocol = tcp_payload.get_app_protocol()
        if app_protocol == TCP_APPLICATION_PROTOCOLS.SSH:
            return True
        if app_protocol in ALLOWED_PROTOCOLS:
            print("[DEBUG] {} - DOZWOLONY PROTOKOL. PRZEPUSZCZAM!".format(app_protocol))
            return False
        #     print("[DEBUG]: TCPBody = {}".format(tcp_body))
        #     print("[DEBUG]: Total length = {}".format(tcp_payload._total_length))
        #     print("[DEBUG]: Header length = {}".format(tcp_payload.get_header_len()))
        #     print("[DEBUG]: Data length = {}".format(tcp_payload.get_data_len()))
        #     print("Entropy = {}".format(entropy))
        entropyManager = Entropy()
        entropy = entropyManager.calculate_shannon(tcp_body)
        if entropy < 5.0:
            print("[DEBUG] ENTROPIA za mala. MOZNA PRZEPUSCIC!")
            return False
        hedge = Hedge()
        results = hedge.execute_tests(tcp_body)
        verdict = hedge.final_verdict(results)
        if verdict == "COMPRESSED":
            print("[DEBUG] COMPRESSED - MOZNA PRZEPUSCIC!")
            return False
        else:
            print("[DEBUG] ENCRYPTED - DAC DO AI!")


        return False


register(EntropyRule)
