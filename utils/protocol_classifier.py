from __future__ import print_function
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *


def main():
    print("[TEST]: Executing testing program. Check if classifier is working correctly.")
    # packets = rdpcap("test_pcap_files/tcp_packets_test.pcap")
    packets = rdpcap("utils/test_pcap_files/tlsPackets_test.pcap")
    for packet in packets:
        if packet.haslayer(TLS):
            print("[DEBUG]: Elo Jestem Z TLSA!!!")
        else:
            print("[DEBUG]: Elo Jestem Z KADS INDZIEJ!!!")

if __name__ == '__main__':
    main()
