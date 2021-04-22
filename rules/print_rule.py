"""Printout rule for PyWall."""

from __future__ import print_function
from rules import register, SimpleRule
import socket


class PrintRule(SimpleRule):
    """Rule that just prints the socket and its payload.

    This is mostly irrelevent now that logging is enabled.

    """

    def filter_condition(self, pywall_packet):
        """Prints out packet information at the IP level."""
        if pywall_packet.get_protocol() == socket.IPPROTO_TCP:
            print(unicode(pywall_packet.get_payload()))
        # print(unicode(pywall_packet.get_payload()))
        # Action should not be applied. Ever.
        return False


register(PrintRule)
