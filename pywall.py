#!/usr/bin/env python2
"""Contains PyWall class, the main class for our Python firewall."""

from __future__ import print_function
from packets import IPPacket
import config

import os
import logging

import netfilterqueue as nfq

_NFQ_INIT = 'iptables -I INPUT -j NFQUEUE --queue-num %d'
_NFQ_CLOSE = 'iptables -D INPUT -j NFQUEUE --queue-num %d'


class PyWall(object):
    """The main class for PyWall.

    This class contains all rules for the firewall.  Furthermore, it waits on
    NetfilterQueue for packets, runs them through rules, and ultimately accepts
    or drops the packets.
    """

    def __init__(self, queue_num=1, default='DROP'):
        """Create a PyWall object, specifying NFQueue queue number."""
        self.queue_num = queue_num
        self.chains = {'INPUT': [], 'ACCEPT': None, 'DROP': None}
        self.default = default
        self._start = 'INPUT'
        self._old_handler = None

    def add_chain(self, chain_name):
        """Add a new, empty chain."""
        self.chains[chain_name] = []

    def add_rule(self, chain, rule):
        """Add a rule to a chain."""
        self.chains[chain].append(rule)

    def _apply_chain(self, chain, nfqueue_packet, pywall_packet):
        """Run the packet through a chain."""
        if chain == 'ACCEPT':
            nfqueue_packet.accept()
        elif chain == 'DROP':
            nfqueue_packet.drop()
        else:
            # Match against every rule:
            for rule in self.chains[chain]:
                result = rule(pywall_packet)
                # If it matches, execute the rule.
                if result:
                    return self._apply_chain(result, nfqueue_packet,
                                             pywall_packet)
            # If no matches, run the default rule.
            return self._apply_chain(self.default, nfqueue_packet,
                                     pywall_packet)

    def callback(self, packet):
        """Accept packets from NFQueue."""
        pywall_packet = IPPacket(packet.get_payload())
        self._apply_chain(self._start, packet, pywall_packet)

    def run(self):
        """Run the PyWall!"""
        # Setup firewall rule.
        setup = _NFQ_INIT % self.queue_num
        os.system(setup)
        print('Set up IPTables: ' + setup)

        # Bind and run NFQ.
        nfqueue = nfq.NetfilterQueue()
        nfqueue.bind(self.queue_num, self.callback)
        try:
            nfqueue.run()
        finally:
            # Always remove the firewall rule when we're done.
            teardown = _NFQ_CLOSE % self.queue_num
            os.system(teardown)
            print('\nTore down IPTables: ' + teardown)


def init_log(log_level, log_name=None, log_mode='a'):
    """
    Prints default log messages to console, optionally to a file.

    Reference: https://docs.python.org/2/howto/logging.html
    """
    f = logging.Formatter(fmt='[%(asctime)s] %(message)s')

    sh = logging.StreamHandler()
    sh.setLevel(log_level)
    sh.setFormatter(f)
    logging.getLogger().addHandler(sh)
    if log_name:
        fh = logging.FileHandler(filename=log_name, mode=log_mode)
        fh.setLevel(log_level)
        fh.setFormatter(f)
        logging.getLogger().addHandler(fh)


if __name__ == '__main__':
    init_log(log_level=logging.DEBUG, log_name='pywall.log', log_mode='w')
    import sys
    if len(sys.argv) != 2:
        logging.critical("usage: %s CONFIG-FILE" % (sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    conf = config.PyWallConfig(sys.argv[1])
    the_wall = conf.create_pywall()
    the_wall.run()
