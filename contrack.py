#!/usr/bin/env python2
"""TCP Connection Tracking."""

from __future__ import print_function

import select
import logging
from enum import Enum

class TCP_STATES(Enum):
    """TCP STATES USED TO TRACK CONNECTION GATHERED IN ONE PLACE"""
    CLOSED = 0,
    SYN_RCVD1 = 1,
    SYN_RCVD2 = 2,
    SYN_SENT1 = 3,
    SYN_SENT2 = 4,
    SYN_SENT3 = 5,
    CLOSE_WAIT1 = 6,
    CLOSE_WAIT2 = 7,
    FIN_WAIT_1 = 8,
    FIN_WAIT_2 = 9,
    FIN_WAIT_3 = 10,
    LAST_ACK = 11,
    CLOSING = 12,
    CLOSING2 = 13,
    ESTABLISHED = 14,

class PyWallCracker(object):
    """Central TCP connection tracking process and class.

    Receives TCP packets from ingress and egress, and updates connection status
    accordingly.  Also, receives connection status queries from the firewall,
    and responds to them.

    Connection tuple is defined as:
    (remote_ip, remote_port, local_ip, local_port)

    Objects placed into the queues should be:
    (connection tuple, syn, ack, fin)

    """

    def __init__(self, ingress_queue, egress_queue, query_pipe):
        """Create an instance of the Cracker, given three IPC's.

        - ingress_queue - Queue of flags from ingress TCP packets.
        - egress_queue  - Queue of flags from egress TCP packets.
        - query_pipe    - Pipe for queries and responses from PyWall.
        """
        self.ingress_queue = ingress_queue
        self.egress_queue = egress_queue
        self.query_pipe = query_pipe
        self.connections = {}

    def handle_ingress(self, report):
        """Handle an ingress packet 'report'.

        Updates the state table for the given packet and flags by following our
        TCP state diagram (only including transitions for ingress packets).

        """
        tup, syn, ack, fin = report
        curr = self.connections.get(tup, TCP_STATES.CLOSED)
        # print("[DEBUG]: CURR = {}".format(curr))
        # print("[DEBUG]: TCP_STATES.CLOSED = {}".format(TCP_STATES.CLOSED))
        l = logging.getLogger('pywall.contrack')
        tcp_state = None
        if curr == TCP_STATES.CLOSED:
            if syn:
                tcp_state = TCP_STATES.SYN_RCVD1
            else:  # Otherwise, assume this was started before firewall ran.
                tcp_state = TCP_STATES.ESTABLISHED
        elif curr == TCP_STATES.SYN_RCVD2:
            if ack:
                tcp_state = TCP_STATES.ESTABLISHED
        elif curr == TCP_STATES.SYN_SENT1:
            if syn and ack:
                tcp_state = TCP_STATES.SYN_SENT2
            elif syn:
                tcp_state = TCP_STATES.SYN_SENT3
        elif curr == TCP_STATES.ESTABLISHED:
            if fin:
                tcp_state = TCP_STATES.CLOSE_WAIT1
            else:
                tcp_state = TCP_STATES.ESTABLISHED
        elif curr == TCP_STATES.FIN_WAIT_1:
            if fin and ack:
                tcp_state = TCP_STATES.FIN_WAIT_3
            elif ack:
                tcp_state = TCP_STATES.FIN_WAIT_2
            elif fin:
                tcp_state = TCP_STATES.CLOSING
        elif curr == TCP_STATES.FIN_WAIT_2:
            if fin:
                tcp_state = TCP_STATES.FIN_WAIT_3
        elif curr == TCP_STATES.CLOSING:
            if ack:
                tcp_state = TCP_STATES.FIN_WAIT_3
        elif curr == TCP_STATES.CLOSING2:
            if ack:
                tcp_state = TCP_STATES.CLOSED
        elif curr == TCP_STATES.LAST_ACK:
            if ack:
                tcp_state = TCP_STATES.CLOSED

        if tcp_state is None:
            # Log undefined transitions and don't change the state of the
            # connection.
            tcp_state = curr
            l.error('RCV: %r (%s): syn=%r, ack=%r, fin=%r => %s'
                    ' (UNDEFINED TRANSITION)' %
                    (tup, curr, syn, ack, fin, tcp_state))
        else:
            # Log other transitions at the lowest level, in case we need to
            # debug.
            l.debug('RCV: %r (%s): syn=%r, ack=%r, fin=%r => %s' %
                    (tup, curr, syn, ack, fin, tcp_state))

        # Update the connection status.
        self.connections[tup] = tcp_state

    def handle_egress(self, report):
        """Handle an egress packet 'report'.

        Updates the state table for the given packet and flags by following our
        TCP state diagram (only including transitions for egress packets).

        """
        tup, syn, ack, fin = report
        curr = self.connections.get(tup, TCP_STATES.CLOSED)
        # print("[DEBUG]: CURR = {}".format(curr))
        l = logging.getLogger('pywall.contrack')
        tcp_state = None
        if curr == TCP_STATES.CLOSED:
            if syn:
                tcp_state = TCP_STATES.SYN_SENT1
            else:  # Assume this was running before hand.
                tcp_state = TCP_STATES.ESTABLISHED
        elif curr == TCP_STATES.SYN_SENT1:
            if syn:
                tcp_state = TCP_STATES.SYN_SENT1  # This means we are retrying a connection.
        elif curr == TCP_STATES.SYN_RCVD1:
            if syn and ack:
                tcp_state = TCP_STATES.SYN_RCVD2
        elif curr == TCP_STATES.SYN_RCVD2:
            if fin:
                tcp_state = TCP_STATES.FIN_WAIT_1
        elif curr == TCP_STATES.SYN_SENT3:
            if ack:
                tcp_state = TCP_STATES.SYN_RCVD2
        elif curr == TCP_STATES.SYN_SENT2:
            if ack:
                tcp_state = TCP_STATES.ESTABLISHED
        elif curr == TCP_STATES.ESTABLISHED:
            if fin:
                tcp_state = TCP_STATES.FIN_WAIT_1
            else:
                tcp_state = TCP_STATES.ESTABLISHED
        elif curr == TCP_STATES.CLOSE_WAIT1:
            if fin and ack:
                tcp_state = TCP_STATES.LAST_ACK
            elif ack:
                tcp_state = TCP_STATES.CLOSE_WAIT2
        elif curr == TCP_STATES.CLOSE_WAIT2:
            if fin:
                tcp_state = TCP_STATES.LAST_ACK
        elif curr == TCP_STATES.CLOSING:
            if ack:
                tcp_state = TCP_STATES.CLOSING2
        elif curr == TCP_STATES.FIN_WAIT_3:
            if ack:
                tcp_state = TCP_STATES.CLOSED

        if tcp_state is None:
            # Log undefined transitions and don't change the state of the
            # connection.
            tcp_state = curr
            l.error('SND: %r (%s): syn=%r, ack=%r, fin=%r => %s'
                    ' (UNDEFINED TRANSITION)' %
                    (tup, curr, syn, ack, fin, tcp_state))
        else:
            # Log other transitions at the lowest level, in case we need to
            # debug.
            l.debug('SND: %r (%s): syn=%r, ack=%r, fin=%r => %s' %
                    (tup, curr, syn, ack, fin, tcp_state))

        self.connections[tup] = tcp_state

    def handle_query(self, con_tuple):
        """Take a query, load the state, and return it in the query pipe."""

        self.query_pipe.send(self.connections.get(con_tuple, TCP_STATES.CLOSED))

    def run(self):
        """Run the connection tracking process.

        Selects on the IPC, waiting for input.
        """
        while True:
            egress_fd = self.egress_queue._reader.fileno()
            ingress_fd = self.ingress_queue._reader.fileno()
            query_fd = self.query_pipe.fileno()

            # Use select to get a list of file descriptors ready to be read.
            ready, _, _ = select.select([egress_fd, ingress_fd, query_fd], [], [])
            for ready_fd in ready:
                if ready_fd == egress_fd:
                    egress_packet = self.egress_queue.get_nowait()
                    # print("[DEBUG]: EGRESS_PACKET={}".format(egress_packet))
                    self.handle_egress(egress_packet)
                elif ready_fd == ingress_fd:
                    ingess_packet = self.ingress_queue.get_nowait()
                    # print("[DEBUG]: INGRESS_PACKET={}".format(ingess_packet))
                    self.handle_ingress(ingess_packet)
                elif ready_fd == query_fd:
                    self.handle_query(self.query_pipe.recv())
