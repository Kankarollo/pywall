"""PyWall instance creator from config file."""

from __future__ import print_function
import json

import rules
# This import must be here to trigger all rules to be imported and register.
from rules import *
from pywall import PyWall
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


class PyWallConfig(object):
    """Creates instances of PyWall from a configuration file."""

    def __init__(self, filename):
        """Constructor - takes filename, but doesn't open."""
        self.filename = filename

    def create_pywall(self, *args):
        """Read the configuration file and create an instance of PyWall.

        Any arguments will be passed to the constructor of PyWall.

        """
        cfg = json.load(open(self.filename))
        default = cfg.pop('default_chain', 'ACCEPT')

        the_wall = PyWall(*args, default=default)

        for chain, rule_list in cfg.items():
            the_wall.add_chain(chain)

            for rule in rule_list:
                name = rule.pop('name', None)
                rule_class = rules.rules[name]
                rule_instance = rule_class(**rule)
                the_wall.add_brick(chain, rule_instance)

        return the_wall

