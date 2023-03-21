from scapy.all import *


class Shared(object):
    def __init__(self):
        self.interfaces = ifaces
        self.managed_dictionary = None
        self.managed_packet_queue = None
        
        self.filter_sequence = ""
        self.filter_isValid = False
