from scapy.all import *

class Shared():
    def __init__(self):
        self.interfaces = ifaces
        self.sniffed_interface = None
