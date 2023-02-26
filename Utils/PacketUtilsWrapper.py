from scapy.all import *


class PacketUtilsWrapper(object):
    __slots__ = [
        '_pkt',
        'ip_src',
        'ip_dst',
        'tcp_sport',
        'tcp_dport',
    ]

    def __init__(self,
                 p: Packet):
        self._pkt = p

        self.tcp_sport = self.tcp_dport = None
        self.ip_src = self.ip_dst = None

        if self._pkt.haslayer(TCP):
            try:
                tcp_layer = self._pkt.getlayer(TCP)
                self.tcp_sport = tcp_layer.sport
                self.tcp_dport = tcp_layer.dport
            except:
                pass

        if self._pkt.haslayer(IP):
            try:
                ip_layer = self._pkt.getlayer(IP)
                self.ip_src = ip_layer.src
                self.ip_dst = ip_layer.dst
            except:
                pass

    def info(self):
        return [self.ip_src, self.ip_dst, self.tcp_sport, self.tcp_dport]
