from scapy.all import *


class PacketUtilsWrapper(object):
    __slots__ = [
        'pkt',
        'ip_src',
        'ip_dst',
        'sport',
        'dport',
        'time',
        'protocol',
        'length'
    ]

    def __init__(self,
                 _pkt: Packet):
        self.pkt = _pkt

        self.protocol = ''

        try:
            # pkt has TCP layer
            tcp_layer = self.pkt.getlayer(TCP)

            self.sport = tcp_layer.sport
            self.dport = tcp_layer.dport

            self.protocol = 'TCP'
        except:
            pass

        try:
            # pkt has UDP layer
            udp_layer = self.pkt.getlayer(UDP)

            self.sport = udp_layer.sport
            self.dport = udp_layer.dport

            self.protocol = 'UDP'
        except:
            self.sport = self.dport = None

        try:
            ip_layer = self.pkt.getlayer(IP)
            self.ip_src = ip_layer.src
            self.ip_dst = ip_layer.dst
        except:
            self.ip_src = self.ip_dst = None

        self.time = self.pkt.time
        self.length = len(self.pkt)

    def expand(self):
        cnt = self.pkt
        yield cnt.name, cnt.fields

    def info(self) -> list:
        # ----- TODO improve -----
        time     = self.time
        source   = f'{self.ip_src}:{self.sport}'
        dest     = f'{self.ip_dst}:{self.dport}'
        length   = self.length
        protocol = self.protocol
        info     = self.pkt.mysummary()
        return [time, source, dest, length, protocol, info]