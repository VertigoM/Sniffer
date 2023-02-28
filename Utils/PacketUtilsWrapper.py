from scapy.all import *
from Utils import IANA_Loader


class PacketUtilsWrapper(object):
    __slots__ = [
        'identifier',
        'pkt',
        'ip_src',
        'ip_dst',
        'sport',
        'dport',
        'time', #epoch time TODO - translate into relative time
        'protocol',
        'length'
    ]

    def __init__(self,
                 _pkt: Packet,
                 _identifier: IANA_Loader.IANA_Loader):
        self.identifier = _identifier
        self.pkt = _pkt

        try:
            # pkt has TCP layer
            tcp_layer = self.pkt.getlayer(TCP)

            self.sport = tcp_layer.sport
            self.dport = tcp_layer.dport
        except:
            pass

        try:
            # pkt has UDP layer
            udp_layer = self.pkt.getlayer(UDP)

            self.sport = udp_layer.sport
            self.dport = udp_layer.dport
        except:
            self.sport = self.dport = None

        ip_layer = None
        self.protocol = 'UNKNOWN'
        try:
            ip_layer = self.pkt.getlayer(IP)
        except:
            pass

        if ip_layer is not None:
            self.ip_src = ip_layer.src
            self.ip_dst = ip_layer.dst
            self.protocol = self.identifier.get_protocol(ip_layer.proto)
        else:
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