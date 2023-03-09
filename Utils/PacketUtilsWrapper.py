from scapy.all import *
from Utils import IANA_Loader

# list filtering using lambdas
# list.filter(lambda p: p.haslayer(...))
# IPv6 -> for ipv6
# IP   -> for ipv4
# if packet has ARP layer L3, L4 are not applicable
# source and destination become MAC addresses

""" class used only for presentation purposes """
class PacketUtilsWrapper(object):
    __slots__ = [
        'identifier',
        'packet',
        'time', #epoch time TODO - translate into relative time
        '_l2',
        '_l3',
        '_l4',
        'protocol',
        'length'
    ]

    def __init__(self,
                 _packet: Packet,
                 _identifier: IANA_Loader.IANA_Loader):
        self.identifier = _identifier
        self.packet = _packet
        
        # ------- Check data-link layer -------
        self._solve_l2()
        
        # ------- Check network layer -------
        self._solve_l3()
        
        # ------- Check transport layer -------
        self._solve_l4()
        
        # ------- Solve protocol -------
        self._solve_protocol()

        self.time = self.packet.time
        self.length = len(self.packet)

    # Datalink layer
    def _solve_l2(self):
        self._l2 = dict()
    
    # Network layer
    def _solve_l3(self):
        # IPv4/IPv6 layer
        self._l3 = dict()
        if len(self.packet.layers()) < 2:
            return
        
        try:
            self._l3['src'] = self.packet.payload.src
            self._l3['dst'] = self.packet.payload.dst
            
            return
        except:
            # AttributeError
            pass
        # Fallback to Ethernet mac address as source/destination
        
        try:
            self._l3['src'] = self.packet.src
            self._l3['dst'] = self.packet.dst \
                if self.packet.dst != 'ff:ff:ff:ff:ff:ff' \
                else 'Broadcast'
            
            return
        except:
            # Attribute Error - packet in malformed
            pass
        
    def _solve_protocol(self):
        # try identifying by usint proto number
        # else take the name of the last layer
        try:
            proto = self.packet.proto
            self.protocol = self.identifier.get_protocol(proto)
        except:
            pass
        
        temp = self.packet
        prot = ''
        while temp:
            prot = temp.name
            temp = temp.payload
        self.protocol = prot
    
    # Transport layer
    def _solve_l4(self):
        self._l4 = dict()
        try:
            self._l4['sport'] = self.packet.sport
            self._l4['dport'] = self.packet.dport
        except:
            # the packet has at least three layers
            # but none of them is part of the OSI transport layer
            pass
        
        
    def info(self) -> list:
        # ----- TODO improve -----
        time     = self.time


        if self._l4.get('sport') is not None:
            _sport = f":{self._l4.get('sport')}"
        else:
            _sport = ""
            
        if self._l4.get('dport') is not None:
            _dport = f":{self._l4.get('dport')}"
        else:
            _dport = ""
        
        source   = self._l3.get("src") + _sport
        dst      = self._l3.get("dst") + _dport
        length   = self.length
        protocol = self.protocol
        info     = self.packet.mysummary()
        return [time, source, dst, length, protocol, info]