from scapy.all import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import datetime
from Utils import IANA_Loader

# list filtering using lambdas
# list.filter(lambda p: p.haslayer(...))
# IPv6 -> for ipv6
# IP   -> for ipv4
# if packet has ARP layer L3, L4 are not applicable
# source and destination become MAC addresses

logger = logging.getLogger('standard')

""" class used only for presentation purposes """
class PacketProcessor(object):
    def __init__(self, _identifier: IANA_Loader.IANA_Loader=None):
        self.identifier = _identifier
        self.M_MAC      = Ether().src 
    
    # Network layer
    def _solve_l3(self, packet: Packet) -> dict:
        # IPv4/IPv6 layer
        if len(packet.layers()) < 2:
            return dict()
        
        # Try get IPv4 src // dst
        _l3 = dict()
        try:
            _l3['src'] = packet.getlayer(IP).src
            _l3['dst'] = packet.getlayer(IP).dst
            
            return _l3
        except:
            # AttributeError
            pass
        
        # Try get IPv6 src // dst
        try:
            _l3['src'] = packet.getlayer(IPv6).src
            _l3['dst'] = packet.getlayer(IPv6).dst
            
            return _l3
        except:
            # AttributeError
            pass
        
        # Fallback to Ethernet mac address as source/destination
        try:
            _l3['src'] = packet.src
            _l3['dst'] = packet.dst \
                if packet.dst != 'ff:ff:ff:ff:ff:ff' \
                else 'Broadcast'
        except:
            # Attribute Error - packet in malformed
            pass
        return _l3
        
    
    # Transport layer
    def _solve_l4(self, packet: Packet) -> dict:
        _l4 = dict()
        try:
            self._l4['sport'] = packet.sport
            self._l4['dport'] = packet.dport
        except:
            # the packet has at least three layers
            # but none of them is part of the OSI transport layer
            pass
        return _l4
        
        
    def _solve_protocol(self, packet: Packet) -> string:
        # try identifying by usint proto number
        # else take the name of the last layer
        # try:
        #     proto = self.packet.proto
        #     self.protocol = self.identifier.get_protocol(proto)
        # except:
        #     pass
        
        temp = packet
        protocol = ''
        while temp:
            protocol = temp.name
            temp = temp.payload
            if any(bad_protocol in temp.payload for bad_protocol in ['Raw', 'Padding']):
                return temp.name
        return protocol
    
    @staticmethod
    def write_pcap(packet_list, path: str = None) -> None:
        if path is None:
            current_date = datetime.datetime.now()
            path = f'saves/{current_date.strftime("%d%m%Y-%H%M")}.pcap'
        try:
            wrpcap(path, packet_list)
        except Exception as e:
            # TODO - find proper way of error handling
            print(f"Error while writing to file!::{str(e)}")
            
    @staticmethod
    def convert_packet_to_node(packet: Packet, font: QFont = QFont('Consolas', 10)) -> QStandardItemModel:
        tree_model = QStandardItemModel()
        root = tree_model.invisibleRootItem()
        
        _t = packet
        _parent_node = root
        while _t.fields_desc:
            _fields_node = QStandardItem()
            _fields_node.setFont(font)
            _fields_node.setText(_t.name)
            for _f in _t.fields_desc:
                _field = QStandardItem()
                _field.setFont(font)
                _field.setText(f"{_f.name}: {_t.getfieldval(_f.name)}")
                _fields_node.appendRow(_field)
                
            _parent_node.appendRow(_fields_node)
            _parent_node = _fields_node
            _t = _t.payload
        
        return tree_model
    
    def get_traffic_outgoing(self) -> Any:
        return lambda packet: packet[Ether].src == self.M_MAC
    
    def get_traffic_ingoing(self) -> Any:
        return lambda packet: packet[Ether].src != self.M_MAC
    
    @staticmethod
    def get_raw_payload(packet) -> bytearray:
        payload = None
        try:
            payload = packet[Raw].load
        except AttributeError as _:
            return None
        except IndexError as _:
            return None
        
        return payload
    
    def check_outgoing(self, packet) -> bool:
        return packet[Ether].src == self.M_MAC
        
    def info(self, packet) -> list:
        # ------- Check data-link layer -------
        # self._solve_l2()
        
        # ------- Check network layer -------
        l3 = self._solve_l3(packet)
        
        # ------- Check transport layer -------
        l4 = self._solve_l4(packet)
        
        # ------- Solve protocol -------
        protocol = self._solve_protocol(packet)
        
        time     = packet.time


        if l4.get('sport') is not None:
            _sport = f":{l4.get('sport')}"
        else:
            _sport = ""
            
        if l4.get('dport') is not None:
            _dport = f":{l4.get('dport')}"
        else:
            _dport = ""
        
        source   = l3.get("src") + _sport
        dst      = l3.get("dst") + _dport
        try:
            length   = len(packet)
        except:
            length   = "Max frame dimension - 65545 - exceeded"
        info     = packet.mysummary()
        return [time, source, dst, length, protocol, info]