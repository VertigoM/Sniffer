from PyQt5.QtGui import QFont
from PyQt5.QtGui import QStandardItem
from PyQt5.QtGui import QStandardItemModel
from typing import Any
from scapy.packet import Packet
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import TCP_client
from scapy.layers.inet6 import IPv6
from scapy.layers.http import HTTP
from scapy.layers.http import HTTPRequest
from scapy.layers.http import Net
from scapy.plist import PacketList
from scapy.sessions import TCPSession
from Utils import IANA_Loader
from subprocess import run
import datetime
import logging

"""
Get standard logger declared inside main
"""
logger = logging.getLogger('standard')

class PacketProcessor(object):
    """
    A class to process each packet.
    Utilities.
    """
    def __init__(self, _identifier: IANA_Loader.IANA_Loader=None):
        self.identifier = _identifier
        self.M_MAC = Ether().src
        
        self._ip_tables_rule__DROP = 'iptables %s INPUT -s %s -p tcp --sport %d -j DROP'
    
    def solve_l3(self, packet: Packet) -> dict:
        """Resolves the network layer

        Args:
            packet (Packet): _description_

        Returns:
            dict: dictionary of network layer source and destination
        """
        # IPv4/IPv6 layer
        if len(packet.layers()) < 2:
            return dict()
        
        # Try get IPv4 src // dst
        l3 = dict()
        try:
            l3['src'] = packet.getlayer(IP).src
            l3['dst'] = packet.getlayer(IP).dst
            
            return l3
        except:
            # AttributeError
            pass
        
        # Try get IPv6 src // dst
        try:
            l3['src'] = packet.getlayer(IPv6).src
            l3['dst'] = packet.getlayer(IPv6).dst
            
            return l3
        except:
            # AttributeError
            pass
        
        # Fallback to Ethernet mac address as source/destination
        try:
            l3['src'] = packet.src
            l3['dst'] = packet.dst \
                if packet.dst != 'ff:ff:ff:ff:ff:ff' \
                else 'Broadcast'
        except:
            # Attribute Error - packet in malformed
            pass
        return l3
        
    
    def solve_l4(self, packet: Packet) -> dict:
        """Resolves the transport layer 

        Args:
            packet (Packet): _description_

        Returns:
            dict: dictionary of transport layer source port and destination port
        """
        l4 = dict()
        try:
            self._l4['sport'] = packet.sport
            self._l4['dport'] = packet.dport
        except:
            # the packet has at least three layers
            # but none of them is part of the OSI transport layer
            pass
        return l4
        
        
    def solve_protocol(self, packet: Packet) -> str:        
        """Protocol identification

        Old implementation: IANA numbers
        Returns:
            str: protocol of packet
        """
        temp = packet
        protocol = ''
        while temp:
            protocol = temp.name
            temp = temp.payload
            if any(bad_protocol in temp.payload for bad_protocol in ['Raw', 'Padding']):
                return temp.name
        return protocol
    
    @staticmethod
    def write_pcap(packet_list: PacketList, path: str=None) -> None:
        """Write pcap file from PacketList

        Args:
            packet_list (PacketList): _description_
            path (str, optional): [path][filename]. Defaults to None.
        """
        if path is None:
            """
            If path is passes as None - save packet_list to saves dir
            as %current_date {%d%m%Y-%H%M}.pcap
            """
            current_date = datetime.datetime.now()
            path = f'saves/{current_date.strftime("%d%m%Y-%H%M")}.pcap'
        try:
            wrpcap(path, packet_list)
        except Exception as exception:
            """
            Old: Find proper way of exception handing
            """
            logger.error(exception)
            
    @staticmethod
    def write_packet_payload_to_file(packet: Packet) -> None:
        """Write binary content of packet to .bin file

        Args:
            packet (Packet): _description_
        """
        with open("dump.bin", "wb") as handler:
            handler.write(packet.show(dump=True).encode("utf-8"))
            
            payload = PacketProcessor.get_raw_payload(packet)
                
            if payload is not None:
                with open("dump_load.bin", "wb") as bin_handler:
                    bin_handler.write(payload)    
            
    @staticmethod
    def convert_packet_to_node(packet: Packet,
                               font: QFont = QFont('Consolas', 10)) -> QStandardItemModel:
        """Convert packet to proper model for being loaded inside a PyQt5::TreeView

        Args:
            packet (Packet): _description_
            font (QFont, optional): _description_. Defaults to QFont('Consolas', 10).

        Returns:
            QStandardItemModel: _description_
        """
        tree_model = QStandardItemModel()
        root = tree_model.invisibleRootItem()
        
        temp = packet
        parent_node = root
        while temp.fields_desc:
            fields_node = QStandardItem()
            fields_node.setFont(font)
            fields_node.setText(temp.name)
            for f in temp.fields_desc:
                field = QStandardItem()
                field.setFont(font)
                field.setText(f"{f.name}: {temp.getfieldval(f.name)}")
                fields_node.appendRow(field)
                
            parent_node.appendRow(fields_node)
            parent_node = fields_node
            temp = temp.payload
        
        return tree_model

    @staticmethod
    def expand_packet(packet: Packet) -> Any:
        yield packet
        while packet.payload:
            packet = packet.payload
            yield packet
            
    @staticmethod
    def forge_packet(packet: Packet) -> Packet:
        """Forge packet in order to fit resending criteria
        
        TBD: [NotComplete/Obsolete]

        Args:
            packet (Packet): _description_

        Returns:
            Packet: _description_
        """
        forged_packet = None
        try:
            forged_packet = packet.copy()
            print(forged_packet)
            logger.info(f"Created deep copy of packet at {forged_packet.id}")
        except AttributeError as error:
            logger.error(str(error))
            
    def send_packet(self, packet: Packet, _interface) -> Packet:
        """
        Send packet accordingly to its properties.
        If packet is TCP send using _send_r and wait for response or timeout.
        If packet is UPD sned using _send_leave.
        
        Else fallback _send_r and wait for timeout or response.
        
        TODO: add better support, check
        which family function to use, send[p]
        """
        if TCP not in packet:
            return self.send_leave(packet, _interface)
        else:
            return self.send_receive(packet, _interface)
    
    def send_leave(self, packet: Packet, _interface) -> None:
        """
        Internal function called in send_packet.
        Send packet and don't wait for answer.
        """
        return
    
    def send_receive(self, packet: Packet, _interface) -> PacketList:
        """
        Internal function called in send_packet.
        Send packet and wait for answer
        """
        
        """
        Create iptables in order for the kernel not to drop
        the response.
        Check if rule already exists else add it.
        Delete it afterwards.
        """
        
        port = packet[TCP].dport
        iface = _interface
        
        host = None
        """
        Check if IPv4 or IPv6
        """
        if IP in packet:
            try:
                host = str(Net(packet[IP].dst))
            except:
                host = packet[IP].dst
        elif IPv6 in packet:
            try:
                host = str(Net(packet[IPv6].dst))
            except:
                host = packet[IPv6].dst
                
        rule_added = self.create_fw_rule('-C', host, port)
            
        if not rule_added:
            if not self.create_fw_rule('-A', host, port):
                logger.error("Failed to add route.")
                return
                
        verbose = True
        iface = _interface
        
        with self.get_TCP_client(packet, host, port, verbose, iface) as sock:
            logger.info(f"Sending packet[s] via {iface}")
            try:
                packet = self.rebuild(packet)
            except AttributeError as exception:
                logger.error(exception)
            
            try:
                return sock.sr1(packet, session=TCPSession(app=True), timeout=10, verbose=verbose)    
            except AttributeError as exception:
                logger.error(exception)
            finally:
                if not self.create_fw_rule('-D', host, port):
                    logger.error("Failed to remove rule after sending packet.")
            
    def create_fw_rule(self,
                       _rule:str, # --check, --add, --delete
                       _host:Any, # destination host, either string or Net object
                       _port:int  # destination port
    ) -> bool:
        """Create iptables rule

        Args:
            _rule (str): string ready to be formatted to proper iptables rule
            _host (Any): _description_
            _port (int): _description_

        Returns:
            bool: Status of rule creation
        """
        iptables_rule = self._ip_tables_rule__DROP % (_rule, _host, _port)        
        try:
            assert run([iptables_rule], capture_output=True, shell=True).returncode == 0
        except AssertionError as exception:
            logger.error(exception)
            return False
        return True
    
    def get_TCP_client(self,
                       packet: Packet, 
                       _host,   # destination host, either string or Net object
                       _port,   # destination port
                       _verbose,# debug verbosity level 
                       _iface) -> Any: # interface via which the packet is sent
        """
        Get tcplink sock
        """
        args=[_host, _port]
        
        kwargs={}
        kwargs['debug']=_verbose
        kwargs['iface']=_iface
        
        if HTTP in packet:
            return TCP_client.tcplink(HTTP, *args, **kwargs)
        elif TCP in packet:
            return TCP_client.tcplink(TCP, *args, **kwargs)
        else:
            return TCP_client.tcplink(Raw, *args, **kwargs)
        
    def rebuild(self, packet: Packet) -> Packet:
        """
        Rebuild packet in order to be [re]sent
        """
        
        """
        Simple case - packet is an HTTPRequest
        
        Extract HTTPRequest headers and let scapy forge the rest
        """
        if HTTPRequest in packet:
            try:
                request = packet[HTTPRequest]
                return HTTP()/request
            except AttributeError as exception:
                logger.error(exception)
                return
        
        """
        More complex case - packet is not an HTTPRequest
        """
        return packet
            
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
        
    def info(self, packet: Packet) -> list:
        """Get basic information from packet

        Args:
            packet (Packet): _description_

        Returns:
            list: packet information
        """
        l3 = self.solve_l3(packet)
        l4 = self.solve_l4(packet)
        protocol = self.solve_protocol(packet)
        
        time = packet.time


        if l4.get('sport') is not None:
            sport = f":{l4.get('sport')}"
        else:
            sport = ""
            
        if l4.get('dport') is not None:
            dport = f":{l4.get('dport')}"
        else:
            dport = ""
        
        source = l3.get("src") + sport
        dst = l3.get("dst") + dport
        try:
            length = len(packet)
        except:
            length = "Max frame dimension - 65535 - exceeded"
        info = packet.mysummary()
        return [time, source, dst, length, protocol, info]