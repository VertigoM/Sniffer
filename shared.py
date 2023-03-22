from scapy.all import *
from multiprocessing import Manager
from scapy.plist import PacketList

class Shared(object):
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Shared, cls).__new__(cls)
            cls._manager = Manager()
            
            cls.interfaces = ifaces
            cls.managed_dictionary = cls._manager.dict()
            cls.managed_packet_queue = cls._manager.Queue()
            
            cls.filter_sequence = ""
            
            cls.packet_record = PacketList()
            cls.packet_record_buffer = PacketList()
        return cls.instance
    
    @classmethod
    def clear_packet_record(cls):
        cls.packet_record = PacketList()
        
    @classmethod
    def extend(cls, _list: list):
        cls.packet_record.extend(_list)