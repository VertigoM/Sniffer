from scapy.all import *
from multiprocessing import Manager
from scapy.plist import PacketList

logger = logging.getLogger('standard')

class Shared(object):
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Shared, cls).__new__(cls)
            cls._manager = Manager()
            
            cls.interfaces = ifaces
            cls.managed_dictionary = cls._manager.dict()
            cls.managed_packet_queue = cls._manager.Queue()
            
            cls.filter_sequence = ""
            cls.filter_isValid = True
            
            cls.packet_record           = PacketList()
            cls.packet_record_buffer    = PacketList()
            # displayed packets
            cls.packet_record_filtered  = PacketList()
        return cls.instance
    
    @classmethod
    def clear_packet_record(cls):
        cls.packet_record = PacketList()
        
    @classmethod
    def sync_capture_lists(cls):
        cls.packet_record_buffer    = PacketList([packet for packet in cls.packet_record])
        cls.packet_record_filtered  = PacketList([packet for packet in cls.packet_record])
        
        logger.info(f"Synced lists:\n\t\tpacket_record: %s" % id(cls.packet_record) + \
                    f"\n\t\tpacket_record_buffer: %s" % id(cls.packet_record_buffer) + \
                    f"\n\t\tpacket_record_filtered: %s" % id(cls.packet_record_filtered))
        
    @classmethod
    def sync_displayed(cls):
        # Pass refference
        cls.packet_record_filtered = cls.packet_record
        
    @classmethod
    def extend(cls, _list: list):
        cls.packet_record.extend(_list)