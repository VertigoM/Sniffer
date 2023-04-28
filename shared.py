from scapy.interfaces import ifaces
from multiprocessing import Manager
from scapy.plist import PacketList
import logging

"""
Get standard logger declard inside main
"""
logger = logging.getLogger('standard')

class Shared(object):
    """
    Container class for managed shared objects
    """
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Shared, cls).__new__(cls)
            cls.manager = Manager()
            
            """
            Load available network interfaces
            """
            cls.interfaces = ifaces
            cls.managed_dictionary = cls.manager.dict()
            cls.managed_packet_queue = cls.manager.Queue()
            
            cls.filter_sequence = ""
            cls.filter_isValid = True
            
            cls.packet_record = PacketList()
            cls.packet_record_filtered = PacketList()
            
            cls.buffered_filename = None
        return cls.instance
        
    @classmethod
    def sync_capture_lists(cls):
        """
        Record packets collected inside packet_record to packet_record_filtered
        """
        cls.packet_record_filtered = PacketList([packet for packet in cls.packet_record])
        
        logger.info(f"Synced lists:\n\t\tpacket_record: %s" % id(cls.packet_record) + \
                    f"\n\t\tpacket_record_filtered: %s" % id(cls.packet_record_filtered))
        
    @classmethod
    def sync_shared(cls, packet_list: list):
        """
        Record packet collected inside packet_list to packet_record
        """
        cls.packet_record = PacketList([packet for packet in packet_list])
        
    @classmethod
    def reset_packet_records(cls):
        """
        Reset both collecting lists
        """
        cls.packet_record = PacketList()
        cls.packet_record_filtered = PacketList()