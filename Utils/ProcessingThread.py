from Utils.PacketUtils import PacketProcessor
from PyQt5.QtCore import QThread
from PyQt5.QtCore import pyqtSignal
import logging
import errno

"""
Get standard logger declared inside main
"""
logger = logging.getLogger('standard')

class ProcessingThread(QThread):
    """ A class to create a dedicated QThread to process packets
    from a Multiprocessing module managed queue.

    Args:
        QThread (_type_): _description_
    """
    
    add_packet = pyqtSignal(list)
    def __init__(
        self,
        _managed_queue,                             # Multiprocessing module managed queue
        _packet_processor: PacketProcessor=None,    # PacketProcessor
        _parent=None):
        QThread.__init__(self, parent=_parent)
        
        if _packet_processor is None:
            self.packet_processor = PacketProcessor()
            
        self.packet_processor = _packet_processor
        self.managed_queue = _managed_queue
        self.managed_list = []
        self.running = True

    def run(self):
        logger.info("Starting processing thread")
        while self.running:
            try:
                packet = self.managed_queue.get()
                self.managed_list.append(packet)
                info = self.packet_processor.info(packet)
                
                self.add_packet.emit(info)
            except IOError as exception:
                if exception.errno == errno.EPIPE:
                    logger.error(exception)
                continue
            except EOFError as exception:
                logger.error(exception)
