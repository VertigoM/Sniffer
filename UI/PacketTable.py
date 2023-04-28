from PyQt5.QtWidgets import QTableWidget
from PyQt5.QtWidgets import QWidget
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QAbstractScrollArea
from Utils.ProcessingThread import ProcessingThread
from scapy.packet import Packet
from shared import Shared
from typing import Any
import logging

"""
Get standard logger declard inside main
"""
logger = logging.getLogger('standard')

class PacketTable(QTableWidget):
    """
    Class for displaying packet list infomation
    """
    def __init__(self, 
                _parent: QWidget,
                _section_size: int,
                _font: QFont,
                _min_height: int,
                _max_height: int,
                _no_columns: int,
                _col_width: int,
                _no_col_width: int,
                _info_col_width: int,
                _horizontal_header_labels: list,
                _selection_behavior: Any,
                _edit_triggers: Any
                ):
        super().__init__(_parent)
        self.verticalHeader().setDefaultSectionSize(_section_size)
        self.horizontalHeader().setFont(_font)
        self.setSizeAdjustPolicy(
            QAbstractScrollArea.AdjustToContents
        )
        self.setFixedHeight(min(_min_height, _max_height))
        self.setAutoScroll(False)
        self.setColumnCount(_no_columns)
        for i in range(1, self.columnCount()):
            self.setColumnWidth(i, _col_width)
        self.setColumnWidth(0, _no_col_width)
        self.setColumnWidth(_no_columns - 1, _info_col_width)
        self.setHorizontalHeaderLabels(_horizontal_header_labels)
        self.setSelectionBehavior(_selection_behavior)
        self.setEditTriggers(_edit_triggers)
        
    def item_selection_event(self,
                             _live_sniffing: bool,
                             _shared: Shared,
                             _processing_thread: ProcessingThread=None) -> Packet:
        """Function for returning selected packet from UI.packet_list_table

        Args:
            _live_sniffing (bool): either the app is used for live or offline sniffing
            _shared (Shared): Shared object
            _processing_thread (ProcessingThread, optional): ProcessingThread object. Defaults to None.

        Returns:
            Packet: selected packet form UI.packet_list_table or None if exception is met
        """
        packet_record = _shared.packet_record
        try:
            managed_list = _processing_thread.managed_list
        except:
            managed_list = []
        
        select_from = None
        if _live_sniffing:
            l0 = len(managed_list)
            l1 = len(packet_record)
            
            logger.info(
            f"Syncing:\n\tprocessing_thread.managed_list: {l0} packets" +
            f"\n\tshared.packet_record: {l1} packets" + 
            f'\n\t{l0 - l1} packets added.')
            
            _shared.sync_shared(managed_list)
            select_from = packet_record
        else:
            _shared.sync_capture_lists()
            select_from = _shared.packet_record_filtered
            
        row = 0
        try:
            row = [item.row() for item in self.selectedItems()][0]
        except IndexError as exception:
            logger.error(f"Selected:{self.packet_list_table.selectedItems()}\n\t{str(exception)}")
            return
        
        index = len(select_from) - row - 1
        packet = None
        
        try:
            packet = select_from[index]
        except IndexError as exception:
            logger.error(f"Selected packet at invalid index: {index}\n\t{str(exception)}")
        
        return packet