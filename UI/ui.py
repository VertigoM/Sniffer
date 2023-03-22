from time import sleep
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from threading import Thread
from PyQt5.QtGui import (
    QFont,
    QIcon,
)
from shared import Shared
from Utils import (
    Sniffer,
    PacketUtils
)
import sys
import logging

logger = logging.getLogger('standard')

class Table(QTableWidget):
    def new_event(self):
        pass

class ProcessingThread(QThread):
    add_packet = pyqtSignal(list)

    def __init__(
        self,
        _managed_queue,
        _packet_processor: PacketUtils.PacketProcessor=None,
        _parent=None):
        QThread.__init__(self, parent=_parent)
        
        if _packet_processor is None:
            self.packet_processor = PacketUtils.PacketProcessor()
            
        self.packet_processor = _packet_processor
        self.managed_queue = _managed_queue
        self.managed_list = []
        self.running = True

    def run(self):
        logger.info("starting ProcessingThread.")
        while self.running:
            try:
                packet = self.managed_queue.get()
            except Exception as exception:
                logger.error(str(exception))
            
            self.managed_list.append(packet)
            info = self.packet_processor.info(packet)
            
            self.add_packet.emit(info)


class UIMainWindow(object):
    def __init__(self):
        self.shared = Shared()
        
        self.__main_widget = QWidget()
        self.__central_widget = self.__main_widget

        self.__main_widget.setFixedSize(1200, 800)

        ''' #Define global font '''
        self.global_font = QFont('Consolas', 10)
        ''' !Define global font '''

        ''' #Define layout'''
        self.outer_layout = QVBoxLayout(self.__central_widget)

        self.top_hbox_layout = self.create_top_horizontal_layout()

        self.top_toolbar_layout = self.create_top_toolbar_layout()
        
        self.bottom_layout = self.create_bottom_layout()

        self.packet_list_table = None
        self.create_packet_list_table()

        self.outer_layout.addLayout(self.top_toolbar_layout)
        self.outer_layout.addLayout(self.top_hbox_layout)
        self.outer_layout.addLayout(self.bottom_layout)

        self.outer_layout.addWidget(self.packet_list_table)

        self.outer_layout.addStretch()

        self.__central_widget.setLayout(self.outer_layout)
        ''' !Define layout'''

        self.worker = None

        self.packet_processor = PacketUtils.PacketProcessor()
        self.processing_thread = ProcessingThread(
            _packet_processor = self.packet_processor,
            _managed_queue = self.shared.managed_packet_queue)

        self.processing_thread.add_packet.connect(self.handle_packet)
        self.processing_thread.start()

    def create_top_toolbar_layout(self) -> QGridLayout:
        layout = QHBoxLayout()

        ''' #Create components '''
        self.start_button = QPushButton(self.__central_widget)
        self.start_button.setIcon(
            QIcon('resources/icons/play.png')
        )
        self.start_button.setMaximumSize(50, 50)
        self.start_button.resize(50, 50)
        self.start_button.setFlat(True)

        self.stop_button = QPushButton(self.__central_widget)
        self.stop_button.setIcon(
            QIcon('resources/icons/stop.png')
        )
        self.stop_button.resize(50, 50)
        self.stop_button.setMaximumSize(50, 50)
        self.stop_button.setFlat(True)
        
        self.save_button = QPushButton(self.__central_widget)
        self.save_button.setIcon(
            QIcon('resources/icons/save.png')
        )
        self.save_button.clicked.connect(self.save_file_to_fs)
        self.save_button.setFlat(True)
        
        self.load_button = QPushButton(self.__central_widget)
        self.load_button.setIcon(
            QIcon('resources/icons/load.png')
        )
        self.load_button.clicked.connect(self.load_file)
        self.load_button.setFlat(True)
        
        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)
        ''' !Create components '''
        
        self.toggle_locked: bool = False

        ''' #Add components to layout '''
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button, 1)
        layout.addWidget(QLabel('|'))
        layout.addWidget(self.save_button, 2)
        layout.addWidget(self.load_button, 3)
        layout.insertSpacing(-1, 1200)
        ''' !Add components to layout '''

        return layout

    def load_file(self) -> None:
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        files, _ = QFileDialog.getOpenFileNames(
            caption="QFileDialog.getOpenFileNames()", 
            directory="./saves",
            filter="All Files (*);;Packet Capture Files (*.pcap)", 
            options=options)
        if files:
            logger.info(f"Loaded file[s] in memory: {files}")
            self.load_file_in_memory(files)
            
    def load_file_in_memory(self, files: list) -> None:
        packets, sessions = Sniffer.Sniffer.get_offline_process(offline=files, filter=None)
        
        QCoreApplication.processEvents()
        self.session_filtering_field.setVisible(True)
        self.session_filtering_field.addItems(sessions)
        
        logger.info(f"Loaded {len(packets)} packets.")
        logger.info(sessions)
        
        self.shared.packet_record = packets
        self.display_packets(packets)      
            
    def save_file_to_fs(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getSaveFileName(
            caption="QFileDialog.getSaveFileName()",
            directory="./saves",
            filter="All Files (*);;",
            options=options)
        if fileName:
            try:
                PacketUtils.PacketProcessor.write_pcap(
                    self.shared.packet_record,
                    f"{fileName}.pcap")
                logger.info(f"Saved file '{fileName}.pcap',{len(self.shared.packet_record)},{sys.getsizeof(self.shared.packet_record)}b to file system.")
            except Exception as exception:
                logger.error(f"Met an exception while saving file to filesystem: {str(exception)}")
        
    def create_top_horizontal_layout(self) -> QHBoxLayout:
        ''' #Create layout '''
        hbox_layout = QHBoxLayout()
        ''' !Create layout '''

        ''' #Create components '''
        label_nic = QLabel(self.__central_widget)
        label_nic.setFont(self.global_font)
        label_nic.setText("NIC")

        self.combo_box = QComboBox(self.__central_widget)
        self.combo_box.setFont(self.global_font)

        self.combo_box.currentTextChanged.connect(self.interface_changed)
        ''' !Create components '''

        ''' #Add components to layout '''
        hbox_layout.addWidget(label_nic)
        hbox_layout.addWidget(self.combo_box, 1)
        ''' !Add components to layout '''

        return hbox_layout

    def create_packet_list_table(self) -> Table:
        self.packet_list_table = Table(self.__central_widget)
        self.packet_list_table.verticalHeader().setDefaultSectionSize(25)
        self.packet_list_table.horizontalHeader().setFont(self.global_font)
        self.packet_list_table.setSizeAdjustPolicy(
            QAbstractScrollArea.AdjustToContents
        )
        self.packet_list_table.setMinimumHeight(450)
        self.packet_list_table.setMaximumHeight(450)
        self.packet_list_table.setAutoScroll(False)
        
        self.packet_list_table.setColumnCount(6)
        [self.packet_list_table.setColumnWidth(i, 175) for i in range(1, 5)]
        self.packet_list_table.setColumnWidth(0, 50)
        self.packet_list_table.setColumnWidth(5, 425)

        self.packet_list_table.setHorizontalHeaderLabels(
            [
                'Time',
                'Source address',
                'Destination address',
                'Length',
                'Protocol',
                'Info'
            ]
        )
        self.packet_list_table.setSelectionBehavior(QTableView.SelectRows)
        self.packet_list_table.itemSelectionChanged.connect(self.selection_event)

    def selection_event(self):
        QCoreApplication.processEvents()
        
        self.shared.extend(self.processing_thread.managed_list)
        
        row = [item.row() for item in self.packet_list_table.selectedItems()][0]
        
        index = len(self.shared.packet_record) - row - 1
        logger.info(f"Number of sniffed packets: Total: {len(self.shared.packet_record)}, {(self.shared.packet_record)}")
        
        try:
            packet = self.shared.packet_record[index]
        except IndexError as error:
            logger.error(f"Selected packet: {index}\n\t{str(error)}")
            
        treeView = QTreeView()
        treeView.setHeaderHidden(True)
        treeView.setModel(PacketUtils.PacketProcessor.convert_packet_to_node(packet))
            
        self.tabWidget.addTab(
            treeView,
            f"Str.{(self.tabWidget.count())}"
        )
        logger.info(f"Selected packet: {index}\n{packet}")

    def create_bottom_layout(self):
        outer_layout = QVBoxLayout()
        innner_layout = QHBoxLayout()
        
        self.tabWidget = QTabWidget()
        self.tabWidget.setFixedHeight(200)
        
        self.tabWidget.setTabsClosable(True)
        self.tabWidget.tabCloseRequested.connect(self.remove_tab)
        
        self.filtering_field = QLineEdit()
        self.filtering_field.setPlaceholderText("BPF filter")
        self.filtering_field.textChanged.connect(self.validate_filter)
        
        self.session_filtering_field = QComboBox()
        self.session_filtering_field.setFixedWidth(400)
        self.session_filtering_field.setVisible(False)
        
        self.filter_button: QPushButton = QPushButton()
        self.filter_button.setFlat(True)
        self.filter_button.setIcon(
            QIcon("resources/icons/filter.png")
        )
        self.filter_button.setMaximumSize(50, 50)
        self.filter_button.resize(50, 50)
        self.filter_button.clicked.connect(self.filter_offline)
        
        innner_layout.addWidget(self.session_filtering_field)
        innner_layout.addWidget(self.filtering_field, 1)
        innner_layout.addWidget(self.filter_button, 2)
        
        outer_layout.addLayout(innner_layout)
        outer_layout.addWidget(self.tabWidget)
        return outer_layout
    
    def validate_filter(self):
        from scapy.arch.common import compile_filter
        from scapy.libs.structures import bpf_program
        
        filter = self.filtering_field.text()
        
        if filter == "":
            self.filtering_field.setStyleSheet("""QLineEdit { background-color: white;}""")
            
            self.filter_button.setEnabled(True)
            self.shared.filter_sequence = ""
            return
        try:
            if isinstance(compile_filter(filter), bpf_program):
                self.shared.filter_sequence = filter
                
                self.filter_button.setEnabled(True)
                self.filtering_field.setStyleSheet("""QLineEdit { background-color: #aeffae;}""")
        except:
            self.filter_button.setEnabled(False)
            self.filtering_field.setStyleSheet("""QLineEdit { background-color: #ffaeae;}""")         
    
    def filter_offline(self, record: str = None):
        # global packet_record
        
        # filter: str = self.filtering_field.text()
        # logger.info(f"Filter set: {filter}")
         
        # # fix this function
        # if record is None:
        #     record = packet_record    
        # filtered_packets = Sniffer.Sniffer.get_offline_process(offline=record, filter=filter)
        # self.display_packets(filtered_packets)
        pass
    
    def toggle_lock(self):
        self.toggle_locked = not self.toggle_locked
        self.filter_button.setEnabled(not self.filter_button.isEnabled())
        
        if "#d3d3d3" in self.filtering_field.styleSheet():
            self.filtering_field.setStyleSheet("""QLineEdit { background-color: #d3d3d3;}""")
        else:
            self.filtering_field.setStyleSheet("""QLineEdit { background-color: white;}""")
            
        self.filtering_field.setEnabled(not self.filtering_field.isEnabled())
        
        self.combo_box.setEnabled(not self.combo_box.isEnabled())
        
        self.start_button.setEnabled(not self.start_button.isEnabled())
        self.load_button.setEnabled(not self.load_button.isEnabled())
        self.save_button.setEnabled(not self.save_button.isEnabled())
        
          
    def remove_tab(self):
        self.tabWidget.removeTab(self.tabWidget.currentIndex())
    
    def populate(self) -> None:
        self.combo_box.addItems(self.shared.interfaces)

    def show(self) -> None:
        self.__main_widget.show()

    def interface_changed(self) -> None:
        self.shared.managed_dictionary['iface'] = self.combo_box.currentText()
        
    def start(self) -> None:
        # clear old data
        self.shared.clear_packet_record()
        self.packet_list_table.setRowCount(0)
        self.session_filtering_field.setVisible(False)
        
        filter: str = self.filtering_field.text()
        
        # Intialize a Sniffer instance 
        self.worker = Sniffer.Sniffer()
        self.toggle_lock()
        
        self.worker.start(
            prn=lambda p: self.shared.managed_packet_queue.put(p, block=True, timeout=0.2),
            iface=self.shared.managed_dictionary.get('iface'),
            filter=filter)

    def stop(self) -> None:
        # PacketUtils.PacketProcessor.write_pcap(packet_record)
        
        try:
            self.worker.stop()
            if self.toggle_locked == True:
                self.toggle_lock()
        except AttributeError as exception:
            logger.error(f"Sniffer not yet initialized: {str(exception)}")
            
    def display_packets(self, packet_list) -> None:
        # clear old packets from the table Widget
        self.packet_list_table.setRowCount(0)
        
        # fill with filtered packets
        for packet in packet_list:
            packet_info = self.packet_processor.info(packet)
            self.handle_packet(packet_info)

    def handle_packet(self, packet_info: list) -> None:
        self.packet_list_table.insertRow(0)
        for index, e in enumerate(packet_info):
            item = QTableWidgetItem()
            item.setText(str(e))
            self.packet_list_table.setItem(0, index, item)


def play():
    ''' time the execution '''
    from time import time

    start_time = time()
    
    application = QApplication([])
    window = UIMainWindow()

    window.populate()

    window.show()
    
    print(f'--- {time() - start_time} seconds ---')

    sys.exit(application.exec())