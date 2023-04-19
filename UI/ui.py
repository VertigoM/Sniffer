from time import sleep
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import (
    QFont,
    QIcon,
    QCursor
)
from shared import Shared
from Utils import (
    Sniffer,
    PacketUtils
)
import sys
import logging
import errno

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
                self.managed_list.append(packet)
                info = self.packet_processor.info(packet)
                
                self.add_packet.emit(info)
            except IOError as exception:
                if exception.errno == errno.EPIPE:
                    logger.error(f"ProcesssingThread::IOError:\n{str(exception)}")
                continue
            except EOFError as exception:
                logger.error(f"ProcessingThread::EOFError:\n{str(exception)}")

class ExternalWindow(object):
    def __init__(self):
        super().__init__()
        self.main_widget = QWidget()
        
        self.layout = QVBoxLayout(self.main_widget)
        self.main_widget.setLayout(self.layout)
        
    def set_custom_layout(self, _layout):
        self.layout.parent = None
        self.main_widget.setLayout = _layout
        
    def show(self) -> None:
        self.main_widget.show()
        
class UIMainWindow(object):
    def __init__(self):
        self.shared = Shared()
        
        self.__main_widget = QWidget()
        self.__central_widget = self.__main_widget

        self.__main_widget.setFixedSize(1200, 800)
        self.external_window = None

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
        
        self.processing_thread = None
        
        self.live_sniffing = False

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
            caption="Load .pcap file", 
            directory="./saves",
            filter="All Files (*);;Packet Capture Files (*.pcap)", 
            options=options)
        if files:
            logger.info(f"Loaded file[s] in memory: {files}")
            
            self.shared.buffered_filename = files
            self.load_file_in_memory(files)
            
    def load_file_in_memory(self, files: list) -> None:      
        packets, sessions = Sniffer.Sniffer.get_offline_process(offline=files, filter=None)
        
        QCoreApplication.processEvents()
        self.session_filtering_field.setVisible(True)
        self.filter_button.setVisible(True)
        self.filter_button__outgoing_traffic.setVisible(True)
        self.filter_button__ingoing_traffic.setVisible(True)
        self.session_filtering_field.addItems(sessions)
        self.filtering_field.setText("")
        self.packet_list_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.packet_list_table.customContextMenuRequested.connect(self.handle_packet_list_packet_pressed)
        
        logger.info(f"Loaded {len(packets)} packets.")
        
        self.shared.sync_shared(packets)
        self.display_packets(packets)      
        
    def handle_packet_list_packet_pressed(self) -> None:
        menu    = QMenu()
        packet  = None
        
        try:
            packet = self.selection_event()
        except Exception as exception:
            self.pop_error_dialog(str(exception))
            
        if packet is None:
            return
        
        _details = QAction("Details")
        _details.triggered.connect(lambda: self.create_tree_view(packet))
        menu.addAction(_details)
        
        _raw = QAction("Raw")
        _raw.triggered.connect(lambda: self.pop_external_window__raw(packet))
        menu.addAction(_raw)

        _repeat = QAction("Repeat")
        _repeat.triggered.connect(lambda: self.pop_external_window__forger(packet))
        menu.addAction(_repeat)
        
        if not self.packet_processor.check_outgoing(packet):
            _repeat.setEnabled(False)
            _repeat.setText("Repeat - only outgoing traffic can be repeated")
        
        c_pos = QCursor.pos()
        menu.exec_(c_pos)
            
    def save_file_to_fs(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getSaveFileName(
            caption="Save .pcap file",
            directory="./saves",
            filter="All Files (*);;",
            options=options)
        if fileName:
            try:
                QCoreApplication.processEvents()
                self.shared.sync_shared(self.processing_thread.managed_list)
                
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
        self.packet_list_table.setEditTriggers(QTableWidget.NoEditTriggers)
        #self.packet_list_table.itemSelectionChanged.connect(self.selection_event)

    def selection_event(self):
        QCoreApplication.processEvents()
        
        select_from = None
        if self.live_sniffing:
            _l0 = len(self.processing_thread.managed_list)
            _l1 = len(self.shared.packet_record)
            logger.info(f"Syncing:\n\tprocessing_thread.managed_list: {_l0} packets" +
                        f"\n\tshared.packet_record: {_l1} packets" + 
                        f'\n\t{_l0 - _l1} packets added.')
            self.shared.sync_shared(self.processing_thread.managed_list)
            select_from = self.shared.packet_record
        else:
            select_from = self.shared.packet_record_filtered
        
        row = 0
        try:
            row = [item.row() for item in self.packet_list_table.selectedItems()][0]
        except IndexError as exception:
            logger.error(f"Selected:{self.packet_list_table.selectedItems()}\n\t{str(exception)}")
            return
        
        index = len(select_from) - row - 1
        
        packet = None
        try:
            packet = select_from[index]
        except IndexError as error:
            logger.error(f"Selected packet: {index}\n\t{str(error)}")
        
        logger.info(f"Selected packet: {index}\n\t{packet}")
        return packet
            
    def create_tree_view(self, packet):
        
        treeView = QTreeView()
        try:
            treeView.setHeaderHidden(True)
            treeView.setModel(PacketUtils.PacketProcessor.convert_packet_to_node(packet))
                
            self.tabWidget.addTab(
                treeView,
                f"Str.{(self.tabWidget.count())}"
            )
        except Exception as error:
            logger.error(f"Selection event::{str(error)}")
        # logger.info(f"Selected packet: {index}\n\t{packet}")

    def create_bottom_layout(self):
        outer_layout = QVBoxLayout()
        inner_layout__1 = QHBoxLayout()
        inner_layout__2 = QHBoxLayout()
        inner_layout__3 = QHBoxLayout()
        
        self.tabWidget = QTabWidget()
        self.tabWidget.setFixedHeight(200)
        
        self.tabWidget.setTabsClosable(True)
        self.tabWidget.tabCloseRequested.connect(self.remove_tab)
        
        inner_layout__3.addWidget(self.tabWidget)
        
        self.filtering_field = QLineEdit()
        self.filtering_field.setPlaceholderText("BPF filter")
        self.filtering_field.textChanged.connect(self.validate_filter)
        
        self.session_filtering_field = QComboBox()
        self.session_filtering_field.setFixedWidth(400)
        self.session_filtering_field.setStyleSheet("QComboBox { combobox-popup: 0; }");
        self.session_filtering_field.setMaxVisibleItems(20)
        self.session_filtering_field.setVisible(False)
        self.session_filtering_field.view().pressed.connect(self.handle_filtering_field_item_pressed)
        
        self.filter_button: QPushButton = QPushButton()
        self.filter_button.setFlat(True)
        self.filter_button.setIcon(
            QIcon("resources/icons/filter.png")
        )
        self.filter_button.setMaximumSize(50, 50)
        self.filter_button.resize(50, 50)
        self.filter_button.setVisible(False)
        self.filter_button.clicked.connect(self.filter_offline)
        
        self.filter_button__outgoing_traffic: QPushButton = QPushButton()
        self.filter_button__ingoing_traffic: QPushButton  = QPushButton()
        
        self.filter_button__outgoing_traffic.setMaximumSize(200, 50)
        self.filter_button__outgoing_traffic.resize(200, 50)
        self.filter_button__outgoing_traffic.setText("Filter outgoing traffic")
        self.filter_button__outgoing_traffic.setFont(self.global_font)
        self.filter_button__outgoing_traffic.clicked.connect(lambda: self.filter_offline(
            lfilter=self.packet_processor.get_traffic_outgoing()
        ))
        self.filter_button__outgoing_traffic.setVisible(False)
        
        self.filter_button__ingoing_traffic.setMaximumSize(200, 50)
        self.filter_button__ingoing_traffic.resize(200, 50)
        self.filter_button__ingoing_traffic.setFont(self.global_font)
        self.filter_button__ingoing_traffic.setText("Filter ingoing traffic")
        self.filter_button__ingoing_traffic.clicked.connect(lambda: self.filter_offline(
            lfilter=self.packet_processor.get_traffic_ingoing()
        ))
        self.filter_button__ingoing_traffic.setVisible(False)
        
        inner_layout__1.addWidget(self.session_filtering_field, 0)
        inner_layout__1.addWidget(self.filtering_field, 1)
        inner_layout__1.addWidget(self.filter_button, 2)
        
        inner_layout__2.addWidget(self.filter_button__outgoing_traffic, 0)
        inner_layout__2.addWidget(self.filter_button__ingoing_traffic, 1)
        inner_layout__2.insertSpacing(-1, 800)
        
        outer_layout.addLayout(inner_layout__1)
        outer_layout.addLayout(inner_layout__2)
        outer_layout.addLayout(inner_layout__3)
        return outer_layout
    
    def handle_filtering_field_item_pressed(self, _index: int) -> None:
        item = self.session_filtering_field.model().itemFromIndex(_index)
        
        menu = QMenu()
        
        _details = QAction("Details")
        _details.triggered.connect(lambda t: print("Handle::triggered::details"))
        menu.addAction(_details)
        
        _extract_content = QAction("Extract content")
        _extract_content.triggered.connect(lambda t: print("Handle::triggered::extract_content"))
        menu.addAction(_extract_content)
        
        _repeat = QAction("Repeat")
        #_repeat.triggered.connect(self.pop_external_window__forger)
        menu.addAction(_repeat)
        
        c_pos = QCursor.pos()
        menu.exec_(c_pos)
        
    def pop_external_window__forger(self, packet) -> None:
        try:
            self.external_window.close()
            self.external_window = None
        except AttributeError as error:
            logger.debug(f"external_window::forger {str(error)}")
        
        self.external_window = QWidget()
        self.external_window.setFixedSize(1000, 800)
        self.external_window.setWindowTitle("Repeater")
        
        inner_layout__1 = QGridLayout()
        
        editable_field_widget = QTextEdit()
        editable_field_widget.setFont(self.global_font)
        editable_field_widget.setText(packet.show(dump=True))
        
        try:
            print(packet.fields_desc)
        except Exception as exception:
            self.pop_error_dialog(str(exception))
        
        _request_label = QLabel("Request")
        _request_label.setFont(self.global_font)
        inner_layout__1.addWidget(_request_label, 1, 0, 1, 1)
        
        _response_label = QLabel("Response")
        _response_label.setFont(self.global_font)
        inner_layout__1.addWidget(_response_label, 1, 3, 1, 1)
        
        inner_layout__1.addWidget(QPushButton("Send"), 0, 3, 1, 2)
        
        inner_layout__1.addWidget(editable_field_widget, 2, 0, -1, 2)
        inner_layout__1.addWidget(QTextEdit(), 2, 3, -1, 2)
        
        self.external_window.setLayout(inner_layout__1)
        self.external_window.show()
        
    def pop_external_window__raw(self, packet) -> None:
        try:
            self.external_window.close()
            self.external_window = None
        except AttributeError as error:
            logger.debug(f"external_window::raw {str(error)}")
        
        from struct import error as error_struct
        from scapy.error import Scapy_Exception
        
        self.external_window = ExternalWindow()
        self.external_window.main_widget = QTabWidget()
        self.external_window.main_widget.setFixedSize(800, 600)
        self.external_window.main_widget.setWindowTitle("Raw")
        
        _dump_packet__plain = None
        try:
            _dump_packet__plain = packet.show(dump=True)
        except error_struct as error:
            self.pop_error_dialog__frame_exceeded(packet)
            logger.error(str(error))
        except Scapy_Exception as error:
            logger.error(str(error))
            self.pop_error_dialog(str(error))
            
        if _dump_packet__plain is None:
            return
            
        from scapy.utils import hexdump
        
        _dump_packet__hex = None
        try:
            _dump_packet__hex = hexdump(packet, dump=True)
        except error_struct as error:
            self.pop_error_dialog__frame_exceeded(packet)
            logger.error(str(error))
        except Scapy_Exception as error:
            logger.error(str(error))
            self.pop_error_dialog(str(error))
            
        if _dump_packet__hex is None:
            return
        
        _raw_widget = QTextBrowser()
        _raw_widget.setText(_dump_packet__plain)
        _raw_widget.setFont(self.global_font)
        self.external_window.main_widget.addTab(_raw_widget, "Raw View")
        
        _hex_widget = QTextBrowser()
        _hex_widget.setText(_dump_packet__hex)
        _hex_widget.setFont(self.global_font)
        self.external_window.main_widget.addTab(_hex_widget, "Hex View")
        self.external_window.show()
        
    def pop_dialog__details(self) -> None:
        dialog = QDialog()
    
    def validate_filter(self):
        from scapy.arch.common import compile_filter
        from scapy.libs.structures import bpf_program
        
        filter = self.filtering_field.text()
        
        if filter == "":
            self.filtering_field.setStyleSheet("""QLineEdit { background-color: white;}""")
            
            self.filter_button.setEnabled(True)
            self.shared.filter_sequence = ""
            self.shared.filter_isValid = True
            self.start_button.setEnabled(True)
             
            return
        try:
            if isinstance(compile_filter(filter), bpf_program):
                self.shared.filter_sequence = filter
                self.shared.filter_isValid = True
                self.start_button.setEnabled(True)
                
                self.filter_button.setEnabled(True)
                self.filtering_field.setStyleSheet("""QLineEdit { background-color: #aeffae;}""")
        except:
            self.filter_button.setEnabled(False)
            self.shared.filter_isValid = False
            self.start_button.setEnabled(False)
            
            self.filtering_field.setStyleSheet("""QLineEdit { background-color: #ffaeae;}""")         
    
    def filter_offline(self, lfilter=None):
        from scapy.error import Scapy_Exception
        QCoreApplication.processEvents()
        self.shared.sync_capture_lists()
        # Filter already sniffed packets
        filter: str = ""
        if self.shared.filter_isValid:
            filter: str = self.filtering_field.text()
        
        logger.info(self.shared.packet_record)
        
        # All the loaded packets are located under shared.packet_record
        # Copy packets to shared.packet_record_buffer
        
        self.shared.packet_record_buffer = self.shared.packet_record
        
        # Filter packets and copy them to packet record
        offline_sniffer = Sniffer.Sniffer()
        try:
            self.shared.packet_record_filtered, _ = offline_sniffer.get_offline_process(
            offline=self.shared.buffered_filename,
            filter=filter,
            lfilter=lfilter)
        except Scapy_Exception as exception:
            self.pop_error_dialog(f"ERROR:{str(exception)}\nFor more details see logs")
            return
        self.display_packets(self.shared.packet_record_filtered)
    
    def toggle_lock(self):
        self.toggle_locked = not self.toggle_locked
        self.filter_button.setEnabled(not self.filter_button.isEnabled())
        self.packet_list_table.setContextMenuPolicy(Qt.DefaultContextMenu)
        
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
        self.shared.reset_packet_records()
        self.packet_list_table.setRowCount(0)
        self.session_filtering_field.setVisible(False)
        self.filter_button__outgoing_traffic.setVisible(False)
        self.filter_button__ingoing_traffic.setVisible(False)
        self.live_sniffing = True
        
        filter = ""
        if self.shared.filter_isValid:
            filter: str = self.filtering_field.text()
            
        logger.info(f"Started sniffing with filter: {filter}")
        
        # Intialize a Sniffer instance 
        self.worker = Sniffer.Sniffer()
        self.toggle_lock()
        
        self.processing_thread = ProcessingThread(
            _packet_processor = self.packet_processor,
            _managed_queue = self.shared.managed_packet_queue)
        
        logger.info(f"Created a new processing thread instance: {id(self.processing_thread)}")

        self.processing_thread.add_packet.connect(self.handle_packet)
        self.processing_thread.start()
        
        self.worker.start(
            prn=lambda p: self.shared.managed_packet_queue.put(p, block=True, timeout=0.2),
            iface=self.shared.managed_dictionary.get('iface'),
            filter=filter)

    def stop(self) -> None:
        # PacketUtils.PacketProcessor.write_pcap(packet_record)
        
        # sync
        self.shared.sync_shared(self.processing_thread.managed_list)
        self.live_sniffing = False
        
        self.processing_thread.isRunning = False
        
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
        
    def pop_error_dialog(self, exception_text: str) -> None:
        dlg = QDialog()
        
        dlg.setWindowTitle("Oops!")
        
        dlg.layout = QVBoxLayout()
        err_mesg   = QLabel(exception_text)
        dlg.layout.addWidget(err_mesg)
        dlg.setLayout(dlg.layout)
        
        dlg.exec_()
        
    def pop_error_dialog__frame_exceeded(self, packet) -> None:
        dlg = QDialog()
        
        dlg.setWindowTitle("Oops!")
        QBtn = QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        button_box = QDialogButtonBox(QBtn)
        
        message = QLabel("Max frame dimension - 65545 - exceeded\nDo you want to save packet content to a file?\n\nNote: The payload will be saved to a separate file.")

        button_box.accepted.connect(lambda: self.pop_error_dialog__frame_exceeded_accepted(packet, dlg))
        button_box.rejected.connect(lambda: dlg.close())
        
        layout = QVBoxLayout()
        layout.addWidget(message)
        layout.addWidget(button_box)
        dlg.setLayout(layout)
        
        dlg.exec_()
        
    def pop_error_dialog__frame_exceeded_accepted(self, packet, parent: QDialog) -> None:
        with open("dump.bin", "wb") as handler:
            handler.write(packet.show(dump=True).encode("utf-8"))
            
            payload = self.packet_processor.get_raw_payload(packet)
                
            if payload is not None:
                with open("dump_load.bin", "wb") as bin_handler:
                    bin_handler.write(payload)
        try:
            parent.close()
        except Exception as error:
            self.pop_error_dialog(str(error))

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