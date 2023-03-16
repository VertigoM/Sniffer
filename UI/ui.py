from time import sleep
from PyQt5.QtWidgets import (
    QWidget,
    QApplication,
    QHBoxLayout,
    QVBoxLayout,
    QComboBox,
    QLabel,
    QGridLayout,
    QPushButton,
    QTableWidget,
    QAbstractScrollArea,
    QTableWidgetItem,
    QTabWidget,
    QTreeView,
    QTableView,
    QInputDialog,
    QLineEdit,
    QFileDialog
)
from PyQt5.QtCore import (
    pyqtSignal,
    pyqtSlot,
    QThread,
    QCoreApplication,
    Qt
)
from multiprocessing import (
    Manager
)
from PyQt5.QtGui import (
    QFont,
    QIcon,
    QPalette
)
from shared import Shared
from Utils import (
    Sniffer,
    PacketUtils,
    IANA_Loader
)
import sys


manager = Manager()
shared = Shared()

shared.managed_dictionary = manager.dict()
shared.managed_packet_queue = manager.Queue()

filter_sequence = ""
valid_filter = False

from scapy.plist import PacketList
packet_record = PacketList()

identifier = IANA_Loader.IANA_Loader()

class Table(QTableWidget):
    def new_event(self):
        pass


class ProcessingThread(QThread):
    add_packet = pyqtSignal(list)
    save       = pyqtSignal()

    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)
        
        self.packet_processor = PacketUtils.PacketProcessor(identifier)
        self.isRunning = True

    def run(self):
        global shared
        while self.isRunning:
            try:
                packet = shared.managed_packet_queue.get()
            except Exception as _:
                continue

            # Packet procesing in order to be printed in the GUI
            # the wrapper may be transformed into a singleton
            info = self.packet_processor.info(packet)
            
            packet_record.append(packet)
            self.add_packet.emit(info)

    def stop(self):
        self.isRunning = False
        self.quit()
        self.wait()


class UIMainWindow(object):
    def __init__(self):
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

        # ----- TODO REMOVE -----
        self.outer_layout.addWidget(self.packet_list_table)

        self.outer_layout.addStretch()

        self.__central_widget.setLayout(self.outer_layout)
        ''' !Define layout'''

        self.worker = None

        ''' #Add signal handling '''

        ''' !Add signal handling '''

        self.processing_thread = ProcessingThread()
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

        self.stop_button = QPushButton(self.__central_widget)
        self.stop_button.setIcon(
            QIcon('resources/icons/stop.png')
        )
        self.stop_button.resize(50, 50)
        self.stop_button.setMaximumSize(50, 50)
        
        self.save_button = QPushButton(self.__central_widget)
        self.save_button.setIcon(
            QIcon('resources/icons/save.png')
        )
        
        self.load_button = QPushButton(self.__central_widget)
        self.load_button.setIcon(
            QIcon('resources/icons/load.png')
        )
        
        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)
        ''' !Create components '''

        ''' #Add components to layout '''
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button, 1)
        layout.addWidget(QLabel('|'))
        layout.addWidget(self.save_button, 2)
        layout.addWidget(self.load_button, 3)
        layout.insertSpacing(-1, 1200)
        ''' !Add components to layout '''

        return layout
        

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
        row = [item.row() for item in self.packet_list_table.selectedItems()][0]
        
        index = len(packet_record) - row - 1
        
        packet = None
        try:
            packet = packet_record[index]
        except IndexError as error:
            print(str(error))
            
        treeView = QTreeView()
        treeView.setHeaderHidden(True)
        treeView.setModel(PacketUtils.PacketProcessor.convert_packet_to_node(packet))
            
        self.tabWidget.addTab(
            treeView,
            f"Str.{index}"
        )
        print(f"idx: {index}\n{packet}")

    def create_bottom_layout(self):
        outer_layout = QVBoxLayout()
        innner_layout = QHBoxLayout()
        
        self.tabWidget = QTabWidget()
        
        self.tabWidget.setTabsClosable(True)
        self.tabWidget.tabCloseRequested.connect(self.remove_tab)
        
        self.filtering_field = QLineEdit()
        self.filtering_field.textChanged.connect(self.validate_filter)
        
        self.filter_button: QPushButton = QPushButton()
        self.filter_button.setFlat(True)
        self.filter_button.setIcon(
            QIcon("resources/icons/filter.png")
        )
        self.filter_button.setMaximumSize(50, 50)
        self.filter_button.resize(50, 50)
        self.filter_button.clicked.connect(self.filter)
        
        innner_layout.addWidget(self.filtering_field)
        innner_layout.addWidget(self.filter_button, 1)
        
        outer_layout.addLayout(innner_layout)
        outer_layout.addWidget(self.tabWidget)
        return outer_layout
    
    def validate_filter(self):
        global filter_sequence
        
        from scapy.arch.common import compile_filter
        from scapy.libs.structures import bpf_program
        
        filter = self.filtering_field.text()
        
        if filter == "":
            self.filtering_field.setStyleSheet("""QLineEdit { background-color: white;}""")
            
            self.filter_button.setEnabled(True)
            filter_sequence = ""
            return
        try:
            if isinstance(compile_filter(filter), bpf_program):
                filter_sequence = filter
                
                self.filter_button.setEnabled(True)
                self.filtering_field.setStyleSheet("""QLineEdit { background-color: green;}""")
        except:
            self.filter_button.setEnabled(False)
            self.filtering_field.setStyleSheet("""QLineEdit { background-color: red;}""")         
    
    def filter(self):
        global packet_record
        
        filter: str = self.filtering_field.text()
        # refilter sniffed packets
        
        from scapy.sendrecv import sniff
        filtered_packets = sniff(offline=packet_record, filter=filter)
        print(filtered_packets)
        
    
    def remove_tab(self):
        self.tabWidget.removeTab(self.tabWidget.currentIndex())
    
    def populate(self, shared: Shared) -> None:
        self.combo_box.addItems(shared.interfaces)

    def show(self) -> None:
        self.__main_widget.show()

    def interface_changed(self) -> None:
        global shared
        shared.managed_dictionary['iface'] = self.combo_box.currentText()
        print(f"changed {shared.managed_dictionary['iface']}")

    def start(self) -> None:
        global shared
        
        # clear old data
        packet_record = PacketList()
        self.packet_list_table.setRowCount(0)
        
        
        self.worker = Sniffer.Sniffer(
            prn=lambda p: shared.managed_packet_queue.put(p, block=True, timeout=0.2),
            iface=shared.managed_dictionary.get('iface'))
        self.worker.start()

    def stop(self) -> None:
        global packet_record
        PacketUtils.PacketProcessor.write_pcap(packet_record)
        
        self.worker.stop()

    def handle_packet(self, info) -> None:
        # add packet info to table
        self.packet_list_table.insertRow(0)
        for idx, e in enumerate(info):
            item = QTableWidgetItem()
            item.setText(str(e))
            self.packet_list_table.setItem(0, idx, item)


def play():
    ''' time the execution '''
    from time import time

    start_time = time()
    
    application = QApplication([])
    window = UIMainWindow()

    global shared
    window.populate(shared)

    window.show()
    
    print(f'--- {time() - start_time} seconds ---')

    sys.exit(application.exec())