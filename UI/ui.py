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
    QTableWidgetItem
)
from PyQt5.QtCore import (
    QObject,
    QRunnable,
    pyqtSignal,
    pyqtSlot,
    QThreadPool,
    QThread
)
from multiprocessing import (
    Process,
    Manager
)
from PyQt5.QtGui import QFont
from shared import Shared
from Utils import (
    Sniffer,
    PacketUtilsWrapper,
    IANA_Loader
)
import sys


manager = Manager()
shared = Shared()

shared.managed_dictionary = manager.dict()
shared.managed_packet_queue = manager.Queue()

# should its dict be passes as managed object
# instead of being coppied 
identifier = IANA_Loader.IANA_Loader()

class Table(QTableWidget):
    def new_event(self):
        pass


# ----- TODO: modify in order to fit proper usage ----
class ProcessingThread(QThread):
    add_packet = pyqtSignal(list)

    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)
        self.isRunning = True

    def run(self):
        global shared
        while self.isRunning:
            try:
                packet = shared.managed_packet_queue.get()
            except Exception as _:
                continue

            # ---- TODO: remove or improve ----
            w_p = PacketUtilsWrapper.PacketUtilsWrapper(packet, identifier)
            # print(type(packet), flush=True)
            self.add_packet.emit(w_p.info())

    def stop(self):
        self.isRunning = False
        self.quit()
        self.wait()
# ------------------------------------------------------


class UIMainWindow(object):
    def __init__(self):
        self.__main_widget = QWidget()
        self.__central_widget = self.__main_widget

        self.__main_widget.resize(1200, 800)

        ''' #Define global font '''
        self.global_font = QFont('Consolas', 10)
        ''' !Define global font '''

        ''' #Define layout'''
        self.outer_layout = QVBoxLayout(self.__central_widget)

        self.combo_box = None
        self.top_hbox_layout = self.create_top_horizontal_layout()

        self.start_button = None
        self.stop_button = None
        self.top_toolbar_layout = self.create_top_toolbar_layout()

        self.packet_list_table = None
        self.create_packet_list_table()

        self.outer_layout.addLayout(self.top_toolbar_layout)
        self.outer_layout.addLayout(self.top_hbox_layout)

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
        grid_layout = QGridLayout()

        ''' #Create components '''
        self.start_button = QPushButton("Start")
        self.start_button.setFont(self.global_font)

        self.stop_button = QPushButton("Stop")
        self.stop_button.setFont(self.global_font)

        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)
        ''' !Create components '''

        ''' #Add components to layout '''
        grid_layout.addWidget(self.start_button, 0, 0)
        grid_layout.addWidget(self.stop_button, 0, 1)
        ''' !Add components to layout '''

        return grid_layout

    def create_top_horizontal_layout(self) -> QHBoxLayout:
        ''' #Create layout '''
        hbox_layout = QHBoxLayout()
        ''' !Create layout '''

        ''' #Create components '''
        label_nic = QLabel()
        label_nic.setFont(self.global_font)
        label_nic.setText("NIC")

        self.combo_box = QComboBox()
        self.combo_box.setFont(self.global_font)

        self.combo_box.currentTextChanged.connect(self.interface_changed)
        ''' !Create components '''

        ''' #Add components to layout '''
        hbox_layout.addWidget(label_nic)
        hbox_layout.addWidget(self.combo_box, 1)
        ''' !Add components to layout '''

        return hbox_layout

    def create_packet_list_table(self) -> Table:
        self.packet_list_table = Table()
        self.packet_list_table.verticalHeader().setDefaultSectionSize(25)
        self.packet_list_table.horizontalHeader().setFont(self.global_font)
        self.packet_list_table.setSizeAdjustPolicy(
            QAbstractScrollArea.AdjustToContents
        )
        self.packet_list_table.setMinimumHeight(50)
        self.packet_list_table.setMaximumHeight(300)
        self.packet_list_table.setColumnCount(6)
        [self.packet_list_table.setColumnWidth(i, 200) for i in range(6)]

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

        # ----- TODO - remove -----
        self.packet_list_table.insertRow(0)
        for i in range(6):
            item = QTableWidgetItem()
            item.setText("DEBUG")
            self.packet_list_table.setItem(0, i, item)
        # ------------------------

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
        self.worker = Sniffer.Sniffer(
            prn=lambda p: shared.managed_packet_queue.put(p, block=True, timeout=0.2),
            iface=shared.managed_dictionary.get('iface'))
        self.worker.start()

    def stop(self) -> None:
        # TODO - remove
        # quick and dirty
        global shared
        self.worker.stop()
        print('--- Started printing ---')
        while not shared.managed_packet_queue.empty():
            item = shared.managed_packet_queue.get(block=True, timeout=0.1)
            print(item, flush=True)

    def handle_packet(self, info) -> None:
        print(f"handle_packet::received_info:{info}")
        self.packet_list_table.insertRow(0)
        for idx, e in enumerate(info):
            item = QTableWidgetItem()
            item.setText(str(e))
            self.packet_list_table.setItem(0, idx, item)


def play():
    ''' time the execution '''
    from time import time

    application = QApplication([])
    window = UIMainWindow()

    global shared
    window.populate(shared)

    window.show()
    #print(f'--- {time() - start_time} seconds ---')

    sys.exit(application.exec())
