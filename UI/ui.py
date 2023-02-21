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
)
from PyQt5.QtCore import (
    QObject,
    QRunnable,
    pyqtSignal,
    pyqtSlot,
    QThreadPool
)
from multiprocessing import (
    Process,
    Manager
)
from PyQt5.QtGui import QFont
from shared import Shared
from Utils import Sniffer
import sys
import logging

manager = Manager()
managed_dictionary = manager.dict()


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

        self.outer_layout.addLayout(self.top_toolbar_layout)
        self.outer_layout.addLayout(self.top_hbox_layout)
        self.outer_layout.addStretch()

        self.__central_widget.setLayout(self.outer_layout)
        ''' !Define layout'''

        self.worker = None

        ''' #Add signal handling '''

        ''' !Add signal handling '''

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

    def populate(self, shared: Shared) -> None:
        self.combo_box.addItems(shared.interfaces)

    def show(self) -> None:
        self.__main_widget.show()

    def interface_changed(self) -> None:
        global managed_dictionary
        managed_dictionary['iface'] = self.combo_box.currentText()
        print(f"changed {managed_dictionary['iface']}")

    def start(self) -> None:
        self.worker = Sniffer.Sniffer(prn=lambda t: t.summary(), iface=managed_dictionary.get('iface'))
        self.worker.start()

    def stop(self) -> None:
        self.worker.stop()


def play():
    ''' time the execution '''
    from time import time
    start_time = time()

    application = QApplication([])
    window = UIMainWindow()

    shared = Shared()
    window.populate(shared)

    manager = Manager()
    packet_list = manager.Queue()

    window.show()
    print(f'--- {time() - start_time} seconds ---')

    sys.exit(application.exec())
