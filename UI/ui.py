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
from scapy.all import *
import sys

global flag_dict
flag_dict = dict()
flag_dict['iface'] = ''


class WorkerSignals(QObject):
    finished    = pyqtSignal()
    error       = pyqtSignal(tuple)
    result      = pyqtSignal(object)
    

class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()
        self.fn         = fn
        self.args       = args
        self.kwargs     = kwargs
        self.signals    = WorkerSignals()
    
    @pyqtSlot()
    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()
    

class UI_main_window():
    def __init__(self):
        self.__main_widget = QWidget()
        self.__central_widget = self.__main_widget
        
        self.__main_widget.resize(1200, 800)
        
        ''' #Define global font '''
        self.global_font = QFont('Consolas', 10)
        ''' !Define global font '''
        
        ''' #Define layout'''
        self.outer_layout = QVBoxLayout(self.__central_widget)
        
        self.top_hbox_layout    = self.create_top_horizontal_layout()
        self.top_toolbar_layout = self.create_top_toolbar_layout()
        
        self.outer_layout.addLayout(self.top_toolbar_layout)
        self.outer_layout.addLayout(self.top_hbox_layout)
        self.outer_layout.addStretch()
        
        self.__central_widget.setLayout(self.outer_layout)
        ''' !Define layout'''
        
        ''' #Add signal handling '''
        global flag_dict
        
        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.start)
        ''' !Add signal handling '''
        
        self.thread_pool = QThreadPool()
        
    
    def create_top_toolbar_layout(self) -> QGridLayout:
        ''' #Create layout '''
        grid_layout = QGridLayout()
        ''' !Create layout '''
        
        ''' #Create components '''
        self.start_button = QPushButton("Start")
        self.start_button.setFont(self.global_font)
        
        self.stop_button  = QPushButton("Stop")
        self.stop_button.setFont(self.global_font)
        ''' !Create components '''
        
        ''' #Add components to layout '''
        grid_layout.addWidget(self.start_button, 0, 0)
        grid_layout.addWidget(self.stop_button,  0, 1)
        ''' !Add components to layout '''
        
        return grid_layout
        
        
    def create_top_horizontal_layout(self) -> QHBoxLayout:
        ''' #Create layout '''
        hbox_layout = QHBoxLayout()
        ''' !Create layout '''
        
        ''' #Create components '''
        label_NIC = QLabel()
        label_NIC.setFont(self.global_font)
        label_NIC.setText("NIC")
        
        self.combo_box = QComboBox()
        self.combo_box.setFont(self.global_font)
        
        self.combo_box.currentTextChanged.connect(self.interface_changed)
        ''' !Create components '''
        
        ''' #Add components to layout '''
        hbox_layout.addWidget(label_NIC)
        hbox_layout.addWidget(self.combo_box, 1)
        ''' !Add components to layout '''
        
        return hbox_layout
    
    
    def populate(self, shared: Shared) -> None:
        self.combo_box.addItems(shared.interfaces)
        
        
    def show(self) -> None:
        self.__main_widget.show()
        
    
    def interface_changed(self) -> None:
        global flag_dict
        flag_dict['iface'] = self.combo_box.currentText()
        
    
    def start(self) -> None:
        worker = Worker(self.sniff)
        
        self.thread_pool.start(worker)
        
    
    def sniff(self) -> None:
        # global flag_dict
        # iface = flag_dict.get('iface')
        # sniff(iface=iface, prn=lambda p: p.show())
        print('hello')
        
        
def sniffing_process(flag_dict, packet_list):
    while flag_dict['close'] == 0:
        sleep(1)
        interface = flag_dict.get('iface')
        a = sniff(iface='wlp4s0', prn=lambda p: p.summary())
    
    print('flag_dict[\'close\'] was set to 0')


def play():
    
    ''' time the execution '''
    from time import time
    start_time = time()
    
    application = QApplication([])
    window      = UI_main_window()
    
    shared = Shared()
    window.populate(shared)
    
    flag_dict['close'] = 0
    
    manager = Manager()
    packet_list = manager.Queue()
    
    process = Process(target=sniffing_process, args=(flag_dict, packet_list))
    process.daemon = True
    process.start()
    
    window.show()
    print(f'--- {time() - start_time} seconds ---')
    
    sys.exit(application.exec()) 
    process.terminate()