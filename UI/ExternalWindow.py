from PyQt5.QtWidgets import QWidget
from PyQt5.QtWidgets import QTabWidget
from PyQt5.QtWidgets import QVBoxLayout
from PyQt5.QtWidgets import QGridLayout
from PyQt5.QtWidgets import QTextBrowser
from PyQt5.QtWidgets import QPushButton
from PyQt5.QtWidgets import QLabel
from PyQt5.QtGui import QFont
from typing import Any

class ExternalWindow(object):
    def __init__(self):
        super().__init__()
        self.main_widget = QWidget()
        
    def set_custom_layout(self, _layout):
        self.layout.parent = None
        self.main_widget.setLayout = _layout
        
    def show(self) -> None:
        self.main_widget.show()
        
class RawContentExternalWindow(ExternalWindow):
    def __init__(self):
        super().__init__()
        
        self.layout = QVBoxLayout()
        self.main_widget = QTabWidget()
        self.main_widget.setLayout(self.layout)
        
        self.main_widget.setFixedSize(800, 600)
        self.main_widget.setWindowTitle("Raw")
        
class ForgerExternalWindow(ExternalWindow):
    """External Window for Forger/Repeater functionality

    Args:
        ExternalWindow (QWidget): _description_
    """
    def __init__(self,
                 _font: QFont,  # font
                 _function: Any # function to be used on send button trigger
        ):
        super().__init__()
        self.font = _font
        
        self.layout = QGridLayout()
        self.main_widget = QWidget()
        self.main_widget.setLayout(self.layout)
        
        self.main_widget.setFixedSize(1000, 800)
        self.main_widget.setWindowTitle("Repeater")
        
        self.editable_field_widget = QTabWidget()
        self.response_field_widget = QTextBrowser()
        
        request_label = QLabel("Request")
        request_label.setFont(self.font)
        response_label = QLabel("Response")
        response_label.setFont(self.font)
        
        self.send_button = QPushButton("Send")
        self.send_button.setFont(self.font)
        self.send_button.clicked.connect(_function)
        
        """
        Set elements inside the layout
        """
        self.layout.addWidget(request_label, 1, 0, 1, 1)
        self.layout.addWidget(response_label, 1, 3, 1, 1)
        self.layout.addWidget(self.send_button, 0, 3, 1, 2)
        self.layout.addWidget(self.editable_field_widget, 2, 0, -1, 2)
        self.layout.addWidget(self.response_field_widget, 2, 3, -1, 2)
        