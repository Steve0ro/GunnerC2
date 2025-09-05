# gui/main_window.py
from PyQt5.QtWidgets import QMainWindow, QApplication, QWidget, QVBoxLayout
from PyQt5.QtCore import Qt

from dashboard import Dashboard
from title_bar import TitleBar

class MainWindow(QMainWindow):
    def __init__(self, api):
        super().__init__()
        self.api = api
        self.setWindowTitle("GunnerC2 — Console")
        self.resize(1240, 780)
        self.setWindowIcon(QApplication.windowIcon())

        # Frameless → we draw the title bar ourselves (puts menu on the OS row)
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)

        # Central: our custom title bar on top, dashboard below
        self.dashboard = Dashboard(api)
        wrapper = QWidget()
        lay = QVBoxLayout(wrapper); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)
        self.titlebar = TitleBar(self, self.dashboard)
        lay.addWidget(self.titlebar)
        lay.addWidget(self.dashboard)
        self.setCentralWidget(wrapper)
