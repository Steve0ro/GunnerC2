# gui/main_window.py
from PyQt5.QtWidgets import QMainWindow

from dashboard import Dashboard

class MainWindow(QMainWindow):
    def __init__(self, api):
        super().__init__()
        self.api = api
        self.setWindowTitle("GunnerC2 — Console")
        self.resize(1240, 780)

        # New: Dashboard with graph + bottom tab browser
        self.dashboard = Dashboard(api)
        self.setCentralWidget(self.dashboard)
