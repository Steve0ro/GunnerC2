# gui/main.py

#Normal Imports
import sys

#PyQt5 Imports
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt

# GunnerC2 Imports
from login_dialog import LoginDialog
from main_window import MainWindow

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(40, 44, 52))
    pal.setColor(QPalette.Base, QColor(33, 37, 43))
    pal.setColor(QPalette.Button, QColor(40, 44, 52))
    pal.setColor(QPalette.Text, Qt.white)
    pal.setColor(QPalette.WindowText, Qt.white)
    pal.setColor(QPalette.ButtonText, Qt.white)
    pal.setColor(QPalette.Highlight, QColor(64, 128, 255))
    pal.setColor(QPalette.HighlightedText, Qt.white)
    app.setPalette(pal)

    dlg = LoginDialog()
    if dlg.exec_() == LoginDialog.Accepted:
        mw = MainWindow(dlg.api_client)
        mw.show()
        sys.exit(app.exec_())
    sys.exit(0)
