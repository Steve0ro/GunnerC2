# gui/main.py

#Normal Imports
import sys, os

#PyQt5 Imports
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPalette, QColor, QIcon
from PyQt5.QtCore import Qt

# GunnerC2 Imports
from login_dialog import LoginDialog
from main_window import MainWindow

def _asset_path(*parts):
    """Resolve a path relative to this file (works when packaged, too)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, *parts)

def _find_icon_path():
    """
    Pick the best available icon:
      1) env GUNNERC2_ICON
      2) gui/assets/gunnerc2.png
      3) gui/assets/gunnerc2.ico
      4) gui/assets/gunnerc2.jpg
    """
    cand = [
        os.environ.get("GUNNERC2_ICON") or "",
        _asset_path("assets", "gunnerc2.png"),
        _asset_path("assets", "gunnerc2.ico"),
        _asset_path("assets", "gunnerc2.jpg"),
    ]
    for p in cand:
        if p and os.path.exists(p):
            return p
    return ""

if __name__ == "__main__":
    # Make icons/text crisp on Hi-DPI before creating QApplication
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    # On Windows, set an explicit AppUserModelID so the taskbar uses our icon/group
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("GunnerC2.App")
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("GunnerC2")
    app.setOrganizationName("GunnerC2")

    # App-wide icon (all windows inherit this unless they override)
    icon_path = _find_icon_path()
    if icon_path:
        app.setWindowIcon(QIcon(icon_path))

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
