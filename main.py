import sys
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication
from ui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    QTimer.singleShot(0, window.show_startup_dialog)
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
