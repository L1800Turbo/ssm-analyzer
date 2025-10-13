# QApplication Bootstrap
# Einstiegspunkt für die GUI-Anwendung.

import sys
from PyQt6.QtWidgets import QApplication
from ssm_gui.windows.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    try:
        # ...dein Fenster/Setup...
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        import traceback
        print("Error in main window:", e)
        traceback.print_exc()

        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.critical(None, "Error", str(e))

if __name__ == "__main__":
    main()

