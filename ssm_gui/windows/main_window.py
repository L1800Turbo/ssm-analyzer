# MainWindow for SSM GUI
# Tab-based: Assembly, ROM import/info, General Config

import logging
from PyQt6.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout, QStatusBar, QMenuBar, QMenu, QFileDialog, QTextEdit
from PyQt6.QtGui import QAction
from ssm_gui.widgets.asm_viewer import AsmViewerWidget
from ssm_gui.widgets.rom_catalog import RomCatalogWidget
from ssm_gui.widgets.ssm_tables import SsmTablesWidget
from analyzer_core.service import RomService
from pathlib import Path

DEFAULT_ROM_FOLDER = "./ressources"

class QTextEditLogger(logging.Handler):
    LEVEL_COLORS = {
        logging.DEBUG: "gray",
        logging.INFO: "black",
        logging.WARNING: "orange",
        logging.ERROR: "red",
        logging.CRITICAL: "darkred"
    }

    def __init__(self, text_edit: QTextEdit):
        super().__init__()
        self.text_edit = text_edit

    def emit(self, record):
        #msg = self.format(record)
        #self.text_edit.append(msg)

        msg = self.format(record)
        color = self.LEVEL_COLORS.get(record.levelno, "black")
        html_msg = f'<span style="color:{color};">{msg}</span>'
        self.text_edit.append(html_msg)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SSM ROM Analyzer")
        self.resize(1200, 800)

        # Initialize RomService once for the whole app
        self.rom_service = RomService()

        # Menu bar
        menu_bar = QMenuBar(self)
        file_menu = QMenu("File", self)
        select_folder_action = QAction("Select ROM files folder", self)
        select_folder_action.triggered.connect(self.select_rom_folder)
        file_menu.addAction(select_folder_action)
        menu_bar.addMenu(file_menu)
        self.setMenuBar(menu_bar)

        self.central_widget = QWidget()
        self.main_vertical_layout = QVBoxLayout(self.central_widget)
        self.setCentralWidget(self.central_widget)

        # Tabs
        self.tabs = QTabWidget()
        self.main_vertical_layout.addWidget(self.tabs)
        self.asm_viewer = AsmViewerWidget(self.rom_service)
        self.tabs.addTab(self.asm_viewer, "Assembly")
        self.rom_catalog = RomCatalogWidget()
        self.tabs.addTab(self.rom_catalog, "ROM Import/Info")
        self.ssm_tables = SsmTablesWidget()
        self.tabs.addTab(self.ssm_tables, "General Config")

        # Log area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.main_vertical_layout.addWidget(self.log_area)

        #self.central_widget.setLayout(self.main_vertical_layout)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        # On start: select the default ROM folder
        self.set_rom_folder(DEFAULT_ROM_FOLDER)

        self.__init_logging()

    def __init_logging(self):
        # Konsole-Handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

        # QTextEdit-Handler
        textedit_handler = QTextEditLogger(self.log_area)
        textedit_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

        # Logger für dieses Modul
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger().addHandler(console_handler)
        logging.getLogger().addHandler(textedit_handler)

    def select_rom_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select ROM files folder")
        if folder:
            self.set_rom_folder(folder)

    def set_rom_folder(self, folder: str):
        self.current_rom_folder = folder
        self.status_bar.showMessage(f"Selected ROM folder: {folder}")

        # Load ROM list from selected folder and update ASM viewer
        rom_paths = self.rom_service.list_roms(Path(self.current_rom_folder))
        self.asm_viewer.set_rom_list(rom_paths)
