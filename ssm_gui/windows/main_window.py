# MainWindow for SSM GUI
# Tab-based: Assembly, ROM import/info, General Config


# TODO Nochmal überdenken die UI:
'''
- ROMs aus Ordner auflisten und in RomServices laden, noch nicht analysieren
- wenn eine Rom geladen wird, soll zunächst der Hex-Code angezeigt werden
- Dann disassembly ohne alles anzeigen
- dann die analysen laufen lassen
- dann asm wieder aktualisieren und function table und son zeug
- wenn Fehler auftauchen: zwischenstand anzeigen mit Fehlermeldung
- später: Reactive?

- bei mehreren Dateien dann: analyse druchführen und angeben, dass analyse abgeschlossen ist. 
    für die reine Anzeige ist dann keine analyzse mehr nötgi
- auch eine Möglichkeit für "alles analyiseren"


'''

import logging
from PyQt6.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout, QStatusBar, QMenuBar, QMenu, QFileDialog, QTextEdit, QHBoxLayout, QLabel, QComboBox, QPushButton
from PyQt6.QtGui import QAction
from analyzer_core.data.romid_tables import RomIdTableCollector
from ssm_gui.widgets.asm_viewer import AsmViewerWidget
from ssm_gui.widgets.rom_catalog import RomCatalogWidget
from ssm_gui.widgets.ssm_tables import SsmTablesWidget
from analyzer_core.service import RomService
from pathlib import Path

DEFAULT_ROM_FOLDER = "./ressources"

logger = logging.getLogger(__name__)

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
        # TODO Für mehrere Dateien irgendwann
        # TODO Aber mit eigenem manager drüber, der dann auch die einzelnen ROM-INformationen nebeneinander legt und vergleicht.
        #
        #self.rom_service = RomService()
        self.rom_services: dict[Path, RomService] = {}
        self.romid_tables = RomIdTableCollector()

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

        # Top bar: ROM selection
        top_bar = QHBoxLayout()
        self.rom_select = QComboBox()
        self.rom_select.setMinimumWidth(220)
        top_bar.addWidget(QLabel("Select ROM image:"))
        top_bar.addWidget(self.rom_select)

        self.load_button = QPushButton("Analyze current ROM file") # Todo später analyze oder load nennen, je nachdem ob schon analysiert
        self.load_button.clicked.connect(self.__on_analyze_rom_file)
        top_bar.addWidget(self.load_button)
        top_bar.addStretch(1)
        self.main_vertical_layout.addLayout(top_bar)

        # Tabs
        self.tabs = QTabWidget()
        self.main_vertical_layout.addWidget(self.tabs)
        self.asm_viewer = AsmViewerWidget()
        self.tabs.addTab(self.asm_viewer, "Analysis")
        self.rom_catalog = RomCatalogWidget(self.rom_services)
        self.tabs.addTab(self.rom_catalog, "ROM Import/Info")
        self.ssm_tables = SsmTablesWidget(self.romid_tables)
        self.tabs.addTab(self.ssm_tables, "SSM tables")

        # Refresh info about analyzed roms
        #self.asm_viewer.roms_updated.connect(self.rom_catalog._refresh_rom_info_tree)
        #self.asm_viewer.roms_updated.connect(self.ssm_tables.refresh_romid_table)

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
        self.rom_select.currentIndexChanged.connect(self.__on_load_rom_file)


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
        rom_paths = RomService.list_roms(Path(self.current_rom_folder))

        # Create RomService instances for each ROM and show on dropdown
        self.rom_select.clear()
        for rom_path in rom_paths:
            service = RomService(rom_path)
            self.rom_select.addItem(service.rom_image.file_name, rom_path)

            self.rom_services[rom_path] = service
    
    def __refresh_views(self, current_service: RomService) -> None:
        self.asm_viewer.set_rom_service(current_service)
        self.asm_viewer.build_current_rom_ui()

        # Add into global RomID safe:
        self.romid_tables.add_ssm_cassette(current_service.rom_cfg.romid_tables)

        # Refresh info tree with ROM information
        # TODO hier auch set_rom_service machen?
        self.rom_catalog.refresh_rom_info_tree()

        # Refresh SSM tables
        self.ssm_tables.refresh_romid_table()
    
    def __on_load_rom_file(self) -> None:
        """Handles loading and analyzing the currently selected ROM file."""


        # TODO: Abfrage einbauen if not analyzed yet, analyze
        current_service: RomService = self.rom_services[self.rom_select.currentData()]

        # try:
        #     current_service.analyze()
        # except Exception as e:
        #     logger.error(f"Exception in analyzer: {str(e)}")

        self.__refresh_views(current_service)
    
    def __on_analyze_rom_file(self) -> None:
        """Handles analyzing the currently selected ROM file."""
        current_service: RomService = self.rom_services[self.rom_select.currentData()]

        try:
            current_service.analyze()
        except Exception as e:
            logger.error(f"Exception in analyzer: {str(e)}")

        self.__refresh_views(current_service)

