import logging
from pathlib import Path
from PyQt6.QtCore import Qt, QModelIndex, QPoint, QAbstractItemModel
from PyQt6.QtGui import QFontDatabase, QKeySequence, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QListWidget, QLabel,
    QPushButton, QComboBox, QTableView, QAbstractItemView, QInputDialog,
    QMessageBox, QMenu, QListWidgetItem, QHeaderView, QCheckBox, QStyle,
    QTabWidget, QTreeView, QSizePolicy
)

from analyzer_core.config.ssm_model import CurrentSelectedDevice
from analyzer_core.service import RomService
from ssm_gui.models.romid_table_model import RomIdTableModel


class SsmTablesWidget(QWidget):
    def __init__(self, rom_services: dict[Path, RomService]):
        super().__init__()

        self.logger = logging.getLogger(f"{__name__}")

        self.rom_services = rom_services
        #self.romid_tables = getattr(rom_service, "romid_tables", {})


        #layout = QVBoxLayout()
        #layout.addWidget(QLabel("ROM Catalog (Meta, Functions, Strings, Export/CSV)"))
        #self.setLayout(layout)

        self.__create_ui()

    def __create_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        top_bar = QHBoxLayout()
        #top_bar.addWidget(QLabel(f"Current ROM: {self.rom_service.rom_name}"))

        # Dropdown for ECU type
        self.device_select = QComboBox()
        self.device_select.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        for dev in CurrentSelectedDevice:
            self.device_select.addItem(dev.name, dev)
        self.device_select.currentIndexChanged.connect(self._on_device_changed)
        top_bar.addWidget(QLabel("Device:"))
        top_bar.addWidget(self.device_select)

        top_bar.addStretch(1)
        layout.addLayout(top_bar)

        splitter = QSplitter()
        layout.addWidget(splitter, 1)

        self.romid_table = QTableView()
        self.romid_model = RomIdTableModel()
        self.romid_table.setModel(self.romid_model)
        #self.romid_table.horizontalHeader().setStretchLastSection(True)
        splitter.addWidget(self.romid_table)

        master_table = QTableView()
        splitter.addWidget(master_table)

    def reshesh_select_ecu(self):
        # TODO workaround, erstmal eine ROM, später erhänzen
        pass

    def _on_device_changed(self, index: int):
        """Handler: Gerät gewechselt → ROMID-Tabelle laden"""

        #print("hallo")
        self.refresh_romid_table()

    
    def refresh_romid_table(self):
        device = self.device_select.currentData()

        for rom_path, ecu in self.rom_services.items():
            romid_info = ecu.config.romid_tables.get(device)

            if romid_info:
                self.romid_model.setRomIdTable(romid_info)
            #if romid_info:
            #   self.romid_model.setRomIdTable(romid_info)
            #   self.romid_table.resizeColumnsToContents()

            self.logger.warning("TODO: Nur eine RomIDtabelle bis jetzt")
            return