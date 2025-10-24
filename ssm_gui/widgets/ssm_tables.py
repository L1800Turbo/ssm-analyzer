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

from analyzer_core.config.ssm_model import CurrentSelectedDevice, RomIdTableInfo, MasterTableInfo
from typing import cast
from analyzer_core.service import RomService
from ssm_gui.models.master_table_model import MasterTableModel
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

        self.romid_table_view = QTableView()
        self.romid_table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.romid_table_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        self.romid_table_model = RomIdTableModel()
        self.romid_table_view.setModel(self.romid_table_model)
        #self.romid_table.horizontalHeader().setStretchLastSection(True)
        splitter.addWidget(self.romid_table_view)

        self.master_table_view = QTableView()
        self.master_table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.master_table_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.master_table_model = MasterTableModel()
        self.master_table_view.setModel(self.master_table_model)
        splitter.addWidget(self.master_table_view)

        romid_table_selection_model = self.romid_table_view.selectionModel()
        if romid_table_selection_model: 
            romid_table_selection_model.selectionChanged.connect(self._on_romid_table_changed)

    def reshesh_select_ecu(self):
        # TODO workaround, erstmal eine ROM, später erhänzen
        pass

    def _on_device_changed(self, index: int):
        """Device changed, load corresponding RomID table."""
        self.refresh_romid_table()

    def _on_romid_table_changed(self, index:int):
        '''
        RomID table changed, load the matching master table
        '''
        # get first selected row (single selection mode expected)
        sel_model = self.romid_table_view.selectionModel()
        if sel_model is None:
            self.selected_romid_entry = None
            self.refresh_master_table()
            return

        rows = sel_model.selectedRows()
        if not rows:
            self.selected_romid_entry = None
            self.refresh_master_table()
            return

        row = rows[0].row()
        # guard: ensure we have a romid_table and entries
        if not hasattr(self, "romid_table") or self.romid_table is None:
            self.selected_romid_entry = None
            self.refresh_master_table()
            return

        if row < 0 or row >= len(self.romid_table.entries):
            self.selected_romid_entry = None
            self.refresh_master_table()
            return

        self.selected_romid_entry = self.romid_table.entries[row]
        self.refresh_master_table()

    
    def refresh_romid_table(self):
        device = self.device_select.currentData()

        for rom_path, ecu in self.rom_services.items():
            self.romid_table = ecu.config.romid_tables.get(device)

            if self.romid_table:
                self.romid_table_model.setRomIdTable(self.romid_table)
            #if romid_info:
            #   self.romid_model.setRomIdTable(romid_info)
            #   self.romid_table.resizeColumnsToContents()

            # TODO Es sollte eine Oberklasse über Service geben, die letztlich alle Infromationen zusammen sammelt

            self.logger.warning("TODO: Nur eine RomIDtabelle bis jetzt")
            return
        
    def refresh_master_table(self):
        entry = getattr(self, "selected_romid_entry", None)
        if entry is None:
            self.master_table_model.setMasterTable(cast(MasterTableInfo, None))
            return

        master = getattr(entry, "master_table", None)
        if master is None:
            self.master_table_model.setMasterTable(cast(MasterTableInfo, None))
            return

        # master is expected to be a MasterTableInfo instance
        self.master_table_model.setMasterTable(master)
