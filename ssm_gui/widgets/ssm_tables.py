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
from typing import Optional, cast
from analyzer_core.data.romid_tables import RomIdTableCollector, SimpleMasterTable
from ssm_gui.models.lookup_table_model import LookupTableModel
from ssm_gui.models.measurements_model import MeasurementsModel
from ssm_gui.models.romid_table_model import RomIdTableModel


class SsmTablesWidget(QWidget):
    def __init__(self, romid_tables: RomIdTableCollector):
        super().__init__()

        self.logger = logging.getLogger(f"{__name__}")

        self.romid_tables = romid_tables

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

        self.measurement_view = QTableView()
        self.measurement_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.measurement_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.measurement_model = MeasurementsModel()
        self.measurement_view.setModel(self.measurement_model)
        splitter.addWidget(self.measurement_view)

        self.lookup_table_view = QTableView()
        self.lookup_table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.lookup_table_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.lookup_table_model = LookupTableModel()
        self.lookup_table_view.setModel(self.lookup_table_model)
        splitter.addWidget(self.lookup_table_view)



        romid_table_selection_model = self.romid_table_view.selectionModel()
        if romid_table_selection_model: 
            romid_table_selection_model.selectionChanged.connect(self._on_romid_table_changed)
        
        measurement_selection_model = self.measurement_view.selectionModel()
        if measurement_selection_model:
            measurement_selection_model.selectionChanged.connect(self._on_measurement_selection_changed)

    def reshesh_select_ecu(self):
        # TODO workaround, erstmal eine ROM, später erhänzen
        pass

    def _on_device_changed(self, index: int):
        """Device changed, load corresponding RomID table."""
        #self._on_romid_table_changed(-1)
        #self.romid_table = None
        self.selected_romid_entry = None
        self.refresh_measurements_table()

        #self.selected_master_table_entry = None
        #self.refresh_action_table()

        self.refresh_romid_table()

    def _on_romid_table_changed(self, index:int):
        '''
        RomID table changed, load the matching master table
        '''
        # get first selected row (single selection mode expected)
        sel_model = self.romid_table_view.selectionModel()
        if sel_model is None:
            self.selected_romid_entry = None
            self.refresh_measurements_table()
            return

        rows = sel_model.selectedRows()
        if not rows:
            self.selected_romid_entry = None
            self.refresh_measurements_table()
            return

        row = rows[0].row()
        # guard: ensure we have a romid_table and entries
        if not hasattr(self, "current_romid_table") or self.current_romid_table is None:
            self.selected_romid_entry = None
            self.refresh_measurements_table()
            return

        if row < 0 or row >= len(self.current_romid_table):
            self.selected_romid_entry = None
            self.refresh_measurements_table()
            return

        #self.selected_master_table_entry = None
        #self.refresh_action_table()

        self.selected_romid_entry = list(self.current_romid_table.items())[row][1]
        self.refresh_measurements_table()

    def _on_measurement_selection_changed(self, selected, deselected):
        # Hole die aktuelle Zeile aus der Auswahl
        indexes = selected.indexes()
        if indexes:
            row = indexes[0].row()
            lookup_table = self.measurement_model.get_lookup_table_for_row(row)
            self.lookup_table_model.setLut(lookup_table or {})
        else:
            self.lookup_table_model.setLut({})  # Leere Tabelle, falls nichts ausgewählt

        

    # def _on_master_table_changed(self, index:int):
    #     '''
    #     Master table changed, load the matching action
    #     '''
    #     sel_model = self.measurement_view.selectionModel()
    #     if sel_model is None:
    #         self.selected_master_table_entry = None
    #         self.refresh_action_table()
    #         return
        
    #     rows = sel_model.selectedRows()
    #     if not rows:
    #         self.selected_master_table_entry = None
    #         self.refresh_action_table()
    #         return
        
    #     row = rows[0].row()
    #     # guard: ensure we have a master_table and entries
    #     if not hasattr(self.master_table_model, "master_table") or self.master_table_model.master_table is None:
    #         self.selected_master_table_entry = None
    #         self.refresh_action_table()
    #         return

    #     if row < 0 or row >= len(self.master_table_model.master_table.entries):
    #         self.selected_master_table_entry = None
    #         self.refresh_action_table()
    #         return

    #     self.selected_master_table_entry = list(self.master_table_model.master_table.entries.values())[row]
    #     self.refresh_action_table()

    
    def refresh_romid_table(self):
        device = self.device_select.currentData()

        self.current_romid_table = self.romid_tables.romid_tables.get(device)
        if self.current_romid_table:
                self.romid_table_model.setRomIdTable(self.current_romid_table)
        else:
            self.romid_table_model.setRomIdTable({})

        # TODO Folgende Anpassungen sind notwendig:
        # - eine Funktion, die alle RomID-Tables zusammenfasst (aus allen RomServices)
        # - dann das Modell ausgeben
        # - aber vermutlich ein Level höher, nciht hier in widget

        # for rom_path, ecu in self.rom_services.items():
        #     self.current_romid_table = ecu.rom_cfg.romid_tables.get(device)

        #     if self.current_romid_table:
        #         self.romid_table_model.setRomIdTable(self.current_romid_table)
        #     #if romid_info:
        #     #   self.romid_model.setRomIdTable(romid_info)
        #     #   self.romid_table.resizeColumnsToContents()

        #     # TODO Es sollte eine Oberklasse über Service geben, die letztlich alle Infromationen zusammen sammelt

        #     self.logger.warning("TODO: Nur eine RomIDtabelle bis jetzt")
        #     return

    def refresh_measurements_table(self):
        master_table: Optional[SimpleMasterTable] = getattr(self, "selected_romid_entry", None)
        if master_table is None or master_table.measurements is None:
            self.measurement_model.setMeasurements({})
            return

        # master is expected to be a MasterTableInfo instance
        self.measurement_model.setMeasurements(master_table.measurements)
        self.measurement_view.resizeColumnsToContents()
        
    # def refresh_master_table(self):
    #     master_table = getattr(self, "selected_romid_entry", None)
    #     if master_table is None:
    #         self.master_table_model.setMasterTable(cast(SimpleMasterTable, None))
    #         return


    #     # master is expected to be a MasterTableInfo instance
    #     self.master_table_model.setMasterTable(master_table)
    #     self.master_table_view.resizeColumnsToContents()
    
    # def refresh_action_table(self):
    #     # TODO Diese hier sollte dann komplett zwischen Switch / Scaling / Diag /... unterscheiden
    #     entry = getattr(self, "selected_master_table_entry", None)
    #     if entry is None:
    #         self.action_model.setScaling(cast(SimpleScaling, None))
    #         return

    #     action = getattr(entry, "action", None)
    #     if action is None:
    #         self.action_model.setScaling(cast(SimpleScaling, None))
    #         return

    #     # action is expected to be a SsmAction instance
    #     self.action_model.setScaling(action)
    #     self.action_view.resizeColumnsToContents()
