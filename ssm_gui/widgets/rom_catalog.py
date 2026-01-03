from dataclasses import asdict
import dataclasses
import enum
from pathlib import Path
from PyQt6.QtCore import Qt, QModelIndex, QPoint, QAbstractItemModel
from PyQt6.QtGui import QFontDatabase, QKeySequence, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QListWidget, QLabel,
    QPushButton, QComboBox, QTableView, QAbstractItemView, QInputDialog,
    QMessageBox, QMenu, QListWidgetItem, QHeaderView, QCheckBox, QStyle,
    QTabWidget, QTreeView, QSizePolicy
)
from PyQt6.QtGui import QStandardItemModel, QStandardItem

from analyzer_core.config.ssm_model import CurrentSelectedDevice
from analyzer_core.service import RomService
from ssm_gui.models.romid_table_model import RomIdTableModel


class RomCatalogWidget(QWidget):
    def __init__(self, rom_services: dict[Path, RomService]):
        super().__init__()

        self.rom_services = rom_services

        self.__create_ui()

    def __create_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        top_bar = QHBoxLayout()
        layout.addLayout(top_bar)

        top_bar.addWidget(QLabel("lüm"))

        self.rom_info_tree = QTreeView(self)
        layout.addWidget(self.rom_info_tree)

        self.rom_info_model = QStandardItemModel()
        self.rom_info_model.setHorizontalHeaderLabels(['Item', 'Value'])
        self.rom_info_tree.setModel(self.rom_info_model)

    def refresh_rom_info_tree(self):

        def object_to_tree_items(key, value):
            node = QStandardItem(str(key))
            if isinstance(value, dict):
                for k, v in value.items():
                    node.appendRow(object_to_tree_items(k, v))
                return [node]
            elif dataclasses.is_dataclass(value) and not isinstance(value, type):
                for k, v in asdict(value).items():
                    node.appendRow(object_to_tree_items(k, v))
                return [node]
            elif isinstance(value, (list, tuple)):
                for idx, v in enumerate(value):
                    node.appendRow(object_to_tree_items(f"[{idx}]", v))
                return [node]
            else:
                # Primitive Werte direkt als zweite Spalte
                if isinstance(value, enum.Enum):
                    return [node, QStandardItem(f"{value.name} ({value.value})")]
                elif isinstance(value, int):
                    return [node, QStandardItem(hex(value))]
                return [node, QStandardItem(str(value))]

        for path, service in self.rom_services.items():
            current_rom = QStandardItem(path.name)
            self.rom_info_model.appendRow([current_rom])

            for ecu in service.rom_cfg.selectable_devices:
                current_ecu = QStandardItem(ecu.name)
                current_rom.appendRow([current_ecu])

                romid_table = service.rom_cfg.romid_tables[ecu]
                current_ecu.appendRow([QStandardItem("pointer_addr"), QStandardItem(f"0x{romid_table.relative_pointer_addr:02X}")])
                current_ecu.appendRow([QStandardItem("length"), QStandardItem(f"0x{romid_table.length:02X}")])

                for romid in romid_table.entries:
                    romid_entry = QStandardItem(f"{romid.romid0:02X} {romid.romid1:02X} {romid.romid2:02X}")
                    current_ecu.appendRow([romid_entry])
    
                    for key, value in asdict(romid).items():
                        romid_entry.appendRow(object_to_tree_items(key, value))


