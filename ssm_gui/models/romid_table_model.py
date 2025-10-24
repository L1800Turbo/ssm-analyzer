import struct
from typing import Any
from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex

from analyzer_core.config.ssm_model import RomIdTableEntry_512kb, RomIdTableInfo


class RomIdTableModel(QAbstractTableModel):
    """Qt TableModel to visualize RomIdTableInfo.entries"""

    HEADERS = ["RomID", "Label"]

    def __init__(self, romid_table: RomIdTableInfo | None = None, parent=None):
        super().__init__(parent)
        self.romid_table = romid_table

    # --- Required overrides ---
    def rowCount(self, parent=QModelIndex()):
        if not self.romid_table or not self.romid_table.entries:
            return 0
        return len(self.romid_table.entries)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None

        if self.romid_table is None:
            return None
        entry = self.romid_table.entries[index.row()]
        col = index.column()

        mapping = {
                0: f"{entry.romid0:02X} {entry.romid1:02X} {entry.romid2:02X}",
                1: "tbd.",
                # 2: entry.romid2,
                # 3: entry.label_index,
                # 4: entry.menuitems_index,
                # 5: entry.ecu_addresses_rel,
                # 6: entry.master_table_address_rel,
                # 7: entry.romid_a,
                # 8: entry.tbd_b,
                # 9: entry.romid_model_index,
                # 10: entry.flagbytes,
            }

        value = mapping.get(col, "")
        return str(value)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        else:
            return str(section + 1)

    # --- Optional helpers ---
    def setRomIdTable(self, romid_table: RomIdTableInfo):
        """Replace table data and refresh."""
        self.beginResetModel()
        self.romid_table = romid_table
        self.endResetModel()
