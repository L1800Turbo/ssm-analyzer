import struct
from typing import Any
from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex

from analyzer_core.config.ssm_model import RomIdTableEntryRaw12, RomIdTableInfo
from analyzer_core.data.romid_tables import MastertableIdentifier, SimpleMasterTableEntry, SimpleMasterTable


class RomIdTableModel(QAbstractTableModel):
    """Qt TableModel to visualize RomIdTableInfo.entries"""

    HEADERS = ["RomID", "Model", "Year", "Source cassettes"]

    def __init__(self, romid_table: dict[int | str, SimpleMasterTable] | None = None, parent=None):
        super().__init__(parent)
        self.romid_table = romid_table

    # --- Required overrides ---
    def rowCount(self, parent=QModelIndex()):
        if not self.romid_table:
            return 0
        return len(self.romid_table)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None

        if self.romid_table is None:
            return None
        entry = list(self.romid_table.values())[index.row()]
        col = index.column()

        mapping = {
                0: f"{entry.romid_str}{f' / {entry.romid_identifier_value[0]:04X} -> {entry.romid_identifier_value[1]}' if entry.romid_identifier_value else ''}",
                1: entry.model if entry.model else "",
                2: entry.year if entry.year else "",
                3: ", ".join(entry.source_cassettes) if entry.source_cassettes else ""
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
    def setRomIdTable(self, romid_table: dict[MastertableIdentifier, SimpleMasterTable]):
        """Replace table data and refresh."""
        self.beginResetModel()
        self.romid_table = romid_table
        self.endResetModel()
