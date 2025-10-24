from typing import Any
from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PyQt6.QtGui import QFontDatabase, QFont

from analyzer_core.config.ssm_model import MasterTableEntry, MasterTableInfo


class MasterTableModel(QAbstractTableModel):
    """Qt TableModel to visualize MasterTableInfo.entries"""

    HEADERS = [
        "MenuItem", "UpperLabel", "AddressIdx",
        "UpperLblIdx", "LowerLblIdx", "AdjustLblIdx",
        "0xB", "0xC", "0xD"
    ]

    def __init__(self, master_table: MasterTableInfo | None = None, parent=None):
        super().__init__(parent)
        self.master_table = master_table

    # --- Required overrides ---
    def rowCount(self, parent=QModelIndex()):
        if not self.master_table or not self.master_table.entries:
            return 0
        return len(self.master_table.entries)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role == Qt.ItemDataRole.FontRole and index.column() == 1:
            return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        
        if self.master_table is None:
            return None
    

        entry: MasterTableEntry = self.master_table.entries[index.row()]
        col = index.column()

        mapping = {
            0: entry.menu_item_str(),
            1: entry.upper_label,
            2: f"0x{entry.action_address_rel:04X}",
            3: str(entry.address_index),
            4: str(entry.upper_label_index),
            5: str(entry.lower_label_index),
            6: str(entry.adjustments_label_index),
            7:  str(entry.master_table_0xB),
            8:  str(entry.master_table_0xC),
            9:  str(entry.master_table_0xD)
        }

        return mapping.get(col, "")

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        else:
            return str(section + 1)

    # --- Optional helpers ---
    def setMasterTable(self, master_table: MasterTableInfo):
        """Replace table data and refresh."""
        self.beginResetModel()
        self.master_table = master_table
        self.endResetModel()
