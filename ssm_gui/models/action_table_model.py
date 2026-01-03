from typing import Any
from PyQt6.QtCore import QObject, Qt, QAbstractTableModel, QModelIndex
#from PyQt6.QtWidgets import QStyledItemDelegate, QTableView

from analyzer_core.config.ssm_model import SsmAction


class ActionTableModel(QAbstractTableModel):
    HEADERS = [
        "Name", "Value"
    ]

    def __init__(self, action: SsmAction | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.action = action
        self._rows = self._build_rows()

    def _build_rows(self):
        rows = []
        if self.action is None:
            return rows
        
        # General action
        rows.append(("Action Type", self.action.action_type.name))

        if self.action.ecu_addresses:
            rows.append(("ECU Addresses", ", ".join(f"0x{addr:04X}" for addr in self.action.ecu_addresses)))

        if self.action.scaling is not None:
            scaling = self.action.scaling
            if scaling.scaling is not None:
                rows.append(("Scaling", str(scaling.scaling)))
                rows.append(("Scaling Address Pointer", f"0x{scaling.scaling_address_pointer:04X}"))
            if scaling.unit is not None:
                rows.append(("Unit", scaling.unit))
            rows.append(("Precision Decimals", scaling.precision_decimals))
            if scaling.lookup_tables is not None:
                rows.append(("Lookup table", ""))
                for key, val in scaling.lookup_tables.items():
                    rows.append((f"  Index {key}", str(val)))
        
        if self.action.switches is not None:
            rows.append(("Switches", ""))
            for switch in self.action.switches:
                rows.append((f"  {switch.name}", f"Bit {switch.bit}, Inverted: {switch.inverted}"))


        return rows

    # --- Required overrides ---
    def rowCount(self, parent=QModelIndex()):
        return len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        #if role == Qt.ItemDataRole.FontRole and index.column() == 1:
        #    return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        
        if self.action is None:
            return None
        
        row, col = index.row(), index.column()
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row][col]

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        else:
            return str(section + 1)

    # --- Optional helpers ---
    def setAction(self, action: SsmAction):
        """Replace table data and refresh."""
        self.beginResetModel()
        self.action = action
        self._rows = self._build_rows()
        self.endResetModel()
