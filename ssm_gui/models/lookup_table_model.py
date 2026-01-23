from typing import Any
from PyQt6.QtCore import QObject, Qt, QAbstractTableModel, QModelIndex

from analyzer_core.data.romid_tables import SimpleMeasurement


class LookupTableModel(QAbstractTableModel):
    HEADERS = [
        "Index", "Value"
    ]

    def __init__(self, lookup_table: dict[int | str, int | str] | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.lut = lookup_table
        self._rows = self._build_rows()

    def _build_rows(self):
        rows = []
        if self.lut is None:
            return rows

        for key, val in self.lut.items():
            rows.append((str(key), str(val)))

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
        
        if self.lut is None:
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
    def setLut(self, lookup_table: dict[int | str, int | str]):
        """Replace table data and refresh."""
        self.beginResetModel()
        self.lut = lookup_table
        self._rows = self._build_rows()
        self.endResetModel()
