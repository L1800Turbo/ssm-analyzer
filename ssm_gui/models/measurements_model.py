
from typing import Any
from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PyQt6.QtGui import QFontDatabase

from analyzer_core.data.romid_tables import SimpleMeasurement

class MeasurementsModel(QAbstractTableModel):
    """Qt TableModel to visualize scaling definitions"""
    HEADERS = [
        "Name", "Read address(es)", "Scaling", "Unit", "Precision"
    ]

    def __init__(self, measurements: dict[str, SimpleMeasurement] | None = None, parent=None):
        super().__init__(parent)
        self.measurements = measurements or {}

    # --- Required overrides ---
    def rowCount(self, parent=QModelIndex()):
        return len(self.measurements)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None

        scaling_name = list(self.measurements.keys())[index.row()]
        scaling = self.measurements[scaling_name]
        col = index.column()

        mapping = {
            0: scaling_name,
            1: ", ".join([f"0x{addr:04X}" for addr in scaling.addresses]),
            2: str(scaling.scaling_expr),
            3: scaling.unit if scaling.unit else "",
            4: str(scaling.precision) if scaling.precision is not None else ""
        }

        return mapping.get(col, "")

    def get_lookup_table_for_row(self, row: int):
        """Return the lookup table dict for the given row, or None if not present."""
        if row < 0 or row >= len(self.measurements):
            return None
        scaling_name = list(self.measurements.keys())[row]
        scaling = self.measurements[scaling_name]
        return scaling.lookup_table if hasattr(scaling, "lookup_table") else None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        else:
            return str(section + 1)

    def setMeasurements(self, measurements: dict[str, SimpleMeasurement]):
        """Replace table data and refresh."""
        self.beginResetModel()
        self.measurements = measurements
        self.endResetModel()