from typing import List
from PyQt6.QtCore import Qt, QModelIndex, QAbstractTableModel, QVariant
from analyzer_core.config.rom_config import RomVarDefinition


class VariableTableModel(QAbstractTableModel):
    COLS = ["Name", "Address"]

    def __init__(self, var_map:dict[str, RomVarDefinition], parent=None):
        super().__init__(parent)
        self._vars:List[RomVarDefinition] = []
        self._var_map = var_map
        self.rebuild()

    def rebuild(self):
        # TODO zu aufwändig, einfach nach key sortieren und diese ganze funktion weg...
        self.beginResetModel()
        self._vars = sorted(self._var_map.values(), key=lambda f: f.name)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._vars)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return QVariant()
        if orientation == Qt.Orientation.Horizontal:
            return self.COLS[section]
        return QVariant()
    
    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return QVariant()
        f = self._vars[index.row()]
        col = index.column()

        # Go over columns
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return f.name
            if col == 1:
                return f"0x{f.rom_address:04X}"
        if role == Qt.ItemDataRole.TextAlignmentRole and col == 1:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return QVariant()
