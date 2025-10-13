from typing import Dict, List, Optional
from PyQt6.QtCore import Qt, QModelIndex, QAbstractTableModel, QVariant

from analyzer_core.disasm.cfg import FunctionInfo


class FunctionTableModel(QAbstractTableModel):
    COLS = ["Name", "Address", "Callers"]

    def __init__(self, functions: Dict[int, FunctionInfo], parent=None):
        super().__init__(parent)
        self._funcs: List[FunctionInfo] = []
        self._func_map = functions
        self.rebuild()

    def rebuild(self):
        self.beginResetModel()
        self._funcs = sorted(self._func_map.values(), key=lambda f: f.start)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._funcs)

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
        f = self._funcs[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return f.name
            if col == 1:
                return f"${f.start:04X}"
            if col == 2:
                if not f.callers:
                    return ""
                # Callers als Name (falls Funktion bekannt) oder $ADDR
                items: List[str] = []
                for a in sorted(f.callers):
                    fi = self._func_map.get(a)
                    items.append(fi.name if fi else f"${a:04X}")
                return ", ".join(items)
        if role == Qt.ItemDataRole.TextAlignmentRole and col == 1:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return QVariant()

    def function_at_row(self, row: int) -> Optional[FunctionInfo]:
        return self._funcs[row] if 0 <= row < len(self._funcs) else None