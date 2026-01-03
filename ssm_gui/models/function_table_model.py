from typing import Dict, List, Optional
from PyQt6.QtCore import Qt, QModelIndex, QAbstractTableModel, QVariant

from analyzer_core.config.rom_config import RomVarDefinition
from analyzer_core.config.ssm_model import CurrentSelectedDevice


class FunctionTableModel(QAbstractTableModel):
    COLS = ["Name", "Address", "Callers"]

    def __init__(self, functions: dict[int, RomVarDefinition], parent=None):
        super().__init__(parent)
        self._funcs: list[RomVarDefinition] = []
        self._func_map = functions
        self.rebuild()

    def rebuild(self):
        self.beginResetModel()
        self._funcs = sorted(self._func_map.values(), key=lambda f: f.rom_address if f.rom_address is not None else 0)
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
        
        var_def = self._funcs[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return var_def.name
            if col == 1:
                return f"0x{var_def.rom_address:04X}{'' if var_def.rom_address == var_def.mapped_address else f' (0x{var_def.mapped_address:04X})'}"
            if col == 2:
                if not var_def.callers:
                    return ""
                # Caller addresses, if known by name (usually not the case as inside functions)
                items: List[str] = []
                for addr in sorted(var_def.callers):
                    fi = self._func_map.get(addr)

                    # TODO Mapped address ist hier noch nciht drin:
                    # wir rufen hier ja keine Funktionen auf, wo die Variable benannt ist, wir müssen aus romconfig quasi neu die offsets laden...
                    # will man hier irgendwie nicht mehr...
                    items.append(fi.name if fi else f"0x{addr:04X}")
                return ", ".join(items)
        if role == Qt.ItemDataRole.TextAlignmentRole and col == 1:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return QVariant()

    def functions_rom_address(self, row: int) -> Optional[int]:
        return self._funcs[row].rom_address if 0 <= row < len(self._funcs) else None