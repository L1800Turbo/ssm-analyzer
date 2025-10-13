
from typing import Optional, Set, Tuple, Callable

from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, QVariant
from PyQt6.QtGui import QColor, QBrush


class ROMTableModel(QAbstractTableModel):
    """
    Hex+ASCII table model with:
        - BYTES_PER_ROW = 16
        - yellow region highlight (set_highlight)
        - optional orange focus address
        - tooltips (Name/Mem-Type via resolver)
    """
    BYTES_PER_ROW = 16
    ASCII_COL_INDEX = BYTES_PER_ROW

    def __init__(
        self,
        rom: bytes,
        base_addr: int = 0x0000,
        name_resolver: Optional[Callable[[int], Optional[str]]] = None,
        mem_type_resolver: Optional[Callable[[int], Optional[str]]] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.rom: bytes = rom or b""
        self.base_addr: int = base_addr & 0xFFFF
        self.highlight_addrs: Set[int] = set()
        self.focus_addr: Optional[int] = None
        self._name_resolver = name_resolver
        self._mem_type_resolver = mem_type_resolver

    def _rows(self) -> int:
        return (len(self.rom) + self.BYTES_PER_ROW - 1) // self.BYTES_PER_ROW if self.rom else 0

    def address_of(self, row: int, col: int) -> Optional[int]:
        if col >= self.BYTES_PER_ROW:
            return None
        idx = row * self.BYTES_PER_ROW + col
        if idx < 0 or idx >= len(self.rom):
            return None
        return (self.base_addr + idx) & 0xFFFF

    def row_col_of_address(self, addr: int) -> Optional[Tuple[int, int]]:
        idx = (addr - self.base_addr) & 0xFFFF
        if idx < 0 or idx >= len(self.rom):
            return None
        return idx // self.BYTES_PER_ROW, idx % self.BYTES_PER_ROW

    def set_rom(self, rom: bytes, base_addr: int = 0x0000) -> None:
        self.beginResetModel()
        self.rom = rom or b""
        self.base_addr = base_addr & 0xFFFF
        self.highlight_addrs.clear()
        self.focus_addr = None
        self.endResetModel()

    def set_highlight(self, addrs: Set[int], focus_addr: Optional[int] = None) -> None:
        affected_rows: Set[int] = set()
        for a in self.highlight_addrs:
            rc = self.row_col_of_address(a)
            if rc:
                affected_rows.add(rc[0])
        for a in addrs:
            rc = self.row_col_of_address(a)
            if rc:
                affected_rows.add(rc[0])

        self.highlight_addrs = {a & 0xFFFF for a in addrs}
        self.focus_addr = None if focus_addr is None else (focus_addr & 0xFFFF)

        if affected_rows:
            top, bottom = min(affected_rows), max(affected_rows)
            tl = self.index(top, 0)
            br = self.index(bottom, self.ASCII_COL_INDEX)
            self.dataChanged.emit(tl, br, [
                Qt.ItemDataRole.BackgroundRole,
                Qt.ItemDataRole.ToolTipRole
            ])

    # ---- Qt Model ----
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else self._rows()

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return self.BYTES_PER_ROW + 1  # + ASCII

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not self.rom:
            return QVariant()
        r, c = index.row(), index.column()
        row_start = r * self.BYTES_PER_ROW

        if role == Qt.ItemDataRole.DisplayRole:
            if c < self.BYTES_PER_ROW:
                idx = row_start + c
                return f"{self.rom[idx]:02X}" if idx < len(self.rom) else ""
            else:
                line = []
                for i in range(self.BYTES_PER_ROW):
                    idx = row_start + i
                    if idx < len(self.rom):
                        v = self.rom[idx]
                        line.append(chr(v) if 32 <= v < 127 else ".")
                return "".join(line)

        if role == Qt.ItemDataRole.TextAlignmentRole:
            return int(Qt.AlignmentFlag.AlignCenter) if c < self.BYTES_PER_ROW \
                else int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        if role == Qt.ItemDataRole.BackgroundRole and c < self.BYTES_PER_ROW:
            addr = self.address_of(r, c)
            if addr is not None:
                if self.focus_addr is not None and addr == self.focus_addr:
                    return QBrush(QColor(255, 180, 120))  # orange
                if addr in self.highlight_addrs:
                    return QBrush(QColor(255, 255, 170))  # yellow

        if role == Qt.ItemDataRole.ToolTipRole and c < self.BYTES_PER_ROW:
            addr = self.address_of(r, c)
            if addr is not None:
                parts = [f"${addr:04X}"]
                if self._mem_type_resolver:
                    mtype = self._mem_type_resolver(addr)
                    if mtype:
                        parts.append(f"Type: {mtype}")
                if self._name_resolver:
                    nm = self._name_resolver(addr)
                    if nm:
                        parts.append(f"Name: {nm}")
                return "\n".join(parts)

        return QVariant()

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return QVariant()
        if orientation == Qt.Orientation.Horizontal:
            return "ASCII" if section == self.ASCII_COL_INDEX else f"{section:02X}"
        # Vertical header: Zeilen-Startadresse
        addr = (self.base_addr + section * self.BYTES_PER_ROW) & 0xFFFF
        return f"{addr:04X}"

    def flags(self, index: QModelIndex):
        return Qt.ItemFlag.ItemIsEnabled