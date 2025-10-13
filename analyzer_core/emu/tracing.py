# MemAccess, ExecutionTracer
# Access tracing, RAM heatmap, logs.

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, List, Dict

from analyzer_core.config.rom_config import RomVarDefinition


@dataclass
class MemAccess:
    addr: Optional[int]  # Memory address being accessed
    var: Optional[RomVarDefinition]  # Variable definition if this memory address is known in a ROM config
    value: Optional[int]  # Value read from or written to memory
    rw: str  # 'R', 'W', 'X' # Was this memory read, written, or executed?
    by: Optional[int]  # function start/caller address
    instr_addr: int  # address where it happened
    next_instr_addr: Optional[int]  # next program counter value after this command

    def __repr__(self) -> str:
        fields = []
        if self.addr is not None:
            fields.append(f"addr=0x{self.addr:04X}")
        if self.var is not None:
            fields.append(f"var={self.var}")
        if self.value is not None:
            fields.append(f"value=0x{self.value:02X}")
        fields.append(f"rw='{self.rw}'")
        if self.by is not None:
            fields.append(f"by=0x{self.by:04X}")
        fields.append(f"instr_addr=0x{self.instr_addr:04X}")
        if self.next_instr_addr is not None:
            fields.append(f"next_instr_addr=0x{self.next_instr_addr:04X}")
        return ("MemAccess(" + ", ".join(fields) + ")")

@dataclass
class ExecutionTracer:
    accesses: List[MemAccess] = field(default_factory=list)
    ram_heatmap: Dict[int, int] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)

    def trace_access(self, access: MemAccess):
        self.accesses.append(access)
        if access.rw == 'R' and access.addr is not None:
            self.ram_heatmap[access.addr] = self.ram_heatmap.get(access.addr, 0) + 1
        self.logs.append(f"{access.rw} at 0x{access.addr:04X} by 0x{access.by:04X} (insn 0x{access.instr_addr:04X})")

    def get_heatmap(self) -> Dict[int, int]:
        return self.ram_heatmap

    def get_logs(self) -> List[str]:
        return self.logs

    def clear(self):
        self.accesses.clear()
        self.ram_heatmap.clear()
        self.logs.clear()
