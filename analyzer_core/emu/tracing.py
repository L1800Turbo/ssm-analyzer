# MemAccess, ExecutionTracer
# Access tracing, RAM heatmap, logs.

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, List, Dict

from analyzer_core.config.rom_config import RomVarDefinition
from analyzer_core.disasm.insn_model import Instruction


@dataclass
class MemAccess:
    instr : Instruction # Instruction including address, size, bytes, mnemonic, op_str, target_type, target_value
    target_addr: Optional[int]  # Effective memory address accessed
    var: Optional[RomVarDefinition]  # Variable definition if this memory address is known in a ROM config
    value: Optional[int]  # Value read from or written to memory
    rw: str  # 'R', 'W', 'X' # Was this memory read, written, or executed?
    by: Optional[int]  # function start/caller address
    next_instr_addr: Optional[int]  # next program counter value after this command

    def __repr__(self) -> str:
        fields = []
        fields.append(f"Instr={self.instr}")
        if self.var is not None:
            fields.append(f"var={self.var}")
        if self.value is not None:
            fields.append(f"value=0x{self.value:02X}")
        fields.append(f"rw='{self.rw}'")
        if self.by is not None:
            fields.append(f"by=0x{self.by:04X}")
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
        if access.rw == 'R' and access.instr.address is not None:
            self.ram_heatmap[access.instr.address] = self.ram_heatmap.get(access.instr.address, 0) + 1
        self.logs.append(f"{access.rw} at 0x{access.instr.address:04X} by 0x{access.by:04X}")

    def get_heatmap(self) -> Dict[int, int]:
        return self.ram_heatmap

    def get_logs(self) -> List[str]:
        return self.logs

    def clear(self):
        self.accesses.clear()
        self.ram_heatmap.clear()
        self.logs.clear()
