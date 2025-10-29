
from dataclasses import dataclass
from typing import Optional

#from analyzer_core.disasm.capstone_wrap import OperandType

INSTRUCTION_GROUPS = {
    "operands_16bit": ['ldx', 'ldd', 'std', 'stx', 'addd', 'subd', 'cpx', 'jsr', 'bsr', 'jmp'],
    "branch_rel8": {"bsr", "bhi", "bls", "bcc", "bcs", "bne", "beq", "bvc", "bvs", "bpl", "bmi", "bge", "blt", "bgt", "ble"},
    "branch_rel16": {"lbsr", "lbra"},
    "jump_abs": {"jmp", "bra"},
    "returns": {"rts", "rti"},
    "functions": {"jsr", "bsr"},
}

@dataclass
class Instruction:
    address: int
    size: int
    bytes: bytes
    mnemonic: str
    op_str: str
    target_type: Optional["OperandType"] = None  # Type of the operand (immediate, direct, etc.)
    target_value: Optional[int] = None

    def __repr__(self):
        return (f"<Instruction addr=0x{self.address:04X} size={self.size} "
                f"mnemonic='{self.mnemonic}' op_str='{self.op_str}' "
                f"target_type={self.target_type} "
                f"target_value_raw={self.target_value}>")

    @property
    def is_function_call(self) -> bool:
        return self.mnemonic.lower() in INSTRUCTION_GROUPS["functions"]

    @property
    def is_jump(self) -> bool:
        return self.mnemonic.lower() in INSTRUCTION_GROUPS["jump_abs"]

    @property
    def is_branch_rel8(self) -> bool:
        return self.mnemonic.lower() in INSTRUCTION_GROUPS["branch_rel8"]

    @property
    def is_branch_rel16(self) -> bool:
        return self.mnemonic.lower() in INSTRUCTION_GROUPS["branch_rel16"]

    @property
    def is_return(self) -> bool:
        return self.mnemonic.lower() in INSTRUCTION_GROUPS["returns"]

    @property
    def is_operand_16bit(self) -> bool:
        return self.mnemonic.lower() in INSTRUCTION_GROUPS["operands_16bit"]
