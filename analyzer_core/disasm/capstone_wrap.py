from enum import Enum, auto
import logging
from typing import List, Optional, Tuple
from capstone import Cs, CsInsn, CS_ARCH_M680X, CS_MODE_M680X_6301
from .insn_model import INSTRUCTION_GROUPS, Instruction

class OperandType(Enum):
    IMMEDIATE = auto()
    DIRECT = auto()
    INDIRECT = auto()
    #REGISTER = auto()
    UNKNOWN = auto()

class Disassembler630x:
    def __init__(self, rom:bytes, arch=CS_ARCH_M680X, mode=CS_MODE_M680X_6301):
        self.cs = Cs(arch, mode)
        self.logger = logging.getLogger(f"{__name__}")

        self.rom = rom

    def __disassemble(self, code: bytes, address_offset: int, count:int = 0):
        """Disassembles code from address_offset. Returns an iterator of CsInsn."""
        return self.cs.disasm(code, address_offset, count)

    def in_rom(self, addr: int) -> bool:
        return 0 <= addr < len(self.rom)

    def parse_op_str(self, instr: Instruction) -> Optional[Tuple[OperandType, int]]:
        """Parses an operand string and returns type + value."""

        if instr.op_str == "":
            return None

        bits = 8
        if instr.is_operand_16bit:
            bits = 16

        try:
            if instr.op_str.startswith("$"):
                return OperandType.DIRECT, int(instr.op_str[1:], 16)
            elif instr.op_str.startswith(">$"):
                return OperandType.DIRECT, int(instr.op_str[2:], 16)
            elif instr.op_str.startswith("#"):
                val = int(instr.op_str[1:], 10)
                mask = (1 << bits) - 1
                return OperandType.IMMEDIATE, val & mask
            elif instr.op_str.endswith(", x"):
                base = instr.op_str[:-3].strip()
                if base.startswith("$"):
                    return OperandType.DIRECT, int(base[1:], 16)
                return OperandType.INDIRECT, int(base)
            elif instr.op_str.isdigit():
                return OperandType.INDIRECT, int(instr.op_str)
        except ValueError as e:
            self.logger.warning(f"Unknown operand format {instr.op_str}: {str(e)}")
            return OperandType.UNKNOWN, 0
            #raise ValueError(f"Unsupported operand format: {op_str}")

    def disassemble_step(self, addr: int):
        #def decode_one(addr: int) -> Instruction | None:
        if not self.in_rom(addr):
            return None

        capstone_instr = list(self.__disassemble(self.rom[addr:addr+8], addr, 1))
        if not capstone_instr:
            return None
        
        ins = capstone_instr[0]
        ins_bytes = self.rom[addr:addr + ins.size]
        instr = Instruction(address=addr & 0xFFFF, size=ins.size, bytes=ins_bytes, mnemonic=ins.mnemonic, op_str=ins.op_str)

        result = self.parse_op_str(instr)
        if result is not None:
            instr.target_type, instr.target_value = result

        return instr

    
    def disassemble_reachable(self, 
                              start_addr: int, 
                              instructions: Optional[List[Instruction]] = None,
                              call_tree: Optional[dict] = None
                              ) -> Tuple[List[Instruction], dict]:
        """
        Disassembliert nur tatsächlich erreichbaren Code ab Startadresse und JSR/JMP-Zielen (rekursiv).
        """
        visited = set()
        if instructions is None: instructions = []
        addr_to_instr_index = {}
        if call_tree is None: call_tree = {}
        code_bytes = set()
        worklist = [(start_addr, start_addr, call_tree)]

        # Skip addresses we detected in previous runs
        for instr in instructions:
            visited.add(instr.address)

        while worklist:
            start, func_entry, tree = worklist.pop()
            start &= 0xFFFF
            func_entry &= 0xFFFF

            # If we've been there before
            if start in visited:
                continue

            cur = start
            while cur not in visited and self.in_rom(cur):
                instr = self.disassemble_step(cur)
                if instr is None or instr.size <= 0:
                    visited.add(cur)
                    break

                if any(((cur + off) & 0xFFFF) in code_bytes for off in range(instr.size)):
                    visited.add(cur)
                    break

                addr_to_instr_index[instr.address] = len(instructions)
                instructions.append(instr)

                for off in range(instr.size):
                    code_bytes.add((instr.address + off) & 0xFFFF)

                visited.add(cur)

                pc_next = (instr.address + instr.size) & 0xFFFF

                # Function call (jsr, bsr) -> new context
                if instr.is_function_call and instr.target_value is not None:
                    callee = instr.target_value & 0xFFFF
                    subtree = tree.setdefault(callee, {})                        

                    if instr.target_type == OperandType.INDIRECT:
                        self.logger.info(f"Indirect function call from {instr.address:#04x} to {instr.target_value:#04x}, only possible in emulation")
                    else:
                        worklist.append((callee, callee, subtree))

                # Jump (jmp, lbra) -> only take the target and break
                if instr.is_jump and instr.target_value is not None:
                    if instr.target_type == OperandType.INDIRECT:
                        self.logger.warning(f"Indirect jump from {instr.address:#04x} to {instr.target_value:#04x}, only possible in emulation!")
                    else:
                        worklist.append((instr.target_value, func_entry, tree))
                    break

                # Relativ-Branches: Ziel + Fallthrough
                if instr.is_branch_rel8:
                    if instr.target_value is not None:
                        worklist.append((instr.target_value, func_entry, tree))
                    if instr.mnemonic == "bra":
                        break
                    cur = pc_next
                    continue

                if instr.is_branch_rel16:
                    if instr.target_value is not None:
                        worklist.append((instr.target_value, func_entry, tree))
                    if instr.mnemonic == "lbra":
                        break
                    cur = pc_next
                    continue

                if instr.is_return:
                    break
                cur = pc_next

        instructions.sort(key=lambda x: x.address)
        return instructions, call_tree
    
    @classmethod
    def find_stackpointer(cls, instructions: List[Instruction]) -> Optional[set|int]:
        stack_pointers:set[int] = set()
        
        for instr in instructions:
            if instr.mnemonic == "lds":
                if instr.target_value is None:
                    raise RuntimeError("find_stackpointer: Found lds instruction, but no target value")
                stack_pointers.add(instr.target_value)
        
        if len(stack_pointers) > 1:
            return stack_pointers
        elif len(stack_pointers) > 0:
            return stack_pointers.pop()
        return None




