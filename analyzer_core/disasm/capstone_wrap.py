from enum import Enum, auto
import logging
from typing import List, Optional, Tuple
from capstone import Cs, CsInsn, CS_ARCH_M680X, CS_MODE_M680X_6301

from analyzer_core.config.memory_map import RegionKind
from analyzer_core.config.rom_config import RomConfig, RomVarDefinition, RomVarType
from analyzer_core.config.ssm_model import CurrentSelectedDevice
from analyzer_core.emu.memory_manager import MemoryManager
from .insn_model import INSTRUCTION_GROUPS, Instruction

logger = logging.getLogger(f"{__name__}")

# TODO Adressierungen nochmal mit Datenblat durchgehen
class OperandType(Enum):
    IMMEDIATE = auto()  # Direct access to value #$xx
    DIRECT = auto()     # Access to address $xx
    INDIRECT = auto()   # Access by pointer $xx, x
    UNKNOWN = auto()

class Disassembler630x:
    def __init__(self, mem: MemoryManager, rom_config: RomConfig, current_device: Optional[CurrentSelectedDevice] = None, arch=CS_ARCH_M680X, mode=CS_MODE_M680X_6301):
        self.cs = Cs(arch, mode)

        self.mem = mem
        self.rom = mem.rom_image.rom
        self.rom_config = rom_config
        self.current_device = current_device if current_device is not None else CurrentSelectedDevice.UNDEFINED

    def __disassemble(self, code: bytes, address_offset: int, count:int = 0):
        """Disassembles code from address_offset. Returns an iterator of CsInsn."""
        return self.cs.disasm(code, address_offset, count)

    def in_rom(self, addr: int) -> bool:
        region = self.mem.memory_map.region_lookup(addr)
        return region is not None and (region.kind == RegionKind.ROM or region.kind == RegionKind.MAPPED_ROM)


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
                    return OperandType.INDIRECT, int(base[1:], 16)
                return OperandType.INDIRECT, int(base)
            elif instr.op_str.isdigit():
                return OperandType.INDIRECT, int(instr.op_str)
        except ValueError as e:
            logger.warning(f"Unknown operand format {instr.op_str}: {str(e)}")
            return OperandType.UNKNOWN, 0
            #raise ValueError(f"Unsupported operand format: {op_str}")

    def disassemble_step(self, addr: int):
        #def decode_one(addr: int) -> Instruction | None:
        if not self.in_rom(addr):
            return None
        
        # Add information about the current device if the address region is in the Mapped ROM
        # This is needed to distinguish between multiple mapped regions wich respond to the same address range
        region = self.mem.memory_map.region_lookup(addr)
        if region.kind == RegionKind.MAPPED_ROM and self.current_device == CurrentSelectedDevice.UNDEFINED:
            raise RuntimeError("Address is in MAPPED_ROM region, but no current device is set in Disassembler630x")
        

        #capstone_instr = list(self.__disassemble(self.rom[addr:addr+8], addr, 1))

        # Read the next 8 bytes from memory manager: mapped regions are handled there
        capstone_instr = list(self.__disassemble(self.mem.read_bytes(addr, 8), addr, 1))
        if not capstone_instr:
            return None
        
        ins = capstone_instr[0]

        # TODO Doppeltes lesen?
        ins_bytes = self.mem.read_bytes(addr, ins.size)
        instr = Instruction(address=addr & 0xFFFF, size=ins.size, bytes=ins_bytes, mnemonic=ins.mnemonic, op_str=ins.op_str)

        result = self.parse_op_str(instr)
        if result is not None:
            instr.target_type, instr.target_value = result

        return instr
    
    # def add_function_info(self, rom_address: int, instr: Instruction, var_defs: dict[int, RomVarDefinition]):

    #     if rom_address in var_defs:
    #         var_def = var_defs[rom_address]
    #         if var_def.type != RomVarType.FUNCTION:
    #             logger.warning(f"Address {rom_address:#04x} already defined as {var_def.type}, cannot mark as FUNCTION")
    #             return
    #         if var_def.callers is None:
    #             var_def.callers = []
    #         if instr.address not in var_def.callers:
    #             var_def.callers.append(instr.address)
    #     else:
    #         var_defs[rom_address] = RomVarDefinition(
    #             name=f"fn_{instr.target_value:04X}",
    #             address=rom_address,
    #             type=RomVarType.FUNCTION,
    #             callers=[instr.address],
    #         )

    
    def disassemble_reachable(self, 
                              mapped_start_addr: int, 
                              instructions: dict[int, Instruction],
                              call_tree: Optional[dict] = None,
                              ) -> Tuple[dict[int, Instruction], dict]:
        """
        Disassemble reachable code starting from start_addr, following function calls and jumps.
        Returns a dictionary of instructions and a call tree.
        """

        if call_tree is None: call_tree = {}
        code_bytes = set()
        worklist = [(mapped_start_addr, mapped_start_addr, call_tree)]


        # Skip addresses we detected in previous runs
        #for instr in instructions:
        #    visited.add(instr.address)

        while worklist:
            start, func_entry, tree = worklist.pop()
            start &= 0xFFFF
            func_entry &= 0xFFFF

            cur = start
            cur_rom = self.rom_config.get_mapped_address(cur, self.current_device)
            # While the actual ROM instrction position is not yet visited and the mapped address is in ROM
            while cur_rom not in instructions and self.in_rom(cur):
                instr = self.disassemble_step(cur)
                if instr is None or instr.size <= 0:
                    #visited.add(cur)
                    # TODO None-Instruction als Dummy?
                    break

                if any(((cur + off) & 0xFFFF) in code_bytes for off in range(instr.size)):
                    #visited.add(cur)
                    break

                #addr_to_instr_index[instr.address] = len(instructions)
                instructions[cur_rom] = instr

                for off in range(instr.size):
                    code_bytes.add((instr.address + off) & 0xFFFF)

                #visited.add(cur)

                pc_next = (instr.address + instr.size) & 0xFFFF

                # Function call (jsr, bsr) -> new context
                if instr.is_function_call and instr.target_value is not None:
                    callee = instr.target_value & 0xFFFF
                    subtree = tree.setdefault(callee, {})

                   

                    if instr.target_type == OperandType.INDIRECT:
                        logger.info(f"Indirect function call from {instr.address:#04x} to {instr.target_value:#04x}, only possible in emulation")
                    else:
                        self.rom_config.add_refresh_function(
                            name=f"fn_{callee:04X}",
                            rom_address=self.rom_config.get_mapped_address(callee, self.current_device),
                            current_device=self.current_device,
                            callers=[cur_rom], #instr.address
                        )
                        
                        worklist.append((callee, callee, subtree))

                # Jump (jmp, lbra) -> only take the target and break
                if instr.is_jump and instr.target_value is not None:
                    if instr.target_type == OperandType.INDIRECT:
                        logger.warning(f"Indirect jump from {instr.address:#04x} to {instr.target_value:#04x}, only possible in emulation!")
                    else:
                        worklist.append((instr.target_value, func_entry, tree))
                    break

                # Relativ-Branches: Ziel + Fallthrough
                if instr.is_branch:
                    if instr.target_value is not None:
                        worklist.append((instr.target_value, func_entry, tree))

                        mapped_address = self.rom_config.get_mapped_address(instr.target_value, self.current_device)

                        # Add label if not present
                        self.rom_config.add_refresh_label(
                            name=f"label_0x{mapped_address:04X}_0x{instr.target_value:04X}",
                            rom_address=mapped_address,
                            current_device=self.current_device,
                            callers=[cur_rom], #instr.address
                        )

                    if instr.mnemonic == "bra":
                        break
                    if instr.mnemonic == "lbra":
                        break
                    cur = pc_next
                    cur_rom = self.rom_config.get_mapped_address(cur, self.current_device)
                    continue

                if instr.is_return:
                    break

                cur = pc_next
                cur_rom = self.rom_config.get_mapped_address(cur, self.current_device)

        return instructions, call_tree
    
    @classmethod
    def find_stackpointer(cls, instructions: dict[int, Instruction]) -> Optional[set|int]:
        stack_pointers:set[int] = set()
        
        for _, instr in instructions.items():
            if instr.mnemonic == "lds":
                if instr.target_value is None:
                    raise RuntimeError("find_stackpointer: Found lds instruction, but no target value")
                stack_pointers.add(instr.target_value)
        
        if len(stack_pointers) > 1:
            return stack_pointers
        elif len(stack_pointers) > 0:
            return stack_pointers.pop()
        return None




