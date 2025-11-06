

from dataclasses import dataclass
import logging

from pyparsing import Callable
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.disasm.insn_model import Instruction
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.emu.tracing import MemAccess


class ParserError(Exception):
    pass

@dataclass
class SavedRegisters:
    A: int
    B: int
    D: int
    X: int
    SP: int
    PC: int

logger = logging.getLogger(__name__)


class InstructionParser:

    def __init__(self, rom_cfg: RomConfig, emulator: Emulator6303, read_address: int):
        self.new_calc_address = read_address
        self.new_calc_register = None

        self.emulator = emulator
        self.rom_cfg = rom_cfg

        self.calc_str = ""

        # Don't go into functions for now
        self.jsr_level = 0

        self.saved_registers: SavedRegisters = SavedRegisters(
            A=0,
            B=0,
            D=0,
            X=0,
            SP=0,
            PC=0
        )

        # Buffer that is used by SSM for calculations or final printout
        self.hex_buffer = [
            self.rom_cfg.address_by_name("print_hex_buffer_0"),
            self.rom_cfg.address_by_name("print_hex_buffer_1"),
            self.rom_cfg.address_by_name("print_hex_buffer_2"),
        ]

        # Relevant addresses for calculation
        self.function_ptrs: dict[int, Callable[[Instruction, MemAccess], None]] = {
            rom_cfg.address_by_name("divide"): self.divide,
            rom_cfg.address_by_name("mul16bit"): self.mul16bit,
        }

    def do_step(self, instr: Instruction, access: MemAccess):

        # hier noch was

        # TODO: Man braucht die PPrevious Register auch bevor diese Liste läuft? eigentlich nicht...?

        # Skip return instructions
        if instr.is_return:
            self.jsr_level -= 1
            return
        
        if self.jsr_level > 0:
            return

        try:
            func = getattr(self, instr.mnemonic)
            func(instr, access)
        except AttributeError: # For unknown functions
                raise ParserError(f"Unknown instruction: {instr.mnemonic} at address 0x{instr.address:04X}")
        
        self.saved_registers = SavedRegisters(
            A=self.emulator.A,
            B=self.emulator.B,
            D=(self.emulator.A << 8)|(self.emulator.B ),
            X=self.emulator.X,
            SP=self.emulator.SP,
            PC=self.emulator.PC
        )

        print(f"Current calculation: {self.calc_str}", flush=True)

    def divide(self, instr: Instruction, access: MemAccess):
        if self.new_calc_address in self.hex_buffer or self.new_calc_address == self.hex_buffer:
            '''or (
        isinstance(self.new_calc_address, (list, tuple))
        and any(addr in self.hex_buffer for addr in self.new_calc_address)
    )'''
            self.calc_str += f" / {self.saved_registers.D}"
            self.new_calc_register = None
            self.new_calc_address = self.hex_buffer
    
    def mul16bit(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "D" or self.new_calc_register == "B":
            self.calc_str += f" * {self.saved_registers.X}"
            self.new_calc_register = None
            self.new_calc_address = self.hex_buffer
        elif self.new_calc_register == "X":
            self.calc_str += f" * {self.saved_registers.D}"
            self.new_calc_register = None
            self.new_calc_address = self.hex_buffer

    def ldaa(self, instr: Instruction, access: MemAccess):
        if instr.target_value == self.new_calc_address or \
            (isinstance(self.new_calc_address, (list, tuple)) and instr.target_value in self.new_calc_address):
            self.new_calc_address = None
            self.new_calc_register = "A"

    def ldab(self, instr: Instruction, access: MemAccess):
        if instr.target_value == self.new_calc_address or \
            (isinstance(self.new_calc_address, (list, tuple)) and instr.target_value in self.new_calc_address):
            self.new_calc_address = None
            self.new_calc_register = "B"
    
    def ldd(self, instr: Instruction, access: MemAccess):
        if instr.target_value == self.new_calc_address or \
            (isinstance(self.new_calc_address, (list, tuple)) and instr.target_value in self.new_calc_address):
            self.new_calc_address = None
            self.new_calc_register = "D"

    def staa(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.new_calc_address = instr.target_value
            self.new_calc_register = None

    def stab(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "B":
            self.new_calc_address = instr.target_value
            self.new_calc_register = None

    def std(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "D":
            self.new_calc_address = instr.target_value
            self.new_calc_register = None
    
    def addd(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "D":
            self.calc_str += f" + {instr.target_value}"
    
    def mul(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.calc_str += f" * {self.saved_registers.B}"
            self.new_calc_register = "D"
        elif self.new_calc_register == "B":
            self.calc_str += f" * {self.saved_registers.A}"
            self.new_calc_register = "D"
    
    def clr(self, instr: Instruction, access: MemAccess):
        if self.new_calc_address == instr.target_value:
            self.calc_str += " * 0"
            self.new_calc_address = None
            self.new_calc_register = None

    def clra(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.calc_str += " * 0"
            self.new_calc_register = None
            self.new_calc_address = None
    
    def clrb(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "B":
            self.calc_str += " * 0"
            self.new_calc_register = None
            self.new_calc_address = None

    def jsr(self, instr: Instruction, access: MemAccess):
        if instr.target_value is None:
            raise ParserError(f"JSR instruction without target value at address 0x{instr.address:04X}")
        func = self.function_ptrs.get(instr.target_value, None)
        if func is not None:
            func(instr, access)
        else:
            logger.debug(f"Skipping JSR to 0x{instr.target_value:04X} at address 0x{instr.address:04X}")

        self.jsr_level += 1
