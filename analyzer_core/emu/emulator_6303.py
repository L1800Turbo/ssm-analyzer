# analyzer_core/emu/emulator_6303.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Callable, Dict
import logging

    # Capstone-Import entfernt, stattdessen Disassembler/Instruction

from analyzer_core.config.memory_map import MemoryMap, MemoryRegion, RegionKind
from analyzer_core.config.ssm_model import CurrentSelectedDevice
from analyzer_core.emu.asm_html_logger import AsmHtmlLogger
from analyzer_core.emu.memory_manager import MemoryManager
from analyzer_core.data.rom_image import RomImage
from analyzer_core.disasm.insn_model import Instruction
from analyzer_core.emu.hooks import HookManager
from analyzer_core.emu.tracing import ExecutionTracer, MemAccess
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.disasm.capstone_wrap import Disassembler630x, OperandType

class EmulationError(Exception):
    pass

logger = logging.getLogger(__name__)

@dataclass
class CPUFlags:
    C: int = 0  # Carry
    Z: int = 0  # Zero
    N: int = 0  # Negative
    V: int = 0  # Overflow
    I: int = 0  # IRQ mask

    def to_byte(self) -> int:
        return ((self.N & 0x01) << 7) | ((self.V & 0x01) << 6) | (1 << 5) | ((self.I & 0x01) << 4) | ((self.Z & 0x01) << 2) | (0 << 1) | (self.C & 0x01)

def operand_needed(func):
    def wrapper(self, instr: Instruction):
        if instr.op_str is None:
            raise ValueError(f"Instruction {instr.mnemonic} needs operand, but none given")
        elif instr.target_value is None:
            raise ValueError(f"Instruction {instr.mnemonic} needs target address, but none given")
        elif instr.target_type is None:
            raise ValueError(f"Instruction {instr.mnemonic} needs target type, but none given")
        return func(self, instr)
    return wrapper

class Emulator6303:
    def __init__(
        self,
        rom_image: RomImage,
        current_device = CurrentSelectedDevice.UNDEFINED,
        #dasm: Optional[Disassembler630x] = None,
        rom_config: Optional[RomConfig] = None,
        hooks: Optional[HookManager] = None,
        tracer: Optional[ExecutionTracer] = None,
        memory_map: Optional[MemoryMap] = None,
        start_pc: int = 0xFFFF,
        initial_sp: Optional[int] = None
    ) -> None:
        
        #self.dasm = dasm if dasm else Disassembler630x(rom=rom_image.rom) # TODO Das noch raus, wird aber aus den Mocks genommen, mit debugger ugcken, wie man das weg bekommt
        self._current_device = current_device

        self.memory_map = memory_map if memory_map else MemoryMap()
        self.hooks = hooks or HookManager()
        self.mem = MemoryManager(self.memory_map, rom_image, hooks=self.hooks)
        self.tracer = tracer or ExecutionTracer() # TODO Tracer einbauen
        self.rom_config = rom_config or RomConfig()

        # Register
        self.A = 0
        self.B = 0
        self.X = 0
        self.SP = initial_sp if initial_sp is not None else self.rom_config.get_stack_pointer()
        self.PC = start_pc & 0xFFFF
        self.flags = CPUFlags()

        self.asm_logger: dict[str, Callable[[Instruction, MemAccess], None]] = {}

        self.last_run_steps = 0

        # TODO Noch registrieren und hier weg
        # try:
        #     log_path = Path("logs/asm_trace.html")
        #     self.asm_html_logger = AsmHtmlLogger(log_path, append=True)
        # except Exception:
        #     self.asm_html_logger = None

    def set_current_device(self, device: CurrentSelectedDevice):
        self._current_device = device


    # --- Helpers for tracing / logging ---
    def add_logger(self, name:str, callback:Callable[[Instruction, MemAccess], None]) -> None:
        self.asm_logger[name] = callback
    
    def remove_logger(self, name:str) -> None:
        if name in self.asm_logger:
            del self.asm_logger[name]

    # --- Helpers: memory/registers/stack ---
    def __read_value8(self, instr: Instruction) -> MemAccess:
        if instr.target_value is None or instr.target_type is None:
            raise ValueError(f"Instruction {instr.mnemonic} needs target address and type, but none given")
        
        if instr.target_type == OperandType.DIRECT:
            addr = instr.target_value
            val = self.read8(addr)
        elif instr.target_type == OperandType.IMMEDIATE:
            addr = None
            val = instr.target_value
        elif instr.target_type == OperandType.INDIRECT:
            addr = (self.X + instr.target_value) & 0xFFFF
            val = self.read8(addr)
        else:
            raise ValueError(f"Unsupported operand type: {instr.target_type}")
        
        return MemAccess(
            instr=instr,
            target_addr=addr,
            var=self.rom_config.get_by_address(addr) if addr is not None else None,
            value=val,
            rw='R',
            by=self.PC,
            next_instr_addr=None
        )

    def __read_value16(self, instr: Instruction) -> MemAccess:
        if instr.target_value is None or instr.target_type is None:
            raise ValueError("Invalid instruction: missing target address or type.")

        if instr.target_type == OperandType.DIRECT:
            addr = instr.target_value
            val = self.read16(addr)
        elif instr.target_type == OperandType.IMMEDIATE:
            addr = None
            val = instr.target_value & 0xFFFF
        elif instr.target_type == OperandType.INDIRECT:
            addr = (self.X + instr.target_value) & 0xFFFF
            val = self.read16(addr)
        else:
            raise ValueError(f"Unsupported operand type: {instr.target_type}")

        return MemAccess(
            instr=instr,
            target_addr=addr,
            var=self.rom_config.get_by_address(addr) if addr is not None else None,
            value=val,
            rw='R',
            by=self.PC,
            next_instr_addr=None
        )
    
    def set_pc(self, addr: int) -> None:
        self.PC = addr & 0xFFFF
        # TODO Hier auch die Memorymap einbauen falls mapped_memory genommen wird!

    def read8(self, addr: int) -> int:
        val = self.mem.read(addr & 0xFFFF) & 0xFF
        return val

    def write8(self, addr: int, value: int) -> None:
        self.mem.write(addr & 0xFFFF, value & 0xFF)

    def read16(self, addr: int) -> int:
        hi = self.read8(addr)
        lo = self.read8((addr + 1) & 0xFFFF)
        return ((hi << 8) | lo) & 0xFFFF

    def write16(self, addr: int, value: int) -> None:
        hi = (value >> 8) & 0xFF
        lo = value & 0xFF
        self.write8(addr, hi)
        self.write8((addr + 1) & 0xFFFF, lo)

    def push8(self, b: int) -> None:
        # 6800/630x: write at SP, then decrement SP
        self.write8(self.SP, b & 0xFF)
        self.SP = (self.SP - 1) & 0xFFFF

    def push16(self, w: int) -> None:
        self.push8((w >> 8) & 0xFF)
        self.push8(w & 0xFF)

    def pull8(self) -> int:
        self.SP = (self.SP + 1) & 0xFFFF
        return self.read8(self.SP)

    def pull16(self) -> int:
        lo = self.pull8()
        hi = self.pull8()
        return ((hi << 8) | lo) & 0xFFFF

    def _set_ZN_8(self, value: int) -> None:
        v8 = value & 0xFF
        self.flags.Z = 1 if v8 == 0 else 0
        self.flags.N = 1 if (v8 & 0x80) else 0
    
    def _set_ZN_16(self, value: int) -> None:
        v16 = value & 0xFFFF
        self.flags.Z = 1 if v16 == 0 else 0
        self.flags.N = 1 if (v16 & 0x8000) else 0

    # --- Instruction helpers (subset; ausbaufähig) ---
    def _AND8(self, lhs: int, rhs: int) -> int:
        res = (lhs & rhs) & 0xFF
        self._set_ZN_8(res)
        self.flags.V = 0
        return res

    def _OR8(self, lhs: int, rhs: int) -> int:
        res = (lhs | rhs) & 0xFF
        self._set_ZN_8(res)
        self.flags.V = 0
        return res

    def _ADD8(self, lhs: int, rhs: int) -> int:
        s = (lhs & 0xFF) + (rhs & 0xFF)
        self._set_ZN_8(s)
        self.flags.C = 1 if s > 0xFF else 0
        # Overflow (signed)
        a, b, r = lhs & 0xFF, rhs & 0xFF, s & 0xFF
        self.flags.V = 1 if ((a ^ r) & (b ^ r) & 0x80) else 0
        return s & 0xFF

    def _SUB8(self, lhs: int, rhs: int) -> int:
        s = (lhs & 0xFF) - (rhs & 0xFF)
        r = s & 0xFF
        self._set_ZN_8(r)
        self.flags.C = 1 if (lhs & 0xFF) < (rhs & 0xFF) else 0
        self.flags.V = 1 if (((lhs ^ rhs) & (lhs ^ r) & 0x80) != 0) else 0
        return r
    
    def _shift_left(self, value):
        old = value
        self.flags.C = (old >> 7) & 0x01
        result = (old << 1) & 0xFF
        self._set_ZN_8(result)
        self.flags.V = 1 if ((old ^ result) & 0x80) != 0 else 0
        return result

    def _shift_right(self, value, arithmetic=False):
        old = value
        self.flags.C = old & 0x01
        
        if arithmetic:
            result = ((old >> 1) | (old & 0x80)) & 0xFF
        else:
            result = (old >> 1) & 0xFF
        self._set_ZN_8(result)
        self.flags.V = 0
        return result

    def _rotate_left(self, value):
        old = value
        carry_in = self.flags.C
        self.flags.C = (old >> 7) & 0x01
        result = ((old << 1) | carry_in) & 0xFF
        self._set_ZN_8(result)
        self.flags.V = 1 if ((old ^ result) & 0x80) != 0 else 0
        return result

    def _rotate_right(self, value):
        old = value
        carry_in = self.flags.C << 7
        self.flags.C = old & 0x01
        result = ((old >> 1) | carry_in) & 0xFF
        self._set_ZN_8(result)
        self.flags.V = 1 if ((old ^ result) & 0x80) != 0 else 0
        return result
    
    def _transfer(self, src, dst):
        setattr(self, dst, getattr(self, src))
        self._set_ZN_8(getattr(self, dst))


    # --- Step/Execute ---
    def get_current_instruction(self) -> Optional[Instruction]:
        mapped_pc = self.rom_config.get_mapped_address(self.PC, self._current_device)
        return self.rom_config.instructions.get(mapped_pc)
        #for instr in self.rom_config.instructions:
        #    if instr.address == self.PC:
        #        return instr
        
        
        #raise EmulationError(f"Couldn't find decompiled instruction at address 0x{self.PC:04X}")
        #return self.dasm.disassemble_step(self.PC)

        # Alternative approach: disassemble everything we get to
    
    def mock_return(self) -> None:
        ret_addr = self.pull16()
        self.PC = ret_addr & 0xFFFF

        # Take care of post-hooks as we might miss them by skipping instructions
        for pc in list(self.hooks.waiting_for_post_hook.keys()):
            level = self.hooks.waiting_for_post_hook[pc]
            if level > 0:
                self.hooks.waiting_for_post_hook[pc] -= 1
            if self.hooks.waiting_for_post_hook[pc] == 0:
                try:
                    self.hooks.run_post_hooks(pc, self, None)
                    self.hooks.waiting_for_post_hook.pop(pc)
                except Exception as e:
                    raise EmulationError(f"Post-hook at 0x{pc:04X} failed: {e}")


    def step(self) -> Optional[MemAccess]:
        # run pre-hooks (they may set memory/registers but must not consume the instruction)
        try:
            self.hooks.run_pre_hooks(self.PC, self)
        except Exception as e:
            raise EmulationError(f"Pre-hook at 0x{self.PC:04X} failed: {e}")
        
        if len(self.hooks.get_post_hooks(self.PC)) > 0:
            self.hooks.waiting_for_post_hook[self.PC] = 1


        # Check if this function is checked to be mocked
        mock_fn = self.hooks.get_mock(self.PC)
        if mock_fn:
            mock_fn(self)
            return
    
        instr = self.get_current_instruction()
        if not instr:
            raise EmulationError(f"No instruction at 0x{self.PC:04X}") # TODO Mapped und so angeben
        
        # TODO Debug-Nachricht bauen bei Funktionsaufruf, wenn unbekannte Funktion aufgerufen wird?
        
        try:
            func = getattr(self, instr.mnemonic)

            asm_step: MemAccess = func(instr)

            if instr.address == 0x93AE: # SVX96 YEAR mit 199*
                pass

            if instr.address == 0x2B75: # DIO1 bei 0x2C36 für 4AT könnte auch noch komisch werden -> romid3 abhängig
                pass

            if instr.address == 0x9085: # SVX96 VorActionComms
                pass

            if instr.address == 0x3728:
                pass

            if instr.address == 0x372B:
                pass

          


            for logger in self.asm_logger.values():
                logger(instr, asm_step)


            # Take care of post-hooks
            for pc in list(self.hooks.waiting_for_post_hook.keys()):
                level = self.hooks.waiting_for_post_hook[pc]
                if instr.is_function_call and level > 0:
                    # Function call: set level for post-hook
                    self.hooks.waiting_for_post_hook[pc] += 1
                elif instr.is_return and level > 0:
                    self.hooks.waiting_for_post_hook[pc] -= 1
                if self.hooks.waiting_for_post_hook[pc] == 0:
                    try:
                        self.hooks.run_post_hooks(pc, self, asm_step)
                        self.hooks.waiting_for_post_hook.pop(pc)
                    except Exception as e:
                        raise EmulationError(f"Post-hook at 0x{pc:04X} failed: {e}")

            return asm_step
        
        except AttributeError: # For unknown functions
                raise EmulationError(f"Unknown instruction: {instr.mnemonic} at address {self.PC:02X}")
                                #f" stack trace: {self.format_call_stack()}")



    def run_function_end(self, max_steps: int = 100000, abort_pc:int|None = None) -> Optional[MemAccess]: #clear_mocks_after: bool = True
        """
        Run from the current PC into functions and back until a RTS/RTI from the current level is reached.
        """

        # If we want to run until this level's rts/rti or abort at specific PC
        if abort_pc is not None:
            sentinel = abort_pc & 0xFFFF
        else:
            sentinel = 0xFFFF

            # Guarantee unique sentinel
            self.push16(sentinel)

        last_step = None
        steps = 0
        while steps < max_steps:
            if self.PC == sentinel:
                break

            if self.PC == 0x2AA6:
                pass

            last_step = self.step()
            steps += 1

        if steps >= max_steps:
            raise TimeoutError("run_function_end: step limit exceeded")
        
        self.last_run_steps = steps

        #print(f"Emulated steps from {start_pc:04X}: {steps}")

        return last_step




    # ------------------------ Assembler functions ------------------------

    
    @operand_needed
    def ldaa(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        self.A = ma.value & 0xFF
        self._set_ZN_8(self.A)
        self.flags.C = self.flags.V = 0

        self.PC += instr.size
        ma.next_instr_addr = self.PC

        return ma
    
    @operand_needed
    def ldab(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")

        self.B = ma.value & 0xFF
        self._set_ZN_8(self.B)
        self.flags.C = self.flags.V = 0

        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma

    @operand_needed
    def staa(self, instr: Instruction) -> MemAccess:
        val = self.A
        addr:int = instr.target_value # type: ignore -> checked by decorator

        if instr.target_type == OperandType.DIRECT:
            self.write8(addr, val)
        elif instr.target_type == OperandType.INDIRECT:
            addr = (self.X + addr) & 0xFFFF
            self.write8(addr, val)
        else:
            raise ValueError("Unsupported store")

        self._set_ZN_8(val)
        self.flags.V = 0
        # Carry unchanged

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
                instr=instr,
                target_addr=addr,
                var=self.rom_config.get_by_address(addr),
                value=val,
                rw='W',
                by=self.PC,
                next_instr_addr=self.PC
            )

    @operand_needed
    def stab(self, instr: Instruction) -> MemAccess:
        val = self.B
        addr:int = instr.target_value # type: ignore -> checked by decorator

        if instr.target_type == OperandType.DIRECT:
            self.write8(addr, val)
        elif instr.target_type == OperandType.INDIRECT:
            addr = (self.X + addr) & 0xFFFF
            self.write8(addr, val)
        else:
            raise ValueError("Unsupported store")

        self._set_ZN_8(val)
        self.flags.V = 0
        # Carry unchanged

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
                instr=instr,
                target_addr=addr,
                var=self.rom_config.get_by_address(addr),
                value=val,
                rw='W',
                by=self.PC,
                next_instr_addr=self.PC
            )

    @operand_needed
    def ldd(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value16(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        self.A = (ma.value >> 8) & 0xFF
        self.B = ma.value & 0xFF
        self._set_ZN_16(ma.value)
        self.flags.V = 0

        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma
    
    @operand_needed
    def ldx(self, instr: Instruction) -> MemAccess:
        """Load 16-bit value into X."""
        ma = self.__read_value16(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        self.X = ma.value & 0xFFFF
        self._set_ZN_8(ma.value)
        self.flags.V = 0

        self.PC += instr.size
        ma.next_instr_addr=self.PC

        return ma



    @operand_needed
    def std(self, instr: Instruction) -> MemAccess:
        val = ((self.A & 0xFF) << 8) | (self.B & 0xFF)
        addr:int = instr.target_value # type: ignore -> checked by decorator
        
        self.write16(addr, val)

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=addr,
            var=self.rom_config.get_by_address(addr),
            value=val,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )


    @operand_needed
    def stx(self, instr: Instruction) -> MemAccess:
        val = self.X
        address:int = instr.target_value # type: ignore -> checked by decorator
        self.write16(address, val)
        
        self._set_ZN_8(val)
        self.flags.V = 0
        # Carry unchanged

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=address,
            var=self.rom_config.get_by_address(address),
            value=val,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )


    @operand_needed
    def anda(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        self.A = (self.A & ma.value) & 0xFF
        self._set_ZN_8(self.A)
        self.flags.V = 0

        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma
    
    @operand_needed
    def andb(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        self.B = (self.B & ma.value) & 0xFF
        self._set_ZN_8(self.B)
        self.flags.V = 0

        old_PC = self.PC
        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma
    
    @operand_needed
    def bita(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        self._set_ZN_8(self.A & ma.value)
        self.flags.V = 0

        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma
    
    @operand_needed
    def bitb(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        self._set_ZN_8(self.B & ma.value)
        self.flags.V = 0

        old_PC = self.PC
        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma

    @operand_needed
    def cmpa(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        _ = self._SUB8(self.A, ma.value)

        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma

    @operand_needed
    def cmpb(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        _ = self._SUB8(self.B, ma.value)

        old_PC = self.PC
        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma

    @operand_needed
    def oraa(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        self.A = (self.A | ma.value) & 0xFF
        self._set_ZN_8(self.A)
        self.flags.V = 0

        old_PC = self.PC
        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma
    
    @operand_needed
    def orab(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        self.B = (self.B | ma.value) & 0xFF
        self._set_ZN_8(self.B)
        self.flags.V = 0

        old_PC = self.PC
        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma
    
    @operand_needed
    def eora(self, instr: Instruction) -> MemAccess:
        addr = instr.target_value
        if addr is None:
            raise ValueError("Invalid target address")

        self.A = (self.A ^ addr) & 0xFF
        self._set_ZN_8(self.A)
        self.flags.V = 0

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def clra(self, instr: Instruction) -> MemAccess:
        self.A = 0
        self._set_ZN_8(self.A)
        self.flags.V = 0
        self.flags.C = 0

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def clrb(self, instr: Instruction) -> MemAccess:
        self.B = 0
        self._set_ZN_8(self.B)
        self.flags.V = 0
        self.flags.C = 0
        
        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    @operand_needed
    def clr(self, instr: Instruction) -> MemAccess:
        addr = instr.target_value
        if addr is None:
            raise ValueError("Invalid target address")
        
        self.write8(addr, 0x00)
        self.flags.Z = 1
        self.flags.N = 0
        self.flags.V = 0
        self.flags.C = 0

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=addr,
            var=self.rom_config.get_by_address(addr),
            value=0,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def asla(self, instr: Instruction) -> MemAccess:
        self.A = self._shift_left(self.A)

        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def aslb(self, instr: Instruction) -> MemAccess:
        self.B = self._shift_left(self.B)
        
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.B),
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def asl(self, instr: Instruction) -> MemAccess:
        addr = instr.target_value
        if addr is None:
            raise ValueError("Invalid target address")
        
        val = self.read8(addr)
        val = self._shift_left(val)
        self.write8(addr, val)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=addr,
            var=self.rom_config.get_by_address(addr),
            value=val,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def asra(self, instr: Instruction) -> MemAccess:
        self.A = self._shift_right(self.A, arithmetic=True)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def asrb(self, instr: Instruction) -> MemAccess:
        self.B = self._shift_right(self.B, arithmetic=True)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def lsra(self, instr: Instruction) -> MemAccess:
        self.A = self._shift_right(self.A, arithmetic=False)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def lsrb(self, instr: Instruction) -> MemAccess:
        self.B = self._shift_right(self.B, arithmetic=False)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.B),
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    @operand_needed
    def lsr(self, instr: Instruction) -> MemAccess:
        addr = instr.target_value
        if addr is None:
            raise ValueError("Invalid target address")
        
        val = self.read8(addr)
        val = self._shift_right(val, arithmetic=False)
        self.write8(addr, val)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=addr,
            var=self.rom_config.get_by_address(addr),
            value=val,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    
    def rola(self, instr: Instruction) -> MemAccess:
        self.A = self._rotate_left(self.A)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def rolb(self, instr: Instruction) -> MemAccess:
        self.B = self._rotate_left(self.B)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.B),
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def rol(self, instr: Instruction) -> MemAccess:
        addr = instr.target_value
        if addr is None:
            raise ValueError("Invalid target address")
        
        val = self.read8(addr)
        val = self._rotate_left(val)
        self.write8(addr, val)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=addr,
            var=self.rom_config.get_by_address(addr),
            value=val,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def ror(self, instr: Instruction) -> MemAccess:
        addr = instr.target_value
        if addr is None:
            raise ValueError("Invalid target address")
        
        val = self.read8(addr)
        val = self._rotate_right(val)
        self.write8(addr, val)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=addr,
            var=self.rom_config.get_by_address(addr),
            value=val,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def rora(self, instr: Instruction) -> MemAccess:
        self.A = self._rotate_right(self.A)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def rorb(self, instr: Instruction) -> MemAccess:
        self.B = self._rotate_right(self.B)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.B),
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
        
      
    @operand_needed
    def adda(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        self.A = self._ADD8(self.A, ma.value)
        self.PC += instr.size
        ma.next_instr_addr=self.PC
        return ma

    @operand_needed
    def addb(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        self.B = self._ADD8(self.B, ma.value)
        self._set_ZN_8(self.B)

        self.PC += instr.size
        ma.next_instr_addr=self.PC
        return ma

    @operand_needed
    def suba(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        self.A = self._SUB8(self.A, ma.value)
        self._set_ZN_8(self.A)
        
        self.PC += instr.size
        ma.next_instr_addr=self.PC
        return ma

    @operand_needed
    def subb(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        self.B = self._SUB8(self.B, ma.value)
        self._set_ZN_16(self.B)
        
        self.PC += instr.size
        ma.next_instr_addr=self.PC
        return ma
    
    @operand_needed
    def addd(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value16(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        d = ((self.A << 8) | self.B) & 0xFFFF
        result = (d + ma.value) & 0xFFFF
        self._set_ZN_16(result)
        self.flags.C = 1 if d + ma.value > 0xFFFF else 0
        self.flags.V = 1 if ((~(d ^ ma.value)) & (d ^ result) & 0x8000) != 0 else 0
        self.A = (result >> 8) & 0xFF
        self.B = result & 0xFF

        ma.value = result
        
        self.PC += instr.size
        ma.next_instr_addr=self.PC
        return ma

    @operand_needed
    def subd(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value16(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        d = ((self.A << 8) | self.B) & 0xFFFF
        result = (d - ma.value) & 0xFFFF
        self._set_ZN_16(result)
        self.flags.C = 1 if d < ma.value else 0
        self.flags.V = 1 if ((d ^ ma.value) & (d ^ result) & 0x8000) != 0 else 0
        self.A = (result >> 8) & 0xFF
        self.B = result & 0xFF

        ma.value = result
        
        self.PC += instr.size
        ma.next_instr_addr=self.PC
        return ma
    
    def aba(self, instr: Instruction) -> MemAccess:
        result = (self.A + self.B) & 0xFF
        self._set_ZN_8(result)
        self.flags.C = 1 if self.A + self.B > 0xFF else 0
        self.flags.V = 1 if ((self.A ^ result) & (self.B ^ result) & 0x80) != 0 else 0
        self.A = result

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def sba(self, instr: Instruction) -> MemAccess:
        """Subtract B from A."""
        result = (self.A - self.B) & 0xFF
        self._set_ZN_8(result)
        self.flags.C = 1 if self.A < self.B else 0
        self.flags.V = 1 if ((self.A ^ self.B) & (self.A ^ result) & 0x80) != 0 else 0
        self.A = result

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    @operand_needed
    def adca(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        carry_in = self.flags.C
        result = self.A + ma.value + carry_in
        self._set_ZN_8(result)
        self.flags.C = 1 if result > 0xFF else 0
        self.flags.V = 1 if ((self.A ^ result) & (ma.value ^ result) & 0x80) != 0 else 0
        self.A = result & 0xFF

        ma.value = result
        #ma.rw = 'W'
        
        self.PC += instr.size
        ma.next_instr_addr=self.PC
        return ma

    @operand_needed
    def adcb(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        carry_in = self.flags.C
        result = self.B + ma.value + carry_in
        self._set_ZN_8(result)
        self.flags.C = 1 if result > 0xFF else 0
        self.flags.V = 1 if ((self.B ^ result) & (ma.value ^ result) & 0x80) != 0 else 0
        self.B = result & 0xFF

        ma.value = result
        ma.rw = 'W'
        
        self.PC += instr.size
        ma.next_instr_addr=self.PC
        return ma

    def inca(self, instr: Instruction) -> MemAccess:
        self.A = (self.A + 1) & 0xFF
        self._set_ZN_8(self.A)
        
        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def incb(self, instr: Instruction) -> MemAccess:
        self.B = (self.B + 1) & 0xFF
        self._set_ZN_8(self.B)

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.B),
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def deca(self, instr: Instruction) -> MemAccess:
        self.A = (self.A - 1) & 0xFF
        self._set_ZN_8(self.A)
        
        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def decb(self, instr: Instruction) -> MemAccess:
        self.B = (self.B - 1) & 0xFF
        self._set_ZN_8(self.B)
        
        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.B),
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    @operand_needed
    def inc(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.target_addr is None or ma.value is None:
            raise ValueError("Invalid memory access")
        
        result = (ma.value + 1) & 0xFF
        self._set_ZN_8(result)
        self.write8(ma.target_addr, result)

        ma.value = result
        ma.rw = 'W'
        
        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma
    
    @operand_needed
    def dec(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        if ma.target_addr is None or ma.value is None:
            raise ValueError("Invalid memory access")
        result = (ma.value - 1) & 0xFF
        self._set_ZN_8(result)
        self.write8(ma.target_addr, result)
        
        ma.value = result
        ma.rw = 'W'
        
        self.PC += instr.size
        ma.next_instr_addr = self.PC
        return ma

    def mul(self, instr: Instruction) -> MemAccess:
        """Multiply A * B unsigned, result in D (A=high, B=low)"""
        result = (self.A & 0xFF) * (self.B & 0xFF)
        self.A = (result >> 8) & 0xFF
        self.B = result & 0xFF
        self.flags.Z = 1 if result == 0 else 0

        old_PC = self.PC
        self.PC += instr.size
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.A),
            value=result,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
        
    def inx(self, instr: Instruction) -> MemAccess:
        old = self.X
        self.X = (self.X + 1) & 0xFFFF

        # Flags
        self._set_ZN_8(self.X)
        self.flags.V = 1 if old == 0x7FFF and self.X == 0x8000 else 0
        # C bleibt unverändert

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.X),
            value=self.X,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def dex(self, instr: Instruction) -> MemAccess:
        old = self.X
        self.X = (self.X - 1) & 0xFFFF

        # Flags
        self._set_ZN_8(self.X)
        self.flags.V = 1 if old == 0x7FFF and self.X == 0x8000 else 0
        # C bleibt unverändert

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(self.X),
            value=self.X,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )


    @operand_needed
    def bra(self, instr: Instruction) -> MemAccess:
        old_PC = self.PC
        self.PC = instr.target_value # type: ignore

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )

    @operand_needed
    def beq(self, instr: Instruction) -> MemAccess:
        old_PC = self.PC

        if self.flags.Z == 1:
            self.PC = instr.target_value # type: ignore
        else:
            self.PC += instr.size
        
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )
        
        
    
    @operand_needed
    def bne(self, instr: Instruction) -> MemAccess:
        old_PC = self.PC

        if self.flags.Z == 0:
            self.PC = instr.target_value # type: ignore
        else:
            self.PC += instr.size
        
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    @operand_needed
    def bcc(self, instr: Instruction) -> MemAccess:
        old_PC = self.PC

        if self.flags.C == 0:
            self.PC = instr.target_value # type: ignore
        else:
            self.PC += instr.size
        
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )


    @operand_needed
    def bcs(self, instr: Instruction) -> MemAccess:
        old_PC = self.PC

        if self.flags.C == 1:
            self.PC = instr.target_value # type: ignore
        else:
            self.PC += instr.size
        
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )

    @operand_needed
    def bmi(self, instr: Instruction) -> MemAccess:
        """Branch if Minus (N == 1)"""
        old_PC = self.PC

        if self.flags.N == 1:
            self.PC = instr.target_value  # type: ignore
        else:
            self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    @operand_needed
    def bhi(self, instr: Instruction) -> MemAccess:
        """Branch if Higher (C == 0 and Z == 0)"""
        old_PC = self.PC

        if self.flags.C == 0 and self.flags.Z == 0:
            self.PC = instr.target_value
        else:
            self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )

    @operand_needed
    def bpl(self, instr: Instruction) -> MemAccess:
        """Branch if Plus (N == 0)"""
        old_PC = self.PC

        if self.flags.N == 0:
            self.PC = instr.target_value
        else:
            self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    @operand_needed
    def bge(self, instr: Instruction) -> MemAccess:
        """Branch if Greater or Equal (N == V)"""
        old_PC = self.PC

        if self.flags.N == self.flags.V:
            self.PC = instr.target_value
        else:
            self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    @operand_needed
    def bls(self, instr: Instruction) -> MemAccess:
        """Branch if Lower or Same (C == 1 or Z == 1)"""
        old_PC = self.PC

        if self.flags.C == 1 or self.flags.Z == 1:
            self.PC = instr.target_value
        else:
            self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def psha(self, instr: Instruction) -> MemAccess:
        self.push8(self.A)

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.SP,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def pshb(self, instr: Instruction) -> MemAccess:
        self.push8(self.B)

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.SP,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )


    
    def pula(self, instr: Instruction) -> MemAccess:
        self.A = self.pull8()

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.SP,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def pulb(self, instr: Instruction) -> MemAccess:
        self.B = self.pull8()

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.SP,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )


    def tab(self, instr: Instruction) -> MemAccess:
        self._transfer('A', 'B')
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def tba(self, instr: Instruction) -> MemAccess:
        self._transfer('B', 'A')
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )



    def coma(self, instr: Instruction) -> MemAccess:
        """One's complement A"""
        self.A = (~self.A) & 0xFF
        self._set_ZN_8(self.A)
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def comb(self, instr: Instruction) -> MemAccess:
        """One's complement B"""
        self.B = (~self.B) & 0xFF
        self._set_ZN_8(self.B)
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def nega(self, instr: Instruction) -> MemAccess:
        self.A = -self.A & 0xFF
        self._set_ZN_8(self.A)
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def negb(self, instr: Instruction) -> MemAccess:
        self.B = -self.B & 0xFF
        self._set_ZN_8(self.B)
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.B,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def nop(self, instr: Instruction) -> MemAccess:
        """No Operation"""
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=None,
            rw='',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def cli(self, instr: Instruction) -> MemAccess:
        """Clear Interrupt Mask (I = 0)"""
        self.flags.I = 0
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=None,
            rw='',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def rti(self, instr: Instruction) -> MemAccess:
        """Return from Interrupt (nur PC, Flags optional)"""
        old_PC = self.PC
        self.PC = self.pull16()
        # Flags ggf. vom Stack holen (optional)

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=None,
            rw='',
            by=self.PC,
            next_instr_addr=self.PC
        )

    @operand_needed
    def tst(self, instr: Instruction) -> MemAccess:
        ma = self.__read_value8(instr)
        
        if ma.target_addr is None or ma.value is None:
            raise ValueError("Invalid memory access")


        # Flags setzen
        self._set_ZN_8(ma.value)
        self.flags.V = 0  # Always clear overflow flag
        # No changes to carry

        old_PC = self.PC
        self.PC += instr.size
        ma.next_instr_addr=self.PC
        return ma

    def tsta(self, instr: Instruction) -> MemAccess:
        # Flags setzen
        self._set_ZN_8(self.A)
        self.flags.V = 0  # Always clear overflow flag
        # No changes to carry

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.A,
            rw='',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def pshx(self, instr: Instruction) -> MemAccess:
        """Push X auf Stack"""
        self.push16(self.X)

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.X,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def pulx(self, instr: Instruction) -> MemAccess:
        """Pull X vom Stack"""
        self.X = self.pull16()
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.X,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def abx(self, instr: Instruction) -> MemAccess:
        """Add B to X"""
        self.X = (self.X + self.B) & 0xFFFF
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.X,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    @operand_needed
    def cpx(self, instr: Instruction) -> MemAccess:
        """Compare X with value"""
        ma = self.__read_value16(instr)
        if ma.value is None:
            raise ValueError("Invalid memory access")
        
        result = (self.X - ma.value) & 0xFFFF
        self._set_ZN_8(result)
        self.flags.V = 1 if ((self.X ^ ma.value) & (self.X ^ result) & 0x8000) != 0 else 0
        self.flags.C = 1 if self.X < ma.value else 0

        old_PC = self.PC
        self.PC += instr.size  
        ma.next_instr_addr=self.PC
        return ma

    # @operand_needed
    # def bsr(self, insn: CsInsn):
    #     """Branch to Subroutine (relative)"""
    #     return_addr = self.PC + insn.size
    #     self.push16(return_addr)
    #     type, offset = self.dasm.parse_operand(insn.op_str)
    #     self.PC = offset

    def xgdx(self, instr: Instruction) -> MemAccess:
        """Exchange D (A+B) with X"""
        d = (self.A << 8) | self.B
        self.A = (self.X >> 8) & 0xFF
        self.B = self.X & 0xFF
        self.X = d

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.X,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
  

    def sec(self, instr: Instruction) -> MemAccess:
        """Set Carry Flag (C = 1)"""
        self.flags.C = 1
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.flags.C,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    def clc(self, instr: Instruction) -> MemAccess:
        """Clear Carry Flag (C = 0)"""
        self.flags.C = 0
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.flags.C,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )

    
    @operand_needed
    def jmp(self, instr: Instruction) -> MemAccess:
        old_PC = self.PC
        self.PC = instr.target_value # type: ignore

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(old_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )

    @operand_needed
    def jsr(self, instr: Instruction) -> MemAccess:
        old_PC = self.PC
        ma = self.__read_value16(instr)

        if ma.target_addr is None:
            raise ValueError("Couldn't determine jumping address for jsr.")

        # Push return address onto stack
        ret = (self.PC + instr.size)
        if ret > 0xFFFF:
            raise ValueError("Jumping to instruction behind ROM!")
        self.push16(ret)

        # Some functions only get known during emulation as they use dynamic addresses
        # TODO sollte man sie hier mit fn_xxxx speichern und später noch ggfs umbenennen?
        #self.rom_config.add_function_address(TODO NAme ma.target_addr)

        self.PC = ma.target_addr
        ma.next_instr_addr = self.PC

        return ma

        if instr.target_type == OperandType.DIRECT:
            self.PC = instr.target_value
        # elif instr.target_type == OperandType.IMMEDIATE:
        #     addr = None
        #     val = instr.target_value & 0xFFFF
        elif instr.target_type == OperandType.INDIRECT:
            addr = (self.X + instr.target_value) & 0xFFFF
            self.PC = self.read16(addr)

        

        return MemAccess(
            instr=instr,
            target_addr=self.PC,
            var=self.rom_config.get_by_address(old_PC), # TODO in den adneren funktionen auch noch anpassen, oder=?
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=self.PC
        )

    

    def rts(self, instr: Instruction) -> MemAccess:
        new_PC = self.pull16()

        old_PC = self.PC
        self.PC = new_PC

        #if self._call_stack:
        #    self._call_stack.pop()

        # Check if we're on a top function, adjust return address for visualization
        if new_PC == 0xFFFF:
            new_PC = old_PC
           
        return MemAccess(
            instr=instr,
            target_addr=None,
            var=self.rom_config.get_by_address(new_PC),
            value=None,
            rw='X',
            by=self.PC,
            next_instr_addr=new_PC
        )

    def sei(self, instr: Instruction) -> MemAccess:
        #logger.warning("Command sei has currently no effect!")
        self.flags.I = 1

        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.flags.I,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def tpa(self, instr: Instruction) -> MemAccess:
        # Transfer CCR (Flags) to A
        self.A = self.flags.to_byte()
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    
    def tap(self, instr: Instruction) -> MemAccess:
        # Transfer A to CCR (Flags)
        flags_byte = self.A
        self.flags.N = (flags_byte >> 7) & 1
        self.flags.V = (flags_byte >> 6) & 1
        self.flags.I = (flags_byte >> 4) & 1
        self.flags.Z = (flags_byte >> 2) & 1
        self.flags.C = flags_byte & 1
        old_PC = self.PC
        self.PC += instr.size

        return MemAccess(
            instr=instr,
            target_addr=None,
            var=None,
            value=self.A,
            rw='W',
            by=self.PC,
            next_instr_addr=self.PC
        )
    

