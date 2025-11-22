

from dataclasses import dataclass
from enum import IntEnum
import logging
from typing import Optional
import sympy as sp
from sympy.logic.boolalg import Boolean
from sympy.core.relational import Relational
from pyparsing import Callable
from analyzer_core.analyze.lookup_table_helper import LookupTable, LookupTableHelper
from analyzer_core.config.memory_map import MemoryRegion, RegionKind, RegionKind
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.disasm.capstone_wrap import OperandType
from analyzer_core.disasm.insn_model import Instruction
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.emu.tracing import MemAccess


class ParserError(Exception):
    pass


class TwoStepComplement(IntEnum):
    NONE = 0
    INVERT = 1  # ~ x
    INVERT_HI_BYTE = 2 # ~ on high byte only -> only supported if low byte will also be ~

class TwoStepDivide(IntEnum):
    NONE = 0
    ROUND_FOR_DIVIDATION = 1  # +5 before division for 8bit rounding

@dataclass
class SavedRegisters:
    A: int
    B: int
    D: int
    X: int
    SP: int
    PC: int

logger = logging.getLogger(__name__)


class CalcInstructionParser:

    def __init__(self, rom_cfg: RomConfig, emulator: Emulator6303, read_address: int):
        self.new_calc_address = None
        self.new_calc_register = None
        self.read_address = read_address

        self.emulator = emulator
        self.rom_cfg = rom_cfg

        # Buffer that is used by SSM for calculations or final printout
        self.hex_buffer = [
            self.rom_cfg.address_by_name("print_hex_buffer_0"),
            self.rom_cfg.address_by_name("print_hex_buffer_1"),
            self.rom_cfg.address_by_name("print_hex_buffer_2"),
        ]

        # Relevant addresses for calculation
        self.function_ptrs: dict[int, Callable[[Instruction, MemAccess], None]] = {
            rom_cfg.address_by_name("divide"): self._divide,
            rom_cfg.address_by_name("mul16bit"): self._mul16bit,
            #rom_cfg.address_by_name("print_lower_value"): lambda instr, access: None,

            # fn_copy_to_lower_screen_buffer: ggfs ergänzen, zum mocken, damit die Nachricht verschwindet, oder auch um die LUT zu verarbeiten. aktuell abx
        }

        # TODO Hardcoded auf eins zunächjst
        self.symbol = sp.Symbol("x1", real = True)
        #self.neg_flag_sym = sp.Symbol("neg_flag", integer=True)
        self.neg_flag_val = 0

        self.init_new_instruction()

    def init_new_instruction(self):
        self.raw_calculations: list[str] = []
        #self.conditions: list[list[str]] = []

        self.current_expr: sp.Expr = sp.Expr()
        self.last_tested_expr: Optional[sp.Expr] = None

        self.conditions: list[Relational] = []
        self.multi_step_complement: TwoStepComplement = TwoStepComplement.NONE
        self.multi_step_divide: TwoStepDivide = TwoStepDivide.NONE
        self.lut_address: int | None = None

        # Don't go into functions for now
        self.jsr_level = 0

        self.calc_register_involed = False # TODO aus den ganzen Dingern nen Datentyp machn?

        # If there are branches detected that depend on calculation values
        self.value_depended_branches = False

        self.saved_registers = SavedRegisters(
            A=0,
            B=0,
            D=0,
            X=0,
            SP=0,
            PC=0
        )
        self.last_instruction: Instruction | None = None

    def add_function_mocks(self):
        self.function_ptrs[ self.rom_cfg.address_by_name("print_lower_value") ] = lambda instr, access: None
    
    def __is_address_match(self, needle, haystack):
        if needle == haystack:
            return True
        if isinstance(haystack, (list, tuple)):
            return needle in haystack
        return False

    # --- Handler functions called from outside ---

    def do_step(self, instr: Instruction, access: MemAccess):

        # Skip return instructions
        if instr.is_return:
            self.jsr_level -= 1
            return
        
        if self.jsr_level > 0:
            return
        
        old_multi_step_calc = self.multi_step_complement

        try:
            func = getattr(self, instr.mnemonic)
            func(instr, access)
        except AttributeError: # For unknown functions
                raise ParserError(f"Unknown instruction: {instr.mnemonic} at address 0x{instr.address:04X}")
        
        # Did we add calculation steps but forgot about the multi step calculations?
        if old_multi_step_calc != TwoStepComplement.NONE and \
           old_multi_step_calc == self.multi_step_complement and \
           self.calc_register_involed:
            raise ParserError(f"Calculation step not handled for instruction {instr.mnemonic} at address 0x{instr.address:04X}")
        
        self.saved_registers = SavedRegisters(
            A=self.emulator.A,
            B=self.emulator.B,
            D=(self.emulator.A << 8)|( self.emulator.B ),
            X=self.emulator.X,
            SP=self.emulator.SP,
            PC=self.emulator.PC
        )
        self.last_instruction = instr

        #print(f"Current calculation: {self.calculations}", flush=True)
    
    def _check_for_rom_address(self, addr: int) -> bool:
        ''' Check if the given address is in a ROM or MAPPED_ROM region '''
        region = self.emulator.mem.region_for(addr)
        if region and (region.kind == RegionKind.ROM or region.kind == RegionKind.MAPPED_ROM):
            return True
        return False


    def set_target_from_var_to_register(self, instr: Instruction, register: str):
        if instr.target_value == self.read_address:
            self.new_calc_address = None
            self.new_calc_register = register
            self.calc_register_involed = True
            
            self.raw_calculations.append("x1") # TODO später noch mehre Variablen unterstützen
            self.current_expr = self.symbol

        elif self.new_calc_register == register:
            # TODO überschreibt
            logger.warning(f"Overwriting calculation register {register} at instruction 0x{instr.address:04X}")
            self.raw_calculations.append(str(instr.target_value))
            self.current_expr = sp.Integer(instr.target_value)

            self.calc_register_involed = True
        elif self.__is_address_match(instr.target_value, self.new_calc_address):
            self.new_calc_address = None
            self.new_calc_register = register
            self.calc_register_involed = True
        elif instr.target_type == OperandType.INDIRECT and self.new_calc_register == 'X':
            self.new_calc_address = None
            self.new_calc_register = register
            self.calc_register_involed = True

            # If we load indirect with X register (e.g. ldd 0, x), we should check if this is an address from the static ROM area.
            # In that case it's likely to be a lookup table access
            if instr.target_value is None:
                raise RuntimeError(f"Expected target for instruction {instr.mnemonic}")
            
            current_lut_address = self.saved_registers.X + instr.target_value
            if self.lut_address is not None and self.lut_expr is not None:
            
                # Check if we're still accessing ROM data -> then it's a LUT access
                if self._check_for_rom_address(current_lut_address):
                    self.add_set_lookup_table()
                else:
                    raise NotImplementedError("Expected LUT address, but accessed non-ROM area.")
            else:
                raise NotImplementedError("Indirect load with X register but no LUT address known.")

        else:
            self.calc_register_involed = False
    
    # TODO diese funktion sollte nicht jedes mal eine LUT erstellen, bei mehreren Durchläufen lädt er ja jedes Mal den Speicher neu!!
    def add_set_lookup_table(self):
        if self.lut_address is None or self.lut_expr is None:
            raise RuntimeError("Expected a defined LUT address and expression before adding a LUT")
    
        factor, index_var = self._extract_factor_and_index(self.lut_expr)
        
        table_name = LookupTableHelper.table_name(self.lut_address)
        if table_name in self.rom_cfg.lookup_tables:
            # LUT is already created (by a previous scaling or a previous, branch dependend run)
            lut = self.rom_cfg.lookup_tables[table_name]
        else:

            possible_idx_vals = self._get_possible_index_values(index_var)

            # We've got a lookup table, create a function for it
            lut = LookupTableHelper.create_get_lookup_table(
                self.emulator, 
                self.lut_address,
                item_size=factor,
                possible_index_values=possible_idx_vals) # TODO size noch dynamisch, wird immer 0,x genommen so
        
            print(f"Lookup table creation to address 0x{self.lut_address:04X} with index {self.current_expr}", flush=True)


            self.rom_cfg.lookup_tables[table_name] = lut

            # Also save the value to the known variables
            self.rom_cfg.add_lut(table_name, self.lut_address, factor * max(possible_idx_vals))

        self.raw_calculations.append(f"[{self.lut_expr}] -> LUT(addr=0x{self.lut_address:04X})")
        self.current_expr = lut(index_var)  # type: ignore
        #self.current_expr = sp.Symbol(f"{LUT.name}({index_var})")  # type: ignore

        self.lut_address = None
        self.lut_expr = None
        

    def set_target_from_register_to_var(self, instr: Instruction, register: str):
        if self.new_calc_register == register:
            self.new_calc_address = instr.target_value
            self.new_calc_register = None
            self.calc_register_involed = True
        elif self.__is_address_match(instr.target_value, self.new_calc_address):
            # In this case the original value would simply get overwritten
            # Happens on e.g. BARO.P 0x3375 IMPREZA96
            self.new_calc_address = instr.target_value
            self.new_calc_register = None
            self.calc_register_involed = True
            #self.calculations.clear()
            self.raw_calculations.append(str(self.saved_registers.D))
            self.current_expr = sp.Integer(self.saved_registers.D)
        else:
            self.calc_register_involed = False
    
    def branch_condition_met(self, instr: Instruction, access: MemAccess) -> bool:
        ''' Return if the current branch condition is met by checking the next instruction address '''
        if instr.is_branch:
            if instr.target_value == access.next_instr_addr:
                return True
            else:
                return False
        else:
            raise ParserError(f"Instruction at 0x{instr.address:04X} is not a branch instruction.")
    
    def _get_test_expression(self) -> Optional[sp.Expr]:
        if self.last_tested_expr is None:
            test_expr = self.current_expr
        else:
            test_expr = self.last_tested_expr
            self.last_tested_expr = None
        
        return test_expr


    
    # --- Functions for subroutines called in scaling functions ---

    def _divide(self, instr: Instruction, access: MemAccess):
        if self.new_calc_address in self.hex_buffer or self.new_calc_address == self.hex_buffer:
            '''or (
        isinstance(self.new_calc_address, (list, tuple))
        and any(addr in self.hex_buffer for addr in self.new_calc_address)
    )'''
            # Clean up the string so only "+5" remains (remove spaces before, after, and in between)
            if self.raw_calculations and self.raw_calculations[-1].replace(" ", "") == "+5":
                self.raw_calculations.pop()  # Remove the +5 before division, it's only for 8bit rounding  
            self.raw_calculations.append(f"/ {self.saved_registers.D}")

            # If we just added a +5 for rounding, remove it from the expression
            if self.multi_step_divide == TwoStepDivide.ROUND_FOR_DIVIDATION:
                self.current_expr = self.current_expr - 5  # type: ignore
                self.multi_step_divide = TwoStepDivide.NONE
            self.current_expr = self.current_expr / self.saved_registers.D # type: ignore
            
            self.new_calc_register = None
            self.new_calc_address = self.hex_buffer
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def _mul16bit(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "D" or self.new_calc_register == "B":
            self.raw_calculations.append(f" * {self.saved_registers.X}")
            self.current_expr = self.current_expr * self.saved_registers.X # type: ignore

            self.new_calc_register = None
            self.new_calc_address = self.hex_buffer
            self.calc_register_involed = True
        elif self.new_calc_register == "X":
            self.raw_calculations.append(f" * {self.saved_registers.D}")
            self.current_expr = self.current_expr * self.saved_registers.D # type: ignore

            self.new_calc_register = None
            self.new_calc_address = self.hex_buffer
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False


    # --- Instruction handlers ---

    def ldaa(self, instr: Instruction, access: MemAccess):
        self.set_target_from_var_to_register(instr, "A")

    def ldab(self, instr: Instruction, access: MemAccess):
        self.set_target_from_var_to_register(instr, "B")
    
    def ldd(self, instr: Instruction, access: MemAccess):
        self.set_target_from_var_to_register(instr, "D")
    
    def ldx(self, instr: Instruction, access: MemAccess):
        self.set_target_from_var_to_register(instr, "X")

    def staa(self, instr: Instruction, access: MemAccess):
        self.set_target_from_register_to_var(instr, "A")

    def stab(self, instr: Instruction, access: MemAccess):
        self.set_target_from_register_to_var(instr, "B")

    def std(self, instr: Instruction, access: MemAccess):
        self.set_target_from_register_to_var(instr, "D")
    
    def xgdx(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "D":
            self.new_calc_register = "X"
            self.calc_register_involed = True
        elif self.new_calc_register == "X":
            self.new_calc_register = "D"
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def addd(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "D":
            self.raw_calculations.append(f" + {instr.target_value}")

            if self.multi_step_complement == TwoStepComplement.INVERT and instr.target_value == 1:
                # If we had an invert before, we need to adjust the calculation
                # ~(x) + 1  == -x
                self.current_expr = -self.current_expr # type: ignore
                self.multi_step_complement = TwoStepComplement.NONE
            else:
                self.current_expr = self.current_expr + instr.target_value # type: ignore
                if instr.target_value == 5:
                    # If we just added one, reset any multi step calc
                    self.multi_step_divide = TwoStepDivide.ROUND_FOR_DIVIDATION

            self.calc_register_involed = True
        elif self.new_calc_register == "B":
            self.raw_calculations.append(f" + {instr.target_value}")
            self.current_expr = self.current_expr + instr.target_value # type: ignore

            self.new_calc_register = "D" # Now we take both registers -> D
            self.calc_register_involed = True
        elif self.new_calc_register == "A":
            raise NotImplementedError("addd handling for A register alone not implemented yet.")
        elif self.__is_address_match(instr.target_value, self.new_calc_address):
            # Additional check for Lookup table access
            if self._check_for_rom_address(self.saved_registers.D):
                self.lut_address = self.saved_registers.D
                self.lut_expr = self.current_expr

            self.raw_calculations.append(f" + {self.saved_registers.D}")
            self.current_expr = self.current_expr + self.saved_registers.D # type: ignore
                
            self.new_calc_register = "D"
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def subd(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "D":
            self.raw_calculations.append(f" - {instr.target_value}")
            self.current_expr = self.current_expr - instr.target_value # type: ignore

            self.calc_register_involed = True
        elif self.new_calc_register == "B":
            self.raw_calculations.append(f" - {instr.target_value}")
            self.current_expr = self.current_expr - instr.target_value # type: ignore
            self.new_calc_register = "D" # Now we take both registers -> D
            self.calc_register_involed = True
        elif self.new_calc_register == "A":
            raise NotImplementedError("subd handling for A register alone not implemented yet.")
        elif self.__is_address_match(instr.target_value, self.new_calc_address):
            self.raw_calculations.append(f" {self.saved_registers.D} - ")
            self.current_expr = self.saved_registers.D - self.current_expr # type: ignore

            self.new_calc_register = "D"
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def adca(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(f" + {instr.target_value} + {self.emulator.flags.C}")
            self.current_expr = self.current_expr + instr.target_value + self.emulator.flags.C # type: ignore
            
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def subb(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(f" - {instr.target_value}")
            self.current_expr = self.current_expr - instr.target_value # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def abx(self, instr: Instruction, access: MemAccess): # B+X->X

        if self.new_calc_register == "D":
            # We use the double register, but only use B here, only take the lower byte of D
            self.raw_calculations.append(" & 0xFF")

            print("TODO: only lower byte used")

            # From now on, only take B
            self.new_calc_register = "B"

        if self.new_calc_register == "B":
            # Do a check for a LUT based on abx
            # 0x2B92 @IMPREZA96 does ABX for a LUT, but doesn't load them, they only get copied to fn_copy_to_lower_screen_buffer 
            # TODO Prüfen, ob das immer so vernünftig ist
            if self._check_for_rom_address(self.emulator.X):
                self.lut_address = self.saved_registers.X
                self.lut_expr = self.current_expr

                self.add_set_lookup_table()
            
            self.new_calc_register = "X"
            self.calc_register_involed = True

            
    
    def anda(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(f" & {instr.target_value}")

            # & doesn't work with sympy Expr -> take modulo for masks
            if instr.target_value is None:
                raise ParserError("ANDA instruction without target value.")
            
            mask = instr.target_value
            if mask & (mask +1) == 0:
                # If mask is continuous 1s from LSB (e.g. 0x0F, 0x3F, 0xFF, 0x7FFF, etc), we can use modulo
                self.current_expr = self.current_expr % (mask +1) # type: ignore
            else:
                raise NotImplementedError("Non-continuous AND masks not implemented yet.")
            #self.current_expr = self.current_expr & instr.target_value # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def negb(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(" * -1")
            self.current_expr = self.current_expr * -1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def inc(self, instr: Instruction, access: MemAccess):
        if self.new_calc_address == instr.target_value:
            self.raw_calculations.append(" + 1")

            if self.multi_step_complement == TwoStepComplement.INVERT:
                # If we had an invert before, we need to adjust the calculation
                # ~(x) + 1  == -x
                self.current_expr = -self.current_expr # type: ignore
                self.multi_step_complement = TwoStepComplement.NONE
            else:
                self.current_expr = self.current_expr + 1 # type: ignore

            self.calc_register_involed = True
        elif self.rom_cfg.address_by_name('print_-_sign') == instr.target_value:
            self.neg_flag_val = 1
        else:
            self.calc_register_involed = False

    def mul(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(f" * {self.saved_registers.B}")
            self.current_expr = self.current_expr * self.saved_registers.B # type: ignore

            self.new_calc_register = "D"
            self.calc_register_involed = True
        elif self.new_calc_register == "B":
            self.raw_calculations.append(f" * {self.saved_registers.A}")
            self.current_expr = self.current_expr * self.saved_registers.A # type: ignore

            self.new_calc_register = "D"
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def coma(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append("~")

            
            #if self.multi_step_calc == TwoStepCalculation.INVERT_HI_BYTE:
            # Set to invert, hi byte doesn't matter to ask
            self.multi_step_complement = TwoStepComplement.INVERT
            self.calc_register_involed = True
        elif self.new_calc_register == "D":
            # TODO More a workaround for now
            self.raw_calculations.append("~(hi)")
            self.multi_step_complement = TwoStepComplement.INVERT_HI_BYTE

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def comb(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append("~")
            self.multi_step_complement = TwoStepComplement.INVERT

            self.calc_register_involed = True
        elif self.new_calc_register == "D":
            # Set to invert, hi byte doesn't matter to ask
            self.multi_step_complement = TwoStepComplement.INVERT
            # TODO More a workaround for now
            if self.raw_calculations[-1] == "~(hi)":
                self.raw_calculations[-1] = "~" # Just set as if both registers where inverted -> D
                self.calc_register_involed = True
            else:
                raise NotImplementedError("comb on D register not implemented completely, yet.")
        else:
            self.calc_register_involed = False
    
    def clr(self, instr: Instruction, access: MemAccess):
        if self.new_calc_address == instr.target_value:
            self.raw_calculations.append(" * 0")
            self.current_expr = self.current_expr * 0 # type: ignore
            
            self.calc_register_involed = True
        elif self.rom_cfg.address_by_name('print_-_sign') == instr.target_value:
            self.neg_flag_val = 0
        else:
            self.calc_register_involed = False

    def clra(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(" * 0")
            self.current_expr = self.current_expr * 0 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def clrb(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(" * 0")
            self.current_expr = self.current_expr * 0 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def cmpa(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            raise NotImplementedError("cmpa handling not implemented yet.")
        else:
            self.calc_register_involed = False
    
    def tst(self, instr: Instruction, access: MemAccess):
        if self.new_calc_address == instr.target_value:
            raise NotImplementedError("tst handling not implemented yet.")
        # TODO Hier auf print_-_sign adresse prüfen und die dann mit auf 0? oder x1? also ja wenn < 0... 
        elif self.rom_cfg.address_by_name('print_-_sign') == instr.target_value:
            # Check if the - sign was set -> another way to check for < 0 before
            self.raw_calculations.append("tst auf - zeichen")
            self.last_tested_expr = sp.Integer(self.neg_flag_val)
            self.calc_register_involed = True

        else:
            self.calc_register_involed = False
    
    def tsta(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.last_tested_expr = self.current_expr
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def beq(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if == 0")
                cond = sp.Eq(self._get_test_expression(), 0)
            else:
                self.raw_calculations.append(" if != 0")
                cond = sp.Ne(self._get_test_expression(), 0)
            self.conditions.append(cond)
    
    def bne(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if != 0")
                cond = sp.Ne(self._get_test_expression(), 0)
            else:
                self.raw_calculations.append(" if == 0")
                cond = sp.Eq(self._get_test_expression(), 0)
            self.conditions.append(cond)

    def bcc(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if >= 0")
                cond = sp.Ge(self._get_test_expression(), 0)
            else:
                self.raw_calculations.append(" if < 0")
                cond = sp.Lt(self._get_test_expression(), 0)
            self.conditions.append(cond)
            
            #self.conditions.append(self.calculations.copy())

    def bcs(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if < 0")
                cond = sp.Lt(self._get_test_expression(), 0)
            else:
                self.raw_calculations.append(" if >= 0")
                cond = sp.Ge(self._get_test_expression(), 0)
            self.conditions.append(cond)

    def bpl(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if >= 0")
                cond = sp.Ge(self._get_test_expression(), 0)
            else:
                self.raw_calculations.append(" if < 0")
                cond = sp.Lt(self._get_test_expression(), 0)
            self.conditions.append(cond)

    def bmi(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if < 0")
                cond = sp.Lt(self._get_test_expression(), 0)
            else:
                self.raw_calculations.append(" if >= 0")
                cond = sp.Ge(self._get_test_expression(), 0)
            self.conditions.append(cond)

    def bra(self, instr: Instruction, access: MemAccess):
        #self.set_branch_impact()
        #self.calculations.append(" if True")
        pass

    def jsr(self, instr: Instruction, access: MemAccess):
        if instr.target_value is None:
            raise ParserError(f"JSR instruction without target value at address 0x{instr.address:04X}")
        func = self.function_ptrs.get(instr.target_value, None)
        if func is not None:
            func(instr, access)
        else:
            logger.debug(f"Skipping JSR to 0x{instr.target_value:04X} at address 0x{instr.address:04X}")

        self.jsr_level += 1


    # --- Calculation helpers ---
    def solve_jump_conditions(self) -> set[int]:
        '''
        Solve the jump conditions collected during parsing
        '''
        solved_values = set()
        for cond in self.conditions:

            if cond == True:
                continue
            if cond == False:
                raise NotImplementedError("Condition is always false, no solution possible. TODO")
            # Versuche, die Gleichung nach self.symbol zu lösen
            eq = sp.Eq(cond.lhs, 0)
            # Sonderfall: Enthält die Gleichung eine LookupTable-Funktion?
            lut_funcs = [f for f in cond.lhs.atoms(sp.Function) if isinstance(f, LookupTable)]
            if lut_funcs:
                # Für jede gefundene LUT: Finde alle Indizes, für die LUT(index) == 0
                for lut in lut_funcs:
                    # Versuche, die Gleichung nach dem Argument der LUT zu lösen
                    arg = lut.args[0]
                    # Check for indiceis where LUT(arg) == rhs (usually 0)
                    indices = lut.func.preimage(eq.rhs)
                    for idx in indices:
                        # Falls arg == self.symbol, ist idx direkt ein Testwert
                        # Falls arg ein Ausdruck ist (z.B. 2*x1), löse nach self.symbol
                        if arg == self.symbol:
                            solved_values.add(sp.Integer(idx))
                        else:
                            # Löst z.B. 2*x1 == idx nach x1
                            sols = sp.solve(sp.Eq(arg, idx), self.symbol)
                            for s in sols:
                                if s.is_real and 0 <= s <= 255:
                                    solved_values.add(int(s))
            else:
                # Allgemeiner Fall: Löse die Gleichung nach self.symbol
                sols = sp.solve(eq, self.symbol)
                for s in sols:
                    if s.is_real and 0 <= s <= 255:
                        solved_values.add(int(s))
            # Optional: Teste Werte knapp unter/über der Grenze (z.B. für Ungleichungen)
            for s in list(solved_values):
                for off in (-1, +1):
                    val = int(max(0, min(255, s + off)))
                    solved_values.add(val)
     
        return solved_values
    
    
        
    def _extract_factor_and_index(self, expr: sp.Expr) -> tuple[int, sp.Basic]:
        if isinstance(expr, sp.Mul):
            factor = None
            index_var = None
            for arg in expr.args:
                if arg.is_Number:
                    factor = int(arg)
                else:
                    index_var = arg
            if factor is not None and index_var is not None:
                return factor, index_var
        if isinstance(expr, sp.Mod):
            return 1, expr
        # Fallback für x1
        vars = list(expr.free_symbols)
        if len(vars) == 1 and expr.is_Symbol:
            return 1, expr
        raise NotImplementedError("Could not extract item size and index variable from LUT expression.")

    def _get_possible_index_values(self, index_var: sp.Basic) -> list[int]:
        # Modulo (fully bit masked values): Mod(x1, N)
        if isinstance(index_var, sp.Mod):
            mod_val = index_var.args[1]
            if mod_val.is_Integer:
                return list(range(sp.Integer(mod_val)))
        # Symbol case: x1
        if index_var.is_Symbol:
            return list(range(256))  # 8 Bit
        # Otherwise unknown, return empty list
        return []
    
    def negate_current_expression(self):
        '''
        Negate the current expression
        '''
        if self.current_expr is not None:
            self.current_expr = -self.current_expr
    
    def calculate_decimal_places(self, decimal_places: int):
        if decimal_places > 0:
            self.raw_calculations.append(f" / {10 ** decimal_places}")
            self.current_expr = self.current_expr / (10 ** decimal_places) 

    def finalize_simplify_equations(self, eq_pieces: list[tuple[sp.Expr | None, Boolean]]) -> sp.Expr:
        # Remove duplicates with same condition
        eq_pieces = list(dict.fromkeys(eq_pieces))

        # Group by same expressions
        grouped: dict[sp.Expr | None, list[Boolean]] = {}
        for expr, cond in eq_pieces:
            grouped.setdefault(expr, []).append(cond)

        combined_equations: list[tuple[sp.Expr | None, Boolean]] = []
        #for expr, conds in grouped.items():
        for expr, conds in grouped.items():
            condition = sp.Or(*conds)
            simplified_condition = sp.simplify(condition, force=True)
            
            combined_equations.append((expr, simplified_condition))

        final_expr_subst = sp.Piecewise(*combined_equations)
        
        # Get Lookup table objects back if included
        return LookupTableHelper.reverse_substitute_lookup_tables(self.rom_cfg.lookup_tables, final_expr_subst)
            
