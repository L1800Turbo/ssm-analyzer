

from dataclasses import dataclass
from enum import IntEnum
import logging
from typing import Optional
import sympy as sp
from sympy.logic.boolalg import Boolean
from sympy.core.relational import Relational
from pyparsing import Callable
from analyzer_core.analyze.lookup_table_helper import LookupTable, LookupTableAccess, LookupTableHelper
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
    ROUND_FOR_DIVIDATION = 1     # +5 before division for 8bit rounding

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

            rom_cfg.address_by_name("copy_to_lower_screen_buffer"): self._copy_to_lower_screen_buffer,

            # fn_copy_to_lower_screen_buffer: ggfs ergänzen, zum mocken, damit die Nachricht verschwindet, oder auch um die LUT zu verarbeiten. aktuell abx
        }

        # TODO Hardcoded auf eins zunächjst
        self.symbol = sp.Symbol("x1", real = True)
        #self.neg_flag_sym = sp.Symbol("neg_flag", integer=True)
        self.neg_flag_val = 0

        # How many lookup tables were found in all function runs
        self.found_luts : int = 0

        self.init_new_instruction()

    def init_new_instruction(self):
        self.raw_calculations: list[str] = []
        #self.conditions: list[list[str]] = []

        self.current_expr: sp.Expr = sp.Expr()
        self.last_tested_expr: Optional[sp.Expr] = None
        self.last_tested_value: Optional[int] = None

        self.conditions: list[Relational] = []
        self.multi_step_complement: TwoStepComplement = TwoStepComplement.NONE
        self.multi_step_divide: TwoStepDivide = TwoStepDivide.NONE


        # Helpers for Lookup tables
        self.lut_access = LookupTableAccess()

        # Useful for Lookup tables
        self.possible_index_values: list[int] = []
        
        
        #self.lut_address: Optional[int] = None
        #self.lut_x_flag_modified_after_set = False # To influence if the LUT expression is x1 or a fixed value
        #self.lut_expr: Optional[int] = None

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
    
    def __is_register_match(self, needle, haystack):
        if needle == haystack:
            return True
        if needle == "D" and haystack in ("A", "B"):
            return True
        if needle in ("A", "B") and haystack == "D":
            return True
        return False

    # --- Handler functions called from outside ---

    def do_step(self, instr: Instruction, access: MemAccess):

        # Skip return instructions
        if instr.is_return:
            self.jsr_level -= 1
            return
        
        if self.jsr_level > 0:
            # Only count up JSR levels, don't parse inside functions
            if instr.is_function_call:
                self.jsr_level += 1
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
        
        # if self.multi_step_divide == TwoStepDivide.PRE_ROUND_FOR_DIVIDATION:
        #     # We just added a +5 for rounding, now set the flag that it's used and needs to be evaluated in the next expression
        #     self.multi_step_divide = TwoStepDivide.ROUND_FOR_DIVIDATION
        # elif self.multi_step_divide == TwoStepDivide.ROUND_FOR_DIVIDATION:
        #     raise ParserError(f"Division step not handled for instruction {instr.mnemonic} at address 0x{instr.address:04X}")
        
        
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


    def set_target_from_var_to_register(self, access: MemAccess, register: str):
        # If we read from the read address like ssm_rx_byte_2, we initialize the calculation
        if access.instr.target_value == self.read_address:
            self.new_calc_address = None
            self.new_calc_register = register
            self.calc_register_involed = True
            
            self.raw_calculations.append("x1") # TODO später noch mehre Variablen unterstützen
            self.current_expr = self.symbol

        elif self.__is_register_match(self.new_calc_register, register):
            # On string based LUTs this happens quite often, so don't show a warning each time
            #logger.warning(f"Overwriting calculation register {register} at instruction 0x{access.instr.address:04X}")
            self.raw_calculations.append(str(access.value))
            self.current_expr = sp.Integer(access.value)

            self.calc_register_involed = True
        elif self.__is_address_match(access.instr.target_value, self.new_calc_address):
            self.new_calc_address = None
            self.new_calc_register = register
            self.calc_register_involed = True
        elif access.instr.target_type == OperandType.INDIRECT and self.new_calc_register == 'X':
            assert access.instr.target_value is not None

            self.new_calc_address = None
            self.new_calc_register = register
            self.calc_register_involed = True

            # If we load indirect with X register (e.g. ldd 0, x), we should check if this is an address from the static ROM area.
            # In that case it's likely to be a lookup table access TODO access.value dann??
            possible_lut_address = self.saved_registers.X + access.instr.target_value
            if self._check_for_rom_address(possible_lut_address):
                if self.lut_access.address_defined():
                    if self.lut_access.get_lut_ptr_modified():
                        self.lut_access.lut_expr = self.current_expr - sp.Integer(self.lut_access.get_lut_address())
                        # Define a lookup table and collect new possible index values
                        self.possible_index_values.extend(self.add_set_lookup_table())
                    else:
                        raise NotImplementedError("LUT address already defined but X register not modified and Load?")
                else:
                    raise NotImplementedError("LUT address with X register modified but no LUT address defined.")
            

        # Not for our variable relevant now, but possibly a LUT access
        elif access.instr.target_value and self._check_for_rom_address(access.instr.target_value):
            if self.lut_access.address_defined():
                logger.warning(f"Expected LUT address at 0x{access.instr.target_value:04X} at instruction 0x{access.instr.address:04X},"
                               f" but lut_address is already set to 0x{self.lut_access.get_lut_address():04X}. Overwriting.")
            
            self.lut_access.set_lut_address(access.instr.target_value)
            
            # But not our calc register
            self.calc_register_involed = False
        else:
            self.calc_register_involed = False
    
    # TODO diese funktion sollte nicht jedes mal eine LUT erstellen, bei mehreren Durchläufen lädt er ja jedes Mal den Speicher neu!!
    def add_set_lookup_table(self, factor = None, index_var=None) -> list[int]:
        if not self.lut_access.address_defined():
            raise RuntimeError("Expected a defined LUT address and expression before adding a LUT")
    
        # If we didn't set them manually, extract them from the expression
        if factor is None or index_var is None:
            factor, index_var = self._extract_factor_and_index(self.lut_access.lut_expr, factor)

        # Collect possible indexes, valid for THIS LUT only
        possible_idx_vals = self._get_possible_index_values(index_var)
        
        table_name = LookupTableHelper.table_name(self.lut_access.get_lut_address())
        if table_name in self.rom_cfg.lookup_tables:
            # LUT is already created (by a previous scaling or a previous, branch dependend run)
            lut = self.rom_cfg.lookup_tables[table_name]

            # Check if we got new possible index values
            LookupTableHelper.add_index_values(lut, possible_idx_vals, self.emulator)
        else:


            # We've got a lookup table, create a function for it
            lut = LookupTableHelper.create_get_lookup_table(
                self.emulator, 
                self.lut_access.get_lut_address(),
                item_size=factor,
                possible_index_values=possible_idx_vals) # TODO size noch dynamisch, wird immer 0,x genommen so
        
            print(f"Lookup table creation to address 0x{self.lut_access.get_lut_address():04X} with index {self.current_expr}", flush=True)

            self.rom_cfg.lookup_tables[table_name] = lut

            # Also save the value to the known variables
            self.rom_cfg.add_lut(table_name, self.lut_access.get_lut_address(), factor * max(possible_idx_vals))
            self.found_luts += 1

        self.raw_calculations.append(f"[{self.lut_access.lut_expr}] -> LUT(addr=0x{self.lut_access.get_lut_address():04X})")
        self.current_expr = lut(index_var)  # type: ignore
        #self.current_expr = sp.Symbol(f"{LUT.name}({index_var})")  # type: ignore

        self.lut_access = LookupTableAccess()

        return possible_idx_vals

    def set_target_from_register_to_var(self, instr: Instruction, register: str):
        if self.__is_register_match(self.new_calc_register, register):
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
    
    def _get_reset_test_expression(self) -> Optional[sp.Expr]:
        if self.last_tested_expr is None:
            test_expr = self.current_expr
        else:
            test_expr = self.last_tested_expr
            self.last_tested_expr = None
        
        return test_expr
    
    def _get_reset_test_value(self) -> Optional[int]:
        if self.last_tested_value is None:
            return 0
        else:
            val = self.last_tested_value
            self.last_tested_value = None
            return val


    
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
                # TODO wird einfach ausgelassen -> Prüfen
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

    def _copy_to_lower_screen_buffer(self, instr: Instruction, access: MemAccess):
        # If we might have a LUT address
        if self.lut_access.address_defined():
            #if not self.lut_access.class_defined(self.rom_cfg.lookup_tables):
            factor = None

            if self.lut_access.get_lut_ptr_modified() and self.current_expr != 0:
                # If there is no symbol, but modification, we assume a display out with factor 16 and this will be the index
                if not self.symbol in self.current_expr.free_symbols:
                    factor = 16
                self.lut_access.lut_expr = self.current_expr
                self.possible_index_values.extend(self.add_set_lookup_table(factor))
            else:
                self.possible_index_values.extend(self.add_set_lookup_table(16, sp.Integer(0)))

        # For safety reasons not to miss a LUT
        elif self._check_for_rom_address(self.saved_registers.X):
            raise NotImplementedError("Expected a defined lookup table")



            # TODO: Jetzt eine Abfrage, ob was mit der LUT gemacht wurde
            # -> ist X immer noch die LUT? nur auf gleiche Adresse reicht nicht, kann ja 0 sein und dann die gleiche Adresse sein
            # -> in den anderen Funktionen ggfs. ein Flag setzen: Wenn LUT-Adresse exisitert, dann Flag, wenn an X gebastelt wurde?
            # x_flag_modified_after_lut_set = False
            #------------------- abx
                        # TODO Prüfen, ob das immer so vernünftig ist -> ANpassen!
            # if self._check_for_rom_address(self.emulator.X):
            #     if self.lut_address is None:
            #         raise NotImplementedError("Expected LUT address at ABX instruction because of Rom address range, but none defined.")
            #     #self.lut_address = self.saved_registers.X
            #     self.lut_expr = self.current_expr

            #     self.add_set_lookup_table()
            #--------------------------
        
            # Check if we're still accessing ROM data -> then it's a LUT access
            #if self._check_for_rom_address(self.lut_access.get_lut_address()):
            #    self.add_set_lookup_table(16, self.lut_access.lut_expr)
            #else:
            #    raise NotImplementedError("Expected LUT address, but accessed non-ROM area.")
      


    # --- Instruction handlers ---

    def ldaa(self, instr: Instruction, access: MemAccess):
        self.set_target_from_var_to_register(access, "A")

    def ldab(self, instr: Instruction, access: MemAccess):
        self.set_target_from_var_to_register(access, "B")
    
    def ldd(self, instr: Instruction, access: MemAccess):
        self.set_target_from_var_to_register(access, "D")
    
    def ldx(self, instr: Instruction, access: MemAccess):
        self.lut_access.set_x_reg_modified()
        self.set_target_from_var_to_register(access, "X")

    def staa(self, instr: Instruction, access: MemAccess):
        self.set_target_from_register_to_var(instr, "A")

    def stab(self, instr: Instruction, access: MemAccess):
        self.set_target_from_register_to_var(instr, "B")

    def std(self, instr: Instruction, access: MemAccess):
        self.set_target_from_register_to_var(instr, "D")
    
    def xgdx(self, instr: Instruction, access: MemAccess):
        self.lut_access.set_x_reg_modified()

        if self.new_calc_register == "D":
            self.new_calc_register = "X"
            self.calc_register_involed = True
        elif self.new_calc_register == "X":
            self.new_calc_register = "D"
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def addd(self, instr: Instruction, access: MemAccess):

        def check_for_division_rounding(target_value: int):
            # Check if the target value is 5 for rounding before division
            # TODO nur wenn +5 für Rundung reicht nicht, kann ja auch eine 5 enthalten sein in einer Summe
            if target_value == 5:
                self.multi_step_divide = TwoStepDivide.ROUND_FOR_DIVIDATION

        if instr.target_value is None:
            raise ParserError(f"Expected target value for ADDD instruction at 0x{instr.address:04X}")

        if self.new_calc_register == "D":
            self.raw_calculations.append(f" + {instr.target_value}")

            if self.multi_step_complement == TwoStepComplement.INVERT and instr.target_value == 1:
                # If we had an invert before, we need to adjust the calculation
                # ~(x) + 1  == -x
                self.current_expr = -self.current_expr # type: ignore
                self.multi_step_complement = TwoStepComplement.NONE
            else:
                check_for_division_rounding(instr.target_value)
                
                self.current_expr = self.current_expr + instr.target_value # type: ignore

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
                #self.lut_address = self.saved_registers.D
                self.lut_expr = self.current_expr
            else:
                # Otherwise it could be a division rounding +5
                check_for_division_rounding(self.saved_registers.D)

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
        self.lut_access.set_x_reg_modified()

        if self.new_calc_register == "D":
            # We use the double register, but only use B here, only take the lower byte of D
            self.raw_calculations.append(" & 0xFF")

            print("TODO: only lower byte used")

            # From now on, only take B
            self.new_calc_register = "B"

        if self.new_calc_register == "B":
            # Do a check for a LUT based on abx
            # 0x2B92 @IMPREZA96 does ABX for a LUT, but doesn't load them, they only get copied to fn_copy_to_lower_screen_buffer 
            # TODO Prüfen, ob das immer so vernünftig ist -> ANpassen!
            # if self._check_for_rom_address(self.emulator.X):
            #     if self.lut_address is None:
            #         raise NotImplementedError("Expected LUT address at ABX instruction because of Rom address range, but none defined.")
            #     #self.lut_address = self.saved_registers.X
            #     self.lut_expr = self.current_expr

            #     self.add_set_lookup_table()
            
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
    
    def inca(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(" + 1")
            self.current_expr = self.current_expr + 1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def incb(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(" + 1")
            self.current_expr = self.current_expr + 1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def inx(self, instr: Instruction, access: MemAccess):
        self.lut_access.set_x_reg_modified()

        if self.new_calc_register == "X":
            self.raw_calculations.append(" + 1")
            self.current_expr = self.current_expr + 1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def deca(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(" - 1")
            self.current_expr = self.current_expr - 1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def decb(self, instr: Instruction, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(" - 1")
            self.current_expr = self.current_expr - 1 # type: ignore

            self.calc_register_involed = True
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
    
    def _compare(self, instr: Instruction, access: MemAccess, register: str):
        if self.__is_register_match(self.new_calc_register, register):
            #self.raw_calculations.append(f" ?= {instr.target_value}")
            self.last_tested_expr = self.current_expr
            # if instr.target_type == OperandType.INDIRECT:
            #     # If indirect, we need to take the value from memory
            #     #assert instr.target_value is not None
            #     mem_value = self.emulator.mem.read_byte(instr.target_value)
            #     self.last_tested_value = mem_value
            #self.last_tested_value = instr.target_value

            # Take the actual value from memory
            self.last_tested_value = access.value
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def cmpa(self, instr: Instruction, access: MemAccess):
        self._compare(instr, access, "A")
        # if self.new_calc_register == "A":
        #     #self.raw_calculations.append(f" ?= {instr.target_value}")
        #     self.last_tested_expr = self.current_expr
        #     self.last_tested_value = instr.target_value
        #     self.calc_register_involed = True
        # else:
        #     self.calc_register_involed = False
    
    def cmpb(self, instr: Instruction, access: MemAccess):
        self._compare(instr, access, "B")
        # if self.new_calc_register == "B":
        #     #self.raw_calculations.append(f" ?= {instr.target_value}")
        #     raise NotImplementedError("cmpb handling not implemented yet.")
        # else:
        #     self.calc_register_involed = False
    
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
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(f" if {test_expression} == {test_value}")
                cond = sp.Eq(test_expression, test_value)
            else:
                self.raw_calculations.append(f" if {test_expression} != {test_value}")
                cond = sp.Ne(test_expression, test_value)
            self.conditions.append(cond)
    
    def bne(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(f" if {test_expression} != {test_value}")
                cond = sp.Ne(test_expression, test_value)
            else:
                self.raw_calculations.append(f" if {test_expression} == {test_value}")
                cond = sp.Eq(test_expression, test_value)
            self.conditions.append(cond)

    def bcc(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(f" if {test_expression} >= {test_value}")
                cond = sp.Ge(test_expression, test_value)
            else:
                self.raw_calculations.append(f" if {test_expression} < {test_value}")
                cond = sp.Lt(test_expression, test_value)
            self.conditions.append(cond)
            
            #self.conditions.append(self.calculations.copy())

    def bcs(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(f" if {test_expression} < {test_value}")
                cond = sp.Lt(test_expression, test_value)
            else:
                self.raw_calculations.append(f" if {test_expression} >= {test_value}")
                cond = sp.Ge(test_expression, test_value)
            self.conditions.append(cond)

    def bpl(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(f" if {test_expression} >= {test_value}")
                cond = sp.Ge(test_expression, test_value)
            else:
                self.raw_calculations.append(f" if {test_expression} < {test_value}")
                cond = sp.Lt(test_expression, test_value)
            self.conditions.append(cond)

    def bmi(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(f" if {test_expression} < {test_value}")
                cond = sp.Lt(test_expression, test_value)
            else:
                self.raw_calculations.append(f" if {test_expression} >= {test_value}")
                cond = sp.Ge(test_expression, test_value)
            self.conditions.append(cond)

    def bge(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(f" if {test_expression} >= {test_value}")
                cond = sp.Ge(test_expression, test_value)
            else:
                self.raw_calculations.append(f" if {test_expression} < {test_value}")
                cond = sp.Lt(test_expression, test_value)
            self.conditions.append(cond)

    def bra(self, instr: Instruction, access: MemAccess):
        #self.set_branch_impact()
        #self.calculations.append(" if True")
        pass

    def jmp(self, instr: Instruction, access: MemAccess):
        ''' Jump instruction, simply skip '''
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
            eq = sp.Eq(cond.lhs, cond.rhs) # TODO War 0
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
    
    
        
    def _extract_factor_and_index(self, expr: sp.Expr, factor: Optional[int] = None) -> tuple[int, sp.Basic]:
        # If we got a factor delivered and there is no symbol, we use a fixed index, broken down by the factor
        if factor is not None and not self.symbol in self.current_expr.free_symbols:
            index_var = expr / sp.Integer(factor)
            return factor, index_var

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
        elif index_var.is_Symbol:
            return list(range(256))  # 8 Bit
        
        elif index_var.is_Integer:
            assert isinstance(index_var, sp.Integer)
            return [int(index_var)]
        
        # Otherwise unknown
        raise NotImplementedError(f"Couldn't create index values out of {index_var}")
    
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
            #simplified_condition = sp.simplify(condition, force=True)
            simplified_condition = sp.simplify(condition)
            
            combined_equations.append((expr, simplified_condition))
        
        combined_equations = self.sort_combined_equations(combined_equations)

        final_expr_subst = sp.Piecewise(*combined_equations)
        
        # Get Lookup table objects back if included
        return LookupTableHelper.reverse_substitute_lookup_tables(self.rom_cfg.lookup_tables, final_expr_subst)
    
    def get_index_values(self) -> list[int]:
        '''
        Get possible index values from the current LUT expression
        '''
        # TODO Passt so nicght, er gibt die Indizies aus, wie sie in der LUT stehen. Aber das sind nicht unbedingt die X1 SSM-Werte!
        if self.possible_index_values:
            return self.possible_index_values
        else:
            return list(range(256))
        
    
    # def sort_conditions(self, conditions: list[Relational]) -> list[Relational]:
    #     """
    #     Order conditions to get the True and ne conditions at the end
    #     """
    #     def condition_key(cond: Relational):
    #         if cond is sp.true:
    #             return 3
    #         elif cond.has(sp.Ne):
    #             return 2
    #         elif cond.has(sp.Eq):
    #             return 0
    #         else:
    #             return 1
        
    #     return sorted(conditions, key=condition_key)


    def condition_priority(self, cond: sp.Expr) -> int:
        """
        Liefert die Sortierpriorität für eine finale Bedingung (Boolean):
        0: Eq(...)
        1: <, <=, >, >=
        2: sonstige logische Formen (Or/And/Not/Xor/Relational unbekannt)
        3: Ne(...), True
        4: False (ganz ans Ende)
        """
        # harte Wahrheitswerte
        if cond is sp.false or cond is False:
            return 5
        if cond is sp.true or cond is True:
            return 4

        # einzelne Relationen
        if isinstance(cond, sp.Eq):
            return 0
        if isinstance(cond, (sp.Lt, sp.Le, sp.Gt, sp.Ge)):
            return 1
        if isinstance(cond, sp.Ne):
            return 3

        # Falls cond ein zusammengesetzter boolescher Ausdruck ist (Or/And/Not/Xor),
        # bewerte nach den enthaltenen Relationen:
        if isinstance(cond, Boolean):
            # Versuche die "stärkste" (niedrigste) Priorität innerhalb zu finden
            # z.B. Or(Eq(...), Ne(...)) => min(0, 3) => 0
            priorities = []
            for atom in cond.atoms(Relational):
                if isinstance(atom, sp.Eq):
                    priorities.append(0)
                elif isinstance(atom, (sp.Lt, sp.Le, sp.Gt, sp.Ge)):
                    priorities.append(1)
                elif isinstance(atom, sp.Ne):
                    priorities.append(3)
                else:
                    priorities.append(2)
            if priorities:
                return min(priorities)
            # keine Relationalen Atom-Bedingungen gefunden: "sonstige Logik"
            return 2

        # generische Relational (SymPy kann Relational liefern ohne spezifische Klasse)
        # if isinstance(cond, sp.Relational):
        #     t = type(cond)
        #     if t is Eq:
        #         return 0
        #     if t in (Lt, Le, Gt, Ge):
        #         return 1
        #     if t is Ne:
        #         return 3
        #     return 2

        # Fallback
        return 2
    

    def sort_combined_equations(self, combined_equations: list[tuple[sp.Expr | None, sp.Expr]]) \
            -> list[tuple[sp.Expr | None, sp.Expr]]:
        """
        Sortiert (expr, cond) nach cond gemäß condition_priority.
        """
        def key(item):
            expr, cond = item
            # Tie-breaker: srepr(cond) sorgt für stabile Ordnung innerhalb gleicher Priorität
            return (self.condition_priority(cond), sp.srepr(cond))
        return sorted(combined_equations, key=key)


            
