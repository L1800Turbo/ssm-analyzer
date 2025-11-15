

from dataclasses import dataclass
from enum import IntEnum
import logging
from typing import Optional
import sympy as sp
from sympy.logic.boolalg import Boolean
from sympy.core.relational import Relational
from pyparsing import Callable
from analyzer_core.config.rom_config import RomConfig
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
            rom_cfg.address_by_name("divide"): self.divide,
            rom_cfg.address_by_name("mul16bit"): self.mul16bit,
            #rom_cfg.address_by_name("print_lower_value"): lambda instr, access: None,
        }

        # TODO Hardcoded auf eins zunächjst
        self.symbol = sp.Symbol("x1")

        self.init_new_instruction()

    def init_new_instruction(self):
        self.raw_calculations: list[str] = []
        #self.conditions: list[list[str]] = []

        self.current_expr: Optional[sp.Expr] = None
        self.conditions: list[Relational] = []
        self.multi_step_complement: TwoStepComplement = TwoStepComplement.NONE
        self.multi_step_divide: TwoStepDivide = TwoStepDivide.NONE

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

        # hier noch was

        # TODO: Man braucht die PPrevious Register auch bevor diese Liste läuft? eigentlich nicht...?

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
        else:
            self.calc_register_involed = False

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

   # def set_branch_impact(self):
        # If in a previous step a register used in calculation changed, mark that branches depend on calculation values
     #   if self.calc_register_involed:
    #        self.value_depended_branches = True

        # TODO: Hier muss dann noch implementiert werden, welche funktion bis hier hin gilt? Oder für die jeweilige funktion wie bpl?
        # also wenn (xy) > 0 ?


    
    # --- Functions for subroutines called in scaling functions ---

    def divide(self, instr: Instruction, access: MemAccess):
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

    def mul16bit(self, instr: Instruction, access: MemAccess):
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
        else:
            self.calc_register_involed = False
    
    def beq(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if == 0")
                cond = sp.Eq(self.current_expr, 0)
            else:
                self.raw_calculations.append(" if != 0")
                cond = sp.Ne(self.current_expr, 0)
            self.conditions.append(cond)
    
    def bne(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if != 0")
                cond = sp.Ne(self.current_expr, 0)
            else:
                self.raw_calculations.append(" if == 0")
                cond = sp.Eq(self.current_expr, 0)
            self.conditions.append(cond)

    def bcc(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if >= 0")
                cond = sp.Ge(self.current_expr, 0)
            else:
                self.raw_calculations.append(" if < 0")
                cond = sp.Lt(self.current_expr, 0)
            self.conditions.append(cond)
            
            #self.conditions.append(self.calculations.copy())

    def bcs(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if < 0")
                cond = sp.Lt(self.current_expr, 0)
            else:
                self.raw_calculations.append(" if >= 0")
                cond = sp.Ge(self.current_expr, 0)
            self.conditions.append(cond)

    def bpl(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if >= 0")
                cond = sp.Ge(self.current_expr, 0)
            else:
                self.raw_calculations.append(" if < 0")
                cond = sp.Lt(self.current_expr, 0)
            self.conditions.append(cond)

    def bmi(self, instr: Instruction, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            if self.branch_condition_met(instr, access):
                self.raw_calculations.append(" if < 0")
                cond = sp.Lt(self.current_expr, 0)
            else:
                self.raw_calculations.append(" if >= 0")
                cond = sp.Ge(self.current_expr, 0)
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
            # Solve each condition with 0 to the symbol TODO zunächst nur ein Symbol x1
            eq = sp.Eq(cond.lhs, 0)
            sol = sp.solve(eq, self.symbol)
            #print(f"  Lösung Bedingung {cond}: {sol}", flush=True)

            # Some equations solve by <, some by <= and vise versa, so we test both sides of the solution
            for s in sol:
                for off in (-1, +1):
                    solved_values.add(int(max(0, min(255, s + off))))
        return solved_values