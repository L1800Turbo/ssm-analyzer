

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
from analyzer_core.config.ssm_model import RomIdTableEntry_512kb
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
    #NEGATE = 3  # - x

class TwoStepDivide(IntEnum):
    NONE = 0
    ROUND_FOR_DIVISION = 1     # +5 before division for 8bit rounding

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

    def __init__(self, rom_cfg: RomConfig, emulator: Emulator6303, read_addresses: list[int]):
        
        self.read_addresses = read_addresses

        self.emulator = emulator
        self.rom_cfg = rom_cfg

        # Buffer that is used by SSM for calculations or final printout
        self.hex_buffer = [
            self.rom_cfg.address_by_name("print_hex_buffer_0"),
            self.rom_cfg.address_by_name("print_hex_buffer_1"),
            self.rom_cfg.address_by_name("print_hex_buffer_2"),
            self.rom_cfg.address_by_name("print_hex_buffer_3"),
        ]

        # Addresses that notify the current scale function as dependend from RomID values
        self.dependend_romid_adresses = [
            self.rom_cfg.address_by_name("romid_0"),
            self.rom_cfg.address_by_name("romid_1"),
            self.rom_cfg.address_by_name("romid_2"),
            self.rom_cfg.address_by_name("current_romid_scaling_index"),
            self.rom_cfg.address_by_name("current_romid_label_index"),
            self.rom_cfg.address_by_name("current_romid_menuitems_index"),
            self.rom_cfg.address_by_name("current_romid_a"),
            self.rom_cfg.address_by_name("current_romid_b"),
            self.rom_cfg.address_by_name("current_romid_model_index"),
            self.rom_cfg.address_by_name("current_romid_flagcmd"),
        ]


        # Relevant addresses for calculation
        mock_function_names: dict[str, Callable[[MemAccess], None]] = {
            "divide": self._divide,
            "mul16bit": self._mul16bit,
            #rom_cfg.address_by_name("print_lower_value"): lambda instr, access: None,

            "copy_to_lower_screen_buffer": self._copy_to_lower_screen_buffer,
            "set_upper_screen_buffer": lambda access: None,
            "print_upper_screen": lambda access: None,
            "print_lower_value": lambda access: None,
            "print_sign": lambda access: None,
            "copy_to_lower_screen_buffer_unit": self._copy_to_lower_screen_buffer_unit,
            "save_count_rx_value_fifo": self._save_count_rx_value_fifo,
        }
        self.mock_function_ptrs: dict[int, Callable[[MemAccess], None]] = {}
        for fn_name, func in mock_function_names.items():
            addr_def = self.rom_cfg.get_by_name(fn_name)
            if addr_def is not None and addr_def.rom_address is not None:
                self.mock_function_ptrs[addr_def.rom_address] = func



        # TODO Hardcoded auf eins zunächjst
        self.symbol = sp.Symbol("x1", real = True)

        # How many lookup tables were found in all function runs
        self.found_luts : int = 0
        self.print_unit_called = False


        self.init_new_instruction()


    def init_new_instruction(self):        
        self.new_calc_address = None
        self.new_calc_register = None
        self.new_calc_register_pushed = None
        self.old_calc_register = None # TODO zunächst für bita SVX96

        self.romid_dependend_addresses: set[tuple[int,int]] = set()

        self.raw_calculations: list[str] = []

        self.current_expr: sp.Expr = sp.Expr()
        self.last_tested_expr: Optional[sp.Expr] = None
        self.last_tested_value: Optional[int] = None

        self.output_buffer_values: list[int] = []

        # If it's necessary to lock further calculation (e.g. after print_lower_screen_buffer)
        self._lock_calculation: bool = False

        self.conditions: list[Relational] = []
        self.multi_step_complement: TwoStepComplement = TwoStepComplement.NONE
        self.multi_step_divide: TwoStepDivide = TwoStepDivide.NONE
        self.multi_step_divide_counter: int = 0

        self.neg_flag_val = 0

        # Helpers for Lookup tables
        self.lut_access = LookupTableAccess()

        # Useful for Lookup tables
        self.possible_index_values: list[int] = []

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
        
        # If calculation is locked, skip further processing
        if self._lock_calculation:
            return
        
        old_multi_step_calc = self.multi_step_complement


        try:
            func = getattr(self, instr.mnemonic)
            func(access)
        except AttributeError: # For unknown functions
                raise ParserError(f"Unknown instruction: {instr.mnemonic} at address 0x{instr.address:04X}")
        
        # Did we add calculation steps but forgot about the multi step calculations?
        if old_multi_step_calc != TwoStepComplement.NONE and \
            old_multi_step_calc == self.multi_step_complement and \
            self.calc_register_involed:
                raise ParserError(f"Calculation step not handled for instruction {instr.mnemonic} at address 0x{instr.address:04X}")
        
        '''
            if old_multi_step_calc == TwoStepComplement.NEGATE:
                # No calculation register involved, but still an invert pending
                self.raw_calculations.append(f" - {self.current_expr} ")
                self.current_expr = -self.current_expr  # type: ignore
                self.multi_step_complement = TwoStepComplement.NONE
            elif '''

        # Did we have a rounding for a possible divition but no division happened?
        if self.multi_step_divide == TwoStepDivide.ROUND_FOR_DIVISION and self.calc_register_involed:
            self.multi_step_divide_counter += 1
            if self.multi_step_divide_counter >= 3:
                # Assume that the +5 addition was not meant for rounding before division
                self.multi_step_divide = TwoStepDivide.NONE
        
        
        self.saved_registers = SavedRegisters(
            A=self.emulator.A,
            B=self.emulator.B,
            D=(self.emulator.A << 8)|( self.emulator.B ),
            X=self.emulator.X,
            SP=self.emulator.SP,
            PC=self.emulator.PC
        )
        self.last_instruction = instr
    
    def _check_for_rom_address(self, addr: int) -> bool:
        ''' Check if the given address is in a ROM or MAPPED_ROM region '''
        region = self.emulator.mem.region_for(addr)
        if region and (region.kind == RegionKind.ROM or region.kind == RegionKind.MAPPED_ROM):
            return True
        return False
    
    def _get_symbolic_buffer_value(self) -> int:
        return sum(val * (2 ** (8 * i)) for i, val in enumerate(reversed(self.output_buffer_values)))
    
    def get_expression_or_buffer_value(self) -> sp.Expr | sp.Integer:
        '''
        Return the expression if there is still a variable involved or if it's a static lookup table, otherwise get the whole buffer
        '''
        if self.symbol in self.current_expr.free_symbols or isinstance(self.current_expr, LookupTable):
            return self.current_expr
        
        # No variable involved, no static lookup table, return buffer value
        return sp.Integer(self._get_symbolic_buffer_value())
        
        


    def set_target_from_var_to_register(self, access: MemAccess, register: str):
        # If we read from the read address like ssm_rx_byte_2, we initialize the calculation
        if access.instr.target_value in self.read_addresses:
            self.new_calc_address = None
            self.new_calc_register = register
            self.calc_register_involed = True

            # Position of the read address in the list, to create x1, x2, ...
            position = self.read_addresses.index(access.instr.target_value) + 1
            
            self.raw_calculations.append(f"x{position}")

            # TODO so noch nicht, der muss ja jetzt die position kennen
            # und: Wenn ein anderes Symbol drin ist, darf er nicht alles überschreiben
            self.current_expr = self.symbol
        
        elif access.instr.target_value in self.dependend_romid_adresses:
            self.romid_dependend_addresses.add((access.instr.target_value, self.emulator.mem.read(access.instr.target_value)))

        elif self.__is_register_match(self.new_calc_register, register):
            # On string based LUTs this happens quite often, so don't show a warning each time
            #logger.warning(f"Overwriting calculation register {register} at instruction 0x{access.instr.address:04X}")

            # Distinguish here more in detail
            if self.new_calc_register == "D" and register == "A":
                self.raw_calculations.append(f"new A {access.value} & {self.saved_registers.B} in D ")
                # TODO rightige Rechnung hier
                self.current_expr = (self.current_expr) + (sp.Integer(access.value) << 8)
                #self.current_expr = (self.current_expr % 256) + (sp.Integer(access.value) << 8)

            elif self.new_calc_register == "D" and register == "B":
                self.raw_calculations.append(f"New B {self.saved_registers.A} & {access.value}>>8 in D ")
                # TODO richtige Rechnung hier
                raise NotImplementedError("Overwriting D register with B not implemented yet.")
            else:
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
            # In that case it's likely to be a lookup table access
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
            # NOTE Skip warning about it, as it happens quite often in LUT accesses (mainly A/C units)
            #if self.lut_access.address_defined():
            #    logger.warning(f"Expected LUT address at 0x{access.instr.target_value:04X} at instruction 0x{access.instr.address:04X},"
            #                   f" but lut_address is already set to 0x{self.lut_access.get_lut_address():04X}. Overwriting.")
            
            self.lut_access.set_lut_address(access.instr.target_value)
            
            # But not our calc register
            self.calc_register_involed = False
        else:
            self.calc_register_involed = False

            # If this was an interesting register, but we're overwriting it with something else, clear it
            if self.new_calc_register == register:
                self.new_calc_register = None
    
    def add_set_lookup_table(self, factor = None, index_var=None) -> list[int]:
        if not self.lut_access.address_defined():
            raise RuntimeError("Expected a defined LUT address and expression before adding a LUT")
    
        # If we didn't set them manually, extract them from the expression
        if factor is None or index_var is None:
            factor, index_var = LookupTableHelper.extract_factor_and_index(self.symbol, self.current_expr, self.lut_access, factor)

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
        
            print(f"Lookup table creation to address 0x{self.lut_access.get_lut_address():04X} with index {index_var}", flush=True)

            self.rom_cfg.lookup_tables[table_name] = lut

            # Also save the value to the known variables
            self.rom_cfg.add_lut(table_name, self.lut_access.get_lut_address(), factor * max(possible_idx_vals), current_device=self.emulator._current_device)
            
        self.found_luts += 1

        # TODO lut_expr und index_var: ist das nicht doppelt?
        self.raw_calculations.append(f"[{self.lut_access.lut_expr}] -> LUT(addr=0x{self.lut_access.get_lut_address():04X})")
        self.current_expr = lut(index_var)  # type: ignore
        

        self.lut_access = LookupTableAccess()

        return possible_idx_vals
    


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
            # Generic case: solve eq for self.symbol
            eq = sp.Eq(cond.lhs, cond.rhs) # TODO War 0
            # Generic case: solve eq for self.symbol
            lut_funcs = [f for f in cond.lhs.atoms(sp.Function) if isinstance(f, LookupTable)]
            if lut_funcs:
                # For each found LUT: find all indices for which LUT(index) == 0
                for lut in lut_funcs:
                    # Try to get the argument of the LUT
                    arg = lut.args[0]
                    # Check for indices where LUT(arg) == rhs (usually 0)
                    indices = lut.func.preimage(eq.rhs)
                    for idx in indices:
                        # If arg == self.symbol, idx is directly a test value
                        # If arg is an expression (e.g. 2*x1), solve for self.symbol
                        if arg == self.symbol:
                            solved_values.add(sp.Integer(idx))
                        else:
                            # Solve e.g. 2*x1 == idx to x1
                            sols = sp.solve(sp.Eq(arg, idx), self.symbol)
                            for s in sols:
                                if s.is_real and 0 <= s <= 255:
                                    solved_values.add(int(s))
            else:
                # Generic case: solve eq for self.symbol
                sols = sp.solve(eq, self.symbol)
                for s in sols:
                    if s.is_real and 0 <= s <= 255:
                        solved_values.add(int(s))

            # Add neighboring values to account for rounding issues
            for s in list(solved_values):
                for off in (-1, +1):
                    val = int(max(0, min(255, s + off)))
                    solved_values.add(val)
     
        return solved_values
    
    def remove_unreachable_conditions(self, conditions: list) -> list:
        cleaned_conditions = conditions.copy()
        for cond in conditions:
            if isinstance(cond, sp.Ne):
                symbols = cond.free_symbols
                if len(symbols) == 1:
                    eq = sp.Eq(cond.lhs, cond.rhs)
                    sols = sp.solve(eq, symbols.pop())
                    for sol in sols:
                        if not sol.is_integer:
                            cleaned_conditions.remove(cond)
                            #logger.debug(f"Removed non-integer condition {cond} from scaling function analysis. As it's a non integer value that never can be solved.")
                else:
                    raise NotImplementedError(f"Condition with multiple free symbols not supported: {cond}")
        return cleaned_conditions

    def _get_possible_index_values(self, index_var: sp.Basic) -> list[int]:
        # Modulo (fully bit masked values): Mod(x1, N)
        if isinstance(index_var, sp.Mod):
            mod_val = index_var.args[1]
            if mod_val.is_Integer:
                return list(range(sp.Integer(mod_val)))
        # Symbol case: x1
        elif index_var.is_Symbol:
            # Check if we got a single relational condition (e.g. x1 <= N)
            if len(self.conditions) == 1 and isinstance(self.conditions[0], Relational):
                rel:Relational = self.conditions[0]
                # Only handle x1 <= N and x1 < N
                if isinstance(rel, sp.Le) and rel.lhs.is_Symbol and rel.rhs.is_Integer:
                    return list(range(sp.Integer(sp.Integer(rel.rhs) + 1)))
                elif isinstance(rel, sp.Lt) and rel.lhs.is_Symbol and rel.rhs.is_Integer:
                    return list(range(sp.Integer(rel.rhs)))
            #else:
            #    raise NotImplementedError(f"Only <= and < inequalities with symbol on lhs and integer on rhs are supported: {index_var}")
            return list(range(256))  # 8 Bit
        
        elif index_var.is_Integer:
            assert isinstance(index_var, sp.Integer)
            return [int(index_var)]
        
        # Otherwise unknown
        raise NotImplementedError(f"Couldn't create index values out of {index_var}")
    
    def negate_current_expression_if_negative(self):
        '''
        Negate the current expression if it is negative

        Must not check on 'print_-_sign' flag, this one will get cleaned on 0 values before!
        '''
        return # TODO Test
        if self.current_expr is not None and self.neg_flag_val == 1:
            self.current_expr = -self.current_expr
    

    def calculate_decimal_places(self, decimal_places: int):
        if decimal_places > 0:
            self.raw_calculations.append(f" / {10 ** decimal_places}")
            self.current_expr = self.current_expr / (10 ** decimal_places) 
    
    @staticmethod
    def _fast_simplify_condition(cond: sp.Expr | sp.And) -> sp.Expr:
        if not isinstance(cond, sp.And):
            return cond

        eq_val = None
        new_args = []

        for arg in cond.args:
            if isinstance(arg, sp.Equality):
                if eq_val is None:
                    eq_val = arg.rhs
                    new_args.append(arg)
                else:
                    # Eq(x, a) & Eq(x, b)
                    return sp.false if arg.rhs != eq_val else arg # type: ignore
            elif isinstance(arg, sp.Unequality):
                if eq_val is not None:
                    if arg.rhs == eq_val:
                        return sp.false
                    # Ne(x, b) ist redundant
                else:
                    new_args.append(arg)
            else:
                new_args.append(arg)

        if eq_val is not None:
            return sp.Eq(cond.args[0].lhs, eq_val) # type: ignore

        return sp.And(*new_args) # type: ignore



    def finalize_simplify_equations(self, eq_pieces: list[tuple[sp.Expr | None, Boolean]]) -> sp.Expr:
        # Remove duplicates with same condition
        eq_pieces = list(dict.fromkeys(eq_pieces))

        # Group by same expressions
        grouped: dict[sp.Expr | None, list[Boolean]] = {}
        for expr, cond in eq_pieces:
            grouped.setdefault(expr, []).append(cond)

        combined_equations: list[tuple[sp.Expr | None, sp.Expr]] = []
        #for expr, conds in grouped.items():
        for expr, conds in grouped.items():
            symplified_conds = []
            for cond in conds:
                if isinstance(cond, sp.And) and all(isinstance(arg, sp.Ne) for arg in cond.args):
                    symplified_conds.append(self._fast_simplify_condition(cond))
                else:
                   symplified_conds.append(sp.simplify(self._fast_simplify_condition(cond))) # TODO funktioniert nicht bei SVX96 AC 0x2566
                #symplified_conds.append(sp.simplify(cond)) # type: ignore
            condition = sp.Or(*symplified_conds)
            #simplified_condition = sp.simplify(condition, force=True)
            simplified_condition = self._fast_simplify_condition(condition) # type: ignore
            #simplified_condition = sp.simplify_logic(condition)

            # Speedup: general simplify is quite slow, so skip it for Ne
            if not(
                isinstance(simplified_condition, sp.Ne) or
                (isinstance(simplified_condition, sp.And) and all(isinstance(arg, sp.Ne) for arg in simplified_condition.args))
            ):
                simplified_condition = sp.simplify(simplified_condition) # type: ignore
            
            if expr is not None:
                expr = sp.sympify(expr.replace(
                    lambda e:isinstance(e, sp.Mod) and e.args[1] == 256,
                    lambda e: e.args[0]
                ))

            combined_equations.append((expr, simplified_condition))
        
        combined_equations = self._sort_combined_equations(combined_equations)

        final_expr_subst = sp.Piecewise(*combined_equations)
        
        # Get Lookup table objects back if included
        return LookupTableHelper.reverse_substitute_lookup_tables(self.rom_cfg.lookup_tables, final_expr_subst, {str(self.symbol): self.symbol}) # type: ignore
    

    def _condition_priority(self, cond: sp.Expr) -> int:
        """
        Get priority of a condition for sorting.
        Lower values have higher priority.
        Priorities:
        0: Eq(...)
        1: <, <=, >, >=
        2: other relational conditions (Or/And/Not/Xor/Relational unknown)
        3: Ne(...), True
        4: False (at the very end)
        """
        # "hard" true false cases
        if cond is sp.false or cond is False:
            return 5
        if cond is sp.true or cond is True:
            return 4

        # Simgle relational conditions:
        if isinstance(cond, sp.Eq):
            return 0
        if isinstance(cond, (sp.Lt, sp.Le, sp.Gt, sp.Ge)):
            return 1
        if isinstance(cond, sp.Ne):
            return 3

        # For compound conditions, try to find the lowest priority among contained relations
        if isinstance(cond, Boolean):
            # Try to get lowest priority among contained relations
            priorities = []
            for atom in cond.atoms(Relational):
                if isinstance(atom, sp.Eq):
                    priorities.append(0)
                elif isinstance(atom, (sp.Lt, sp.Le, sp.Gt, sp.Ge)):
                    # Add one point more towards lower priority: multiple relational conditions are usually the default condition
                    priorities.append(2)
                elif isinstance(atom, sp.Ne):
                    priorities.append(3)
                else:
                    priorities.append(2)
            if priorities:
                return min(priorities)

        return 2
    

    def _sort_combined_equations(self, combined_equations: list[tuple[sp.Expr | None, sp.Expr]]) \
            -> list[tuple[sp.Expr | None, sp.Expr]]:
        """
        Sort (expr, cond) by cond according to condition_priority.
        """
        def key(item):
            expr, cond = item
            # Tie-breaker: srepr(cond) ensures stable order within the same priority
            return (self._condition_priority(cond), sp.srepr(cond))
        return sorted(combined_equations, key=key)
    



    def set_target_from_register_to_var(self, access: MemAccess, register: str):
        if self.__is_register_match(self.new_calc_register, register):
            self.new_calc_address = access.instr.target_value
            # TODO: Als test, der Wert bleibt ja im Accu, aber wird nicht zwangsläufig weiterverwendet
            self.old_calc_register = self.new_calc_register
            self.new_calc_register = None
            self.calc_register_involed = True
        elif self.__is_address_match(access.instr.target_value, self.new_calc_address):
            # In this case the original value would simply get overwritten
            # Happens on e.g. BARO.P 0x3375 IMPREZA96
            self.new_calc_address = access.instr.target_value
            self.new_calc_register = None
            self.calc_register_involed = True
            
            self.raw_calculations.append(str(self.saved_registers.D))
            self.current_expr = sp.Integer(self.saved_registers.D)
        else:
            self.calc_register_involed = False

        # If we write directly to the output buffer
        if access.instr.target_value in self.hex_buffer:

            #save_expr_okay = False

            # First, get all buffer values out of memory
            buffer_values = []
            for addr in self.hex_buffer:
                val = self.emulator.mem.read(addr)
                buffer_values.append(val)

            # Secondly, check if the target address (an actual calculation output) is in the buffer
            if self.new_calc_address in self.hex_buffer:
                buffer_idx = self.hex_buffer.index(self.new_calc_address)
                buffer_values[buffer_idx] = self.current_expr

            self.output_buffer_values = buffer_values

            self.raw_calculations.append(f"Symbolic buffer value: {self._get_symbolic_buffer_value()}")

            self.calc_register_involed = True
    
    def _branch_condition_met(self, access: MemAccess) -> bool:
        ''' Return if the current branch condition is met by checking the next instruction address '''
        if access.instr.is_branch:
            if access.instr.target_value == access.next_instr_addr:
                return True
            else:
                return False
        else:
            raise ParserError(f"Instruction at 0x{access.instr.address:04X} is not a branch instruction.")
    
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

    def _divide(self, access: MemAccess):
        if self.new_calc_address in self.hex_buffer or self.new_calc_address == self.hex_buffer:
            dividor = sp.Integer(self.saved_registers.D)

            # If we just added a +5 for rounding, remove it from the expression
            if self.multi_step_divide != TwoStepDivide.NONE:
                # TODO wird einfach ausgelassen -> Prüfen

                # Check how much rounding we need to remove
                remove_rounding = 5
                self.current_expr = self.current_expr - sp.Integer(5)

                const, terms = self.current_expr.as_coeff_add()
                if sp.Gt(const, 50) and dividor % 100 == 0:
                    # If we divide by 100, the +5 rounding is actually +50 in the final result
                    remove_rounding -= 50
                    self.current_expr = self.current_expr - sp.Integer(50)
                
                const, terms = self.current_expr.as_coeff_add()
                if sp.Gt(const, 500) and dividor % 1000 == 0:
                    # If we divide by 1000, the +5 rounding is actually +500 in the final result
                    remove_rounding -= 500
                    self.current_expr = self.current_expr - sp.Integer(500)

                self.raw_calculations.append(f"-{remove_rounding} (rounding removal)")
                self.multi_step_divide = TwoStepDivide.NONE

            self.current_expr = self.current_expr / dividor # type: ignore
            self.raw_calculations.append(f"/ {dividor}")
            
            self.new_calc_register = None
            self.new_calc_address = self.hex_buffer
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def _mul16bit(self, access: MemAccess):
        if (self.new_calc_register == "D" or self.new_calc_register == "B") or \
            (self.new_calc_address in self.hex_buffer and self.old_calc_register in ("D", "B")): # Workaround for SVX96 AC 0x2639: gets written to buffer, but not used really..
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

    def _copy_to_lower_screen_buffer(self, access: MemAccess):
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
        
        # At this point, we wrote a LUT to the screen and further calculation expressions could be disturbing.
        # E.g. IMPREZA96 TCS @ 0x37C0: Error codes get written like a scaling with LUT access, but afterwards,
        # The hex value of the error code gets printed to the upper screeen (jsr index_to_ascii -> std ssm_display_y0_x7)
        # -> Lock further calculations to avoid these
        self._lock_calculation = True

        # TODO: DAs reicht so nicht -> Der Fehlercode von TCS wird in HEX ausgegeben, ist aber nicht im Text enthalten, den müsste man also 
        # abhängig von index_to_ascii nochmal extra behandeln. Evtl. die Funktion dann mocken
    
    def _copy_to_lower_screen_buffer_unit(self, access: MemAccess):
        # Only indicate that we wrote to the screen buffer
        self.print_unit_called = True

    def _save_count_rx_value_fifo(self, access: MemAccess):
        # We called this function that saves the RX value to a FIFO buffer,
        # so we need to adjust the SSM rx byte to a buffered variable
        self.read_addresses = [self.rom_cfg.address_by_name("buffered_ssm_rx_byte_2")]
        self.raw_calculations.append(f"Using buffered SSM RX byte from address {self.read_addresses[0]} for further calculations.")

        # Simulate clear the RX FIFO flag to let the function always run for the first time.
        # In that case, it doesn't set a busy flag and the scaling function can proceed.
        self.emulator.mem.write(self.rom_cfg.address_by_name("CC_flag_clear_RX_FIFO"), 0)
        


    # --- Instruction handlers ---

    def psha(self, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(f" PSHA {access.value}")
            self.new_calc_register_pushed = "A"
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def pula(self, access: MemAccess):
        if self.new_calc_register_pushed == "A":
            self.raw_calculations.append(f" PULA {access.value}")
            self.new_calc_register = "A"
            self.new_calc_register_pushed = None
            self.calc_register_involed = True

    def ldaa(self, access: MemAccess):
        self.set_target_from_var_to_register(access, "A")

    def ldab(self, access: MemAccess):
        self.set_target_from_var_to_register(access, "B")
    
    def ldd(self, access: MemAccess):
        self.set_target_from_var_to_register(access, "D")
    
    def ldx(self, access: MemAccess):
        self.lut_access.set_x_reg_modified()
        self.set_target_from_var_to_register(access, "X")

    def staa(self, access: MemAccess):
        self.set_target_from_register_to_var(access, "A")

    def stab(self, access: MemAccess):
        self.set_target_from_register_to_var(access, "B")

    def std(self, access: MemAccess):
        self.set_target_from_register_to_var(access, "D")
    
    def stx(self, access: MemAccess):
        self.lut_access.set_x_reg_modified()
        self.set_target_from_register_to_var(access, "X")
    
    def xgdx(self, access: MemAccess):
        self.lut_access.set_x_reg_modified(d_and_x_mixed=True)

        if self.new_calc_register == "D":
            self.new_calc_register = "X"
            self.calc_register_involed = True
        elif self.new_calc_register == "X":
            self.new_calc_register = "D"
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
            self.new_calc_register = None
    
    def addb(self, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(f" + {access.instr.target_value}")
            self.current_expr = self.current_expr + sp.Integer(access.instr.target_value)
            
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def addd(self, access: MemAccess):

        def check_for_division_rounding(target_value: int):
            # Check if the target value is at least 5 for rounding before division,
            # then it will be subtracted again before division
            test_value = target_value - 5
            if test_value >= 0:
                self.multi_step_divide = TwoStepDivide.ROUND_FOR_DIVISION
                self.multi_step_divide_counter = 0


        if access.instr.target_value is None:
            raise ParserError(f"Expected target value for ADDD instruction at 0x{access.instr.address:04X}")

        if self.new_calc_register == "D":
            self.raw_calculations.append(f" + {access.instr.target_value}")
            if self.multi_step_complement == TwoStepComplement.INVERT and access.instr.target_value == 1:
                # If we had an invert before, we need to adjust the calculation
                self.raw_calculations.append(f" ... -({self.current_expr}) instead of +1 and inverting")
                # ~(x) + 1  == -x
                self.current_expr = -self.current_expr
                self.multi_step_complement = TwoStepComplement.NONE
            else:
                check_for_division_rounding(access.instr.target_value)
                
                self.current_expr = self.current_expr + sp.Integer(access.instr.target_value)

            self.calc_register_involed = True
        elif self.new_calc_register == "B":
            self.raw_calculations.append(f" + {access.instr.target_value}")
            self.current_expr = self.current_expr + sp.Integer(access.instr.target_value)

            self.new_calc_register = "D" # Now we take both registers -> D
            self.calc_register_involed = True
        elif self.new_calc_register == "A":
            raise NotImplementedError("addd handling for A register alone not implemented yet.")
        elif self.__is_address_match(access.instr.target_value, self.new_calc_address):
            # Additional check for Lookup table access
            if self._check_for_rom_address(self.saved_registers.D):
                self.lut_expr = self.current_expr
            else:
                # Otherwise it could be a division rounding +5
                check_for_division_rounding(self.saved_registers.D)

            self.raw_calculations.append(f" + {self.saved_registers.D}")
            self.current_expr = self.current_expr + sp.Integer(self.saved_registers.D)
                
            self.new_calc_register = "D"
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def subd(self, access: MemAccess):
        if self.new_calc_register == "D":
            if self.neg_flag_val == 1:
                # If we had a negate before, we need to adjust the calculation
                self.raw_calculations.append(f" Negate, substract and negate again")
                self.current_expr = -self.current_expr

            self.raw_calculations.append(f" - {access.instr.target_value}")
            self.current_expr = self.current_expr - sp.Integer(access.instr.target_value)

            if self.neg_flag_val == 1:
                self.current_expr = -self.current_expr

            self.calc_register_involed = True
        elif self.new_calc_register == "B":
            self.raw_calculations.append(f" - {access.instr.target_value}")
            self.current_expr = self.current_expr - sp.Integer(access.instr.target_value)
            self.new_calc_register = "D" # Now we take both registers -> D
            self.calc_register_involed = True
        elif self.new_calc_register == "A":
            raise NotImplementedError("subd handling for A register alone not implemented yet.")
        elif self.__is_address_match(access.instr.target_value, self.new_calc_address):
            if self.neg_flag_val == 1:
                # If we had a negate before, we need to adjust the calculation
                self.raw_calculations.append(f" Negate, substract and negate again")
                self.current_expr = -self.current_expr
            
            self.raw_calculations.append(f" {self.saved_registers.D} - new_calc_address pointer ")
            self.current_expr = sp.Integer(self.saved_registers.D) - self.current_expr

            if self.neg_flag_val == 1:
                self.current_expr = -self.current_expr

            self.new_calc_register = "D"
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def adca(self, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(f" + {access.instr.target_value} + {self.emulator.flags.C}")
            self.current_expr = self.current_expr + sp.Integer(access.instr.target_value) + sp.Integer(self.emulator.flags.C)
            
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def adcb(self, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(f" + {access.instr.target_value} + {self.emulator.flags.C}")
            self.current_expr = self.current_expr + sp.Integer(access.instr.target_value) + sp.Integer(self.emulator.flags.C)
            
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def subb(self, access: MemAccess):
        if self.new_calc_register == "B":
            # TODO Alle müssen so umgestellt werden, manchmal ist es der Inhalt der Variblen, nicht die Adresse selbst
            self.raw_calculations.append(f" - {access.value}")

            self.current_expr = self.current_expr - sp.Integer(access.value)

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def abx(self, access: MemAccess): # B+X->X
        self.lut_access.set_x_reg_modified()

        if self.new_calc_register == "D":
            # We use the double register, but only use B here, only take the lower byte of D
            self.raw_calculations.append(" & 0xFF (from abx)")

            # From now on, only take B
            self.new_calc_register = "B"

        if self.new_calc_register == "B":            
            self.new_calc_register = "X"
            self.calc_register_involed = True

            self.raw_calculations.append(f" + {self.saved_registers.X} (abx)")

            
    
    def anda(self, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(f" & {access.instr.target_value}")

            # & doesn't work with sympy Expr -> take modulo for masks
            if access.instr.target_value is None:
                raise ParserError("ANDA instruction without target value.")
            
            mask = access.instr.target_value
            if mask & (mask +1) == 0:
                # If mask is continuous 1s from LSB (e.g. 0x0F, 0x3F, 0xFF, 0x7FFF, etc), we can use modulo
                self.current_expr = self.current_expr % (mask +1) # type: ignore
            else:
                raise NotImplementedError("Non-continuous AND masks not implemented yet.")
            #self.current_expr = self.current_expr & instr.target_value # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def negb(self, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(" * -1")
            self.current_expr = self.current_expr * -1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def inc(self, access: MemAccess):
        if self.new_calc_address == access.instr.target_value:
            self.raw_calculations.append(" + 1")

            if self.multi_step_complement == TwoStepComplement.INVERT:
                # If we had an invert before, we need to adjust the calculation
                # ~(x) + 1  == -x

                self.raw_calculations.append(f" ... -{self.current_expr} instead of +1 and inverting")
                self.current_expr = -self.current_expr # type: ignore
                self.multi_step_complement = TwoStepComplement.NONE
            else:
                self.current_expr = self.current_expr + 1 # type: ignore

            self.calc_register_involed = True
        elif self.rom_cfg.address_by_name('print_-_sign') == access.instr.target_value:

            self.current_expr = -self.current_expr
                
            self.neg_flag_val = 1
            self.raw_calculations.append(" negate and set -sign flag")
            self.calc_register_involed = False
        else:
            self.calc_register_involed = False
    
    def inca(self, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(" + 1")
            self.current_expr = self.current_expr + 1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def incb(self, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(" + 1")
            self.current_expr = self.current_expr + 1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def inx(self, access: MemAccess):
        self.lut_access.set_x_reg_modified()

        if self.new_calc_register == "X":
            self.raw_calculations.append(" + 1")
            self.current_expr = self.current_expr + 1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def deca(self, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(" - 1")
            self.current_expr = self.current_expr - 1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def decb(self, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(" - 1")
            self.current_expr = self.current_expr - 1 # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def mul(self, access: MemAccess):
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
    
    def coma(self, access: MemAccess):
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
    
    def comb(self, access: MemAccess):
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
    
    def clr(self, access: MemAccess):
        if self.new_calc_address == access.instr.target_value:
            self.raw_calculations.append(" * 0")
            self.current_expr = self.current_expr * 0 # type: ignore
            
            self.calc_register_involed = True
        elif self.rom_cfg.address_by_name('print_-_sign') == access.instr.target_value:
            # NOTE: Only remove the flag for non-zero values
            # TODO der soll hier gucken, ob der aktuell errechnete Wert 0 ist oder nicht, aber wie?? 
            # prüfen ob der Wert aktuell in einem Register steht? Und wenn in einer Variable?
            current_value = None

            if self.new_calc_register is not None:
                current_value = getattr(self.saved_registers, self.new_calc_register)

            if current_value is not None and current_value == 0:
                self.raw_calculations.append(" - sign wird nicht gecleart/geändert, weil der aktuelle Wert 0 ist")
            # elif self.multi_step_complement == ThreeStepComplement.NEGATE:
            #     # If we had a negate before
            #     # -x -> x, so remove the negate
            #     self.multi_step_complement = ThreeStepComplement.NONE
            #     self.raw_calculations.append(" don't clr -sign flag (negate removal)")
            else:
                if self.neg_flag_val == 1:
                    self.raw_calculations.append(f" clr - sign and negate: -({self.current_expr})")

                    self.neg_flag_val = 0

                    # TODO Test
                    self.current_expr = -self.current_expr
                elif self.neg_flag_val == 0:
                    self.raw_calculations.append(" clr - sign, don't negate as - sign was not set")
                else:
                    raise NotImplementedError("neg_flag_val  > 1 not implemented yet.")
            self.calc_register_involed = False
        else:
            self.calc_register_involed = False

    def clra(self, access: MemAccess):
        if self.new_calc_register == "A":
            self.raw_calculations.append(" * 0")
            self.current_expr = self.current_expr * 0 # type: ignore

            self.calc_register_involed = True
        elif self.new_calc_register == "D":
            # TODO More a workaround for now
            self.raw_calculations.append(" * 0 (hi)")
            self.current_expr = (self.current_expr % 256)  # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def clrb(self, access: MemAccess):
        if self.new_calc_register == "B":
            self.raw_calculations.append(" * 0")
            self.current_expr = self.current_expr * 0 # type: ignore

            self.calc_register_involed = True
        elif self.new_calc_register == "D":
            # TODO More a workaround for now
            self.raw_calculations.append(" * 0 (lo)")
            self.current_expr = self.current_expr - (self.current_expr % 256)  # type: ignore

            self.calc_register_involed = True
        else:
            self.calc_register_involed = False
    
    def _compare(self, access: MemAccess, register: str):
        if self.__is_register_match(self.new_calc_register, register):
            self.last_tested_expr = self.current_expr

            # Take the actual value from memory
            self.last_tested_value = access.value
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def cmpa(self, access: MemAccess):
        self._compare(access, "A")
    
    def cmpb(self, access: MemAccess):
        self._compare(access, "B")
    
    def tst(self, access: MemAccess):
        if self.new_calc_address == access.instr.target_value:
            raise NotImplementedError("tst handling not implemented yet.")
        # TODO Hier auf print_-_sign adresse prüfen und die dann mit auf 0? oder x1? also ja wenn < 0... 
        elif self.rom_cfg.address_by_name('print_-_sign') == access.instr.target_value:
            # Check if the - sign was set -> another way to check for < 0 before
            self.raw_calculations.append("tst auf - zeichen")
            self.last_tested_expr = sp.Integer(self.neg_flag_val)
            self.calc_register_involed = True

        else:
            self.calc_register_involed = False
    
    def tsta(self, access: MemAccess):
        if self.new_calc_register == "A":
            self.last_tested_expr = self.current_expr
            self.calc_register_involed = True
        elif self.new_calc_register == "D":
            self.raw_calculations.append(" test hi byte of calc register D ")
            self.last_tested_expr = self.current_expr // 256 # type: ignore
            self.calc_register_involed = True
        else:
            self.calc_register_involed = False

    def bita(self, access: MemAccess):
        if self.new_calc_register == "A" or self.old_calc_register == "A":
            self.raw_calculations.append(f" & {access.instr.target_value} for bit test")
            
            assert self.current_expr is not None
            assert access.instr.target_value is not None
            self.last_tested_expr = sp.And(self.current_expr, access.instr.target_value) # type: ignore
            self.calc_register_involed = True

            # TODO Dirty hack for now, SVX96 @0x87BA: checked for bit, but afterwards a isn't relevant anymore
            # might also match on other cases
            #self.new_calc_register = None
        else:
            self.calc_register_involed = False

    def bitb(self, access: MemAccess):
        if self.new_calc_register == "B" or self.old_calc_register == "B":
            self.raw_calculations.append(f" & {access.instr.target_value} for bit test")
            
            assert self.current_expr is not None
            assert access.instr.target_value is not None
            self.last_tested_expr = sp.And(self.current_expr, access.instr.target_value) # type: ignore
            self.calc_register_involed = True

        else:
            self.calc_register_involed = False
    
    def beq(self, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self._branch_condition_met(access):
                self.raw_calculations.append(f" beq test met: {test_expression} == {test_value}")
                cond = sp.Eq(test_expression, test_value)
            else:
                self.raw_calculations.append(f" beq test not met: {test_expression} != {test_value}")
                cond = sp.Ne(test_expression, test_value)
            self.conditions.append(cond)
    
    def bne(self, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self._branch_condition_met(access):
                self.raw_calculations.append(f" bne test met: {test_expression} != {test_value}")
                cond = sp.Ne(test_expression, test_value)
            else:
                self.raw_calculations.append(f" bne test not met: {test_expression} == {test_value}")
                cond = sp.Eq(test_expression, test_value)
            self.conditions.append(cond)

    def bcc(self, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self._branch_condition_met(access):
                self.raw_calculations.append(f" bcc test met: {test_expression} >= {test_value}")
                cond = sp.Ge(test_expression, test_value)
            else:
                self.raw_calculations.append(f" bcc test not met: {test_expression} < {test_value}")
                cond = sp.Lt(test_expression, test_value)
            self.conditions.append(cond)
            
            #self.conditions.append(self.calculations.copy())

    def bcs(self, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self._branch_condition_met(access):
                self.raw_calculations.append(f" bcs test met: {test_expression} < {test_value}")
                cond = sp.Lt(test_expression, test_value)
            else:
                self.raw_calculations.append(f" bcs test not met: {test_expression} >= {test_value}")
                cond = sp.Ge(test_expression, test_value)
            self.conditions.append(cond)

    def bpl(self, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self._branch_condition_met(access):
                self.raw_calculations.append(f" bpl test is '{test_expression}' >= {test_value}")
                cond = sp.Ge(test_expression, test_value)
            else:
                self.raw_calculations.append(f" bpl test is '{test_expression}' < {test_value}")
                cond = sp.Lt(test_expression, test_value)
            self.conditions.append(cond)

    def bmi(self, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self._branch_condition_met(access):
                self.raw_calculations.append(f" bmi test met: {test_expression} < {test_value}")
                cond = sp.Lt(test_expression, test_value)
            else:
                self.raw_calculations.append(f" bmi test not met: {test_expression} >= {test_value}")
                cond = sp.Ge(test_expression, test_value)
            self.conditions.append(cond)

    def bge(self, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self._branch_condition_met(access):
                self.raw_calculations.append(f" bge test met: {test_expression} >= {test_value}")
                cond = sp.Ge(test_expression, test_value)
            else:
                self.raw_calculations.append(f" bge test not met: {test_expression} < {test_value}")
                cond = sp.Lt(test_expression, test_value)
            self.conditions.append(cond)
    
    def bls(self, access: MemAccess):
        if self.calc_register_involed:
            self.value_depended_branches = True
            test_value = self._get_reset_test_value()
            test_expression = self._get_reset_test_expression()
            if self._branch_condition_met(access):
                self.raw_calculations.append(f" bls test met: {test_expression} <= {test_value}")
                cond = sp.Le(test_expression, test_value)
            else:
                self.raw_calculations.append(f" bls test not met: {test_expression} > {test_value}")
                cond = sp.Gt(test_expression, test_value)
            self.conditions.append(cond)

    def bra(self, access: MemAccess):
        pass

    def jmp(self, access: MemAccess):
        ''' Jump instruction, simply skip '''
        pass

    def jsr(self, access: MemAccess):
        if access.instr.target_value is None:
            raise ParserError(f"JSR instruction without target value at address 0x{access.instr.address:04X}")
        func = self.mock_function_ptrs.get(access.instr.target_value, None)
        if func is not None:
            func(access)
        else:
            func_name = self.rom_cfg.get_by_address(access.instr.target_value)
            if func_name is not None:
                func_name = f" [{func_name.name}]"
            else:
                func_name = ""
            logger.info(f"Skipping JSR to 0x{access.instr.target_value:04X}{func_name} at address 0x{access.instr.address:04X}")

        self.jsr_level += 1



            
