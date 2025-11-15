from dataclasses import dataclass
import logging
from typing import List, Optional

import sympy as sp
from sympy.logic.boolalg import And, Or, Boolean
from sympy.core.relational import Relational
from analyzer_core.analyze.instruction_parser import CalcInstructionParser
from analyzer_core.analyze.pattern_detector import PatternDetector
from analyzer_core.config.rom_config import RomConfig, RomScalingDefinition
from analyzer_core.config.ssm_model import CurrentSelectedDevice, MasterTableEntry, RomIdTableEntry_512kb
from analyzer_core.disasm.capstone_wrap import Disassembler630x, OperandType
from analyzer_core.disasm.insn_model import Instruction
from analyzer_core.emu.emulator_6303 import EmulationError, Emulator6303
from analyzer_core.emu.memory_manager import MemoryManager
from analyzer_core.emu.ssm_emu_helper import SsmEmuHelper
from analyzer_core.emu.tracing import MemAccess
from analyzer_core.ssm.action_functions.action_helper import SsmActionHelper

logger = logging.getLogger(__name__)



class SsmActionScalingFunction(SsmActionHelper):

    def __init__(self, 
            rom_cfg: RomConfig, 
            emulator: Emulator6303, 
            current_device: CurrentSelectedDevice, 
            romid_entry:RomIdTableEntry_512kb, 
            mt_entry: MasterTableEntry) -> None:
        super().__init__(rom_cfg, emulator)
        self.current_device = current_device
        self.romid_entry = romid_entry
        self.mt_entry = mt_entry

        self.data_scaling: Optional[sp.Expr] = None
        self.decimal_places: Optional[int] = None
        self.unit: Optional[str] = None
        self.value_sign: str = ""

        #self.caluclations_raw: dict[int, list] = {}

        logger.debug(f"Running Scaling Function for MT Entry {mt_entry.menu_item_str()} with scaling index {mt_entry.scaling_index}")

        self._ensure_scaling_disassembly()
        self._set_unit()

        self._add_function_mocks()
        self._init_instruction_parser()

        # Add function mocks where we need information from the disassembly as variable names could be unknown before
        ###self.instr_parser.add_function_mocks()

        self._emulate_receive_ssm_response()

    # TODO als Alternative nur den INdex nehmen und direkt aqus der Tabelle die Adresse holen?
    # Aber was wäre mit BARO.P usw?

    def _init_instruction_parser(self):
        self.instr_parser = CalcInstructionParser(self.rom_cfg, self.emulator, read_address=self.rom_cfg.address_by_name("ssm_rx_byte_2"))
        # Add function mocks where we need information from the disassembly as variable names could be unknown before
        self.instr_parser.add_function_mocks()


    def _ensure_scaling_disassembly(self):
        '''
        Do a disassembly of the scaling function table if not already done.
        '''
        if self.romid_entry.current_scale_fn_table_pointer is None:
            raise ValueError("No scaling function table pointer available in ROM ID entry.")

        scaling_fn_table_ptr = self.romid_entry.current_scale_fn_table_pointer + 2 * self.mt_entry.scaling_index
        self.scaling_fn_ptr = self.emulator.read16(scaling_fn_table_ptr)
        

        # TODO: Der muss das vom Memory lesen den Pointer, damit der Adressoffset passt!, aber nicht direkt, nur der Offset

        if self.scaling_fn_ptr not in self.rom_cfg.scaling_addresses: # TODO erst wird hier nur nach der scaling_Address geguckt, aber nirgednwo hinzugefügt
            disasm = Disassembler630x(mem=self.emulator.mem) # TODO Besser raussuchen? self.emulator.mem.rom_image.rom)
            disasm.disassemble_reachable(self.scaling_fn_ptr, self.rom_cfg.instructions, self.rom_cfg.call_tree)

            pattern_detector = PatternDetector(self.rom_cfg)
            
            # TODO Wird so noch nicht gehen? Der sucht ja ab instructions, aber nicht für das gesamte.. wobei er es finden sollte??
            pattern_detector.detect_patterns(self.rom_cfg.instructions, "scaling_function_pattern")
    
    def _add_function_mocks(self):
        '''
        Add necessary function mocks for the scaling functions
        '''

        def mock_skip(em: Emulator6303):
            # Just return from the function
            em.mock_return()

        self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_value"), mock_skip)

        # As soon as we read the SSM RX bytes in the scaling function, we log the tracing
        def hook_read_ssm_rx_bytes_in_scaling_fn(addr: int, value: int, mem: MemoryManager):
            logger.debug(f"hook_read_ssm_rx_bytes_in_scaling_fn at {addr:04X}")
            #self.emulator.add_logger("scaling_fn_ssm_rx_logger", lambda instr, access: logging.debug(f"[SCALING_FN] Read SSM RX Bytes: {instr.address:04X}"))
            self.emulator.add_logger("scaling_fn_ssm_rx_logger", self._trace_rx_value_calculation)

        def hook_pre_scaling_function(em: Emulator6303):
            logger.debug(f"hook_pre_scaling_function at {self.scaling_fn_ptr:04X}")
            self.emulator.hooks.add_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_2"), hook_read_ssm_rx_bytes_in_scaling_fn)
        
        def hook_post_scaling_function(em: Emulator6303, access):
            print(f"hook_post_scaling_function at {self.scaling_fn_ptr:04X}", flush=True)
            self.emulator.hooks.remove_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_2"), hook_read_ssm_rx_bytes_in_scaling_fn)
            self.emulator.remove_logger("scaling_fn_ssm_rx_logger")

        self.emulator.hooks.add_pre_hook(self.scaling_fn_ptr, hook_pre_scaling_function)
        self.emulator.hooks.add_post_hook(self.scaling_fn_ptr, hook_post_scaling_function)

        
        # TODO Noch mocken?
        # fn_fn_copy_to_lower_screen_buffer_unit -> wird ja eigentrlich schon manuell gemacht
    
    def _emulate_receive_ssm_response(self):
        # Emulate that a response has been received
        SsmEmuHelper.set_ssm_response_received_flag(self.rom_cfg, self.emulator)

        # Reset wait counter in main loop wich lets the scaling function run only every 4th time
        self.emulator.mem.write(self.rom_cfg.address_by_name("master_table_run_scaling_wait_counter"), 4)

    def run_function(self):
        """Emulate scaling function with multiple inputs to determine scaling."""

        if self.scaling_fn_ptr in self.rom_cfg.scaling_addresses:
            logger.debug(f"Scaling function at 0x{self.scaling_fn_ptr:04X} already known, skipping emulation.")
            if self.mt_entry.item_label:
                self.rom_cfg.scaling_addresses[self.scaling_fn_ptr].functions.append(self.mt_entry.item_label)
            return
        
        #sympy_x = sp.Symbol("x1")
        ssm_inputs: List[int] = [0]   # initial TX values to test
        seen_samples: set[int] = set()
        #per_input_expr: dict[int, sp.Expr] = {}

        eq_pieces: list[tuple[sp.Expr | None, Boolean]] = []

        #expressions: list = [] #sp.Expr
        #conditions: list[Boolean] = []

        #raw_zeugs: list[list[str]] = []

        while ssm_inputs:
            rx_test_value = ssm_inputs.pop(0)
            seen_samples.add(rx_test_value)

            # Reset Emulator/Parser
            self.emulator.mem.write(self.rom_cfg.address_by_name("ssm_rx_byte_2"), rx_test_value)
            self._emulate_receive_ssm_response()
            self._init_instruction_parser() #  TODO das neu initialiseren dann nicht mit fischem objekt sondern der init-funktiopn dadrin?

            # Run the emulation
            self.emulator.set_pc(self.rom_cfg.address_by_name("mastertable_run_scaling_fn"))
            self.emulator.run_function_end(
                abort_pc=self.rom_cfg.address_by_name("master_table_main_loop")
            )

            # After running, collect modified variables
            # TODO noch in die Klasse auslagern?
            decimal_places = self.emulator.mem.read(self.rom_cfg.address_by_name('decimal_places'))
            if decimal_places > 0:
                self.instr_parser.raw_calculations.append(f" / {10 ** decimal_places}")
                self.instr_parser.current_expr = self.instr_parser.current_expr / (10 ** decimal_places) 
            
            negative_sign = self.emulator.mem.read(self.rom_cfg.address_by_name('print_-_sign')) == 1
            if negative_sign == 1:
                self.instr_parser.current_expr = -self.instr_parser.current_expr # type: ignore
            

            print(f"{rx_test_value}  Expr: {self.instr_parser.current_expr}  guard: {sp.And(*self.instr_parser.conditions)}", flush=True)

            # Get jump conditions from guards to find new test inputs
            for value in self.instr_parser.solve_jump_conditions():
                if value not in seen_samples and value not in ssm_inputs:
                    ssm_inputs.append(value)
                    print(f"    Adding new test input value: {value}", flush=True)

            eq_pieces.append((self.instr_parser.current_expr, sp.And(*self.instr_parser.conditions)))

            # TODO eigener Datentyp? in den PArser?
            #expressions.append(self.instr_parser.current_expr)
            #conditions.append(sp.And(*self.instr_parser.conditions))

            #raw_zeugs.append(self.instr_parser.raw_calculations.copy())

        #pieces = [(expr, cond) for expr, cond in zip(expressions, conditions)]

        # Remove duplicates with same condition
        eq_pieces = list(dict.fromkeys(eq_pieces))

        # Group by same expressions
        grouped: dict[sp.Expr | None, list[Boolean]] = {}
        for expr, cond in eq_pieces:
            grouped.setdefault(expr, []).append(cond)

        combined_equations: list[tuple[sp.Expr | None, Boolean]] = []
        for expr, conds in grouped.items():
            condition = sp.Or(*conds)
            simplified_condition = sp.simplify(condition, force=True)
            
            combined_equations.append((expr, simplified_condition))

        final_expr = sp.Piecewise(*combined_equations)

        print(f"Final Scaling Expression: {final_expr}", flush=True)

        print("#########################################", flush=True)



            





        #     if self.data_scaling is None:
        #         raise EmulationError("Scaling function did not produce a scaling expression.")
            
        

        #     # If there were branches in the assembly depending on calculation values, another run might be needed
        #     if self.instr_parser.value_depended_branches:
        #         logger.debug("Detected value-dependent branch during emulation.")

        #         bounds = self._extract_piecewise_boundaries(self.data_scaling, sympy_x)
        #         news = []
        #         for b in bounds:
        #             for off in (-1, +1):
        #                 val = int(max(0, min(255, b + off)))
        #                 if val not in seen_samples and val not in ssm_inputs:
        #                     news.append(val)
        #                     seen_samples.add(val)
        #         if news:
        #             logger.debug(f"Discovered new boundary samples: {news}")
        #             ssm_inputs.extend(news)
        
        # # Get final scaling by combining all piecewise parts TODO hier unten ja schon mal gar nicht?
        # if self.decimal_places is None:
        #     raise EmulationError("Decimal places not determined after scaling function execution.")

        # print(f"Alle Scalings: {self.data_scaling}")
        # final_expr = self._flatten_piecewise(self.data_scaling)

        # self.rom_cfg.scaling_addresses[self.scaling_fn_ptr] = RomScalingDefinition(
        #     scaling=str(final_expr),
        #     precision_decimals=self.decimal_places,
        #     unit=self.unit,
        #     functions=[self.mt_entry.item_label] if self.mt_entry.item_label else [],
        # )

        # print(f"Alle Rechnungen: {self.caluclations_raw}")

        # if self.mt_entry.action is None:
        #     raise RuntimeError("MasterTableEntry action datatype not set before saving SCALING action results.")
        # self.mt_entry.action.scaling = self.rom_cfg.scaling_addresses[self.scaling_fn_ptr]

        # logger.debug(f"Completed scaling detection at 0x{self.scaling_fn_ptr:04X}: {final_expr}")



    def run_post_actions(self):
        # negative_sign = "-" if self.emulator.mem.read(self.rom_cfg.address_by_name('print_-_sign')) == 1 else ""
        # positive_sign = "+" if self.emulator.mem.read(self.rom_cfg.address_by_name('print_+_sign')) == 1 else ""
        # self.value_sign = f"{positive_sign}{negative_sign}"
        # self.decimal_places = self.emulator.mem.read(self.rom_cfg.address_by_name('decimal_places'))
        
        # if self.decimal_places > 0:
        #     self.instr_parser.raw_calculations.append(f" / {10 ** self.decimal_places}")
       
        
        #print(f"Vor clean (value-sign \"{self.value_sign}\"): {' '.join(self.instr_parser.raw_calculations)} )", flush=True)

        #expr = self._build_expr_from_tokens(self.value_sign, self.instr_parser.raw_calculations)
        #expr = sp.piecewise_fold(expr)
        #expr = sp.simplify(expr)
        #self.data_scaling = expr
        

        #print(f"Cleaned: {self.data_scaling}", flush=True)
        pass

    
    def _build_expr_from_tokens(self, sign: str, tokens: List[str]) -> sp.Expr:
        """
        Baut aus den vom InstructionParser gelieferten Tokens direkt einen SymPy-Ausdruck.
        - '+5', '-7', '*3', '/10' wirken algebraisch auf 'expr'
        - 'if <cmp>' schließt aktuellen Zweig (expr, cond) ab
        - Default-Arm wird automatisch angehängt
        - am Ende piecewise_fold + simplify
        """
        x = sp.symbols("x1")
        expr: Optional[sp.Expr] = None
        arms: list[sp.Tuple[sp.Expr, Boolean]] = []

        def to_relop(cond_raw: str, expr_for_cond: Optional[sp.Expr]) -> Relational:
            cs = cond_raw.strip()
            cs= cs.replace(" ", "")

            left_expr = expr_for_cond if expr_for_cond is not None else x

            if cs.startswith(">="):
                return sp.Ge(left_expr, int(cs[2:]))

            elif cs.startswith("<="):
                return sp.Le(left_expr, int(cs[2:]))
            elif cs.startswith(">"):
                return sp.Gt(left_expr, int(cs[1:]))
            elif cs.startswith("<"):
                return sp.Lt(left_expr, int(cs[1:]))
            elif cs.startswith("!="):
                return sp.Ne(left_expr, int(cs[2:]))
            elif cs.startswith("="):
                return sp.Eq(left_expr, int(cs[1:]))
            
            raise ValueError(f"Unknown condition in scaling function: {cond_raw}")
        
        def apply_arrith(e: Optional[sp.Expr], token: str) -> sp.Expr:
            #if e is None:
            #    raise ValueError(f"Cannot apply arithmetic '{token}' without a base expression, need base value first.")
            if token.startswith("+"):
                return e + sp.sympify(token[1:])
            elif token.startswith("-"):
                return e - sp.sympify(token[1:])
            elif token.startswith("*"):
                return e * sp.sympify(token[1:])
            elif token.startswith("/"):
                return e / sp.sympify(token[1:])
            elif token.startswith("~") or token == "~":
                return sp.sympify(f"~({sp.sstr(e)})")
            
            return sp.sympify(token)
        
        i = 0
        last_expr = None
        while i < len(tokens):
            raw = tokens[i].replace(" ", "")

            # Erkenne das Muster "~" gefolgt von "+1"
            if raw == "~" and i + 1 < len(tokens) and tokens[i + 1].replace(" ", "") == "+1":
                if expr is None and last_expr is None:
                    raise ValueError("Cannot start expression with '~' operator without a base value.")
                expr = -expr if expr is not None else -last_expr
                i += 2  # Überspringe "+1"
                continue

            if raw.startswith("if"):
                cond_str = raw[2:]  # nutze originalen raw-String hinter "if"
                cond = to_relop(cond_str, expr if expr is not None else last_expr)
                if expr is None and last_expr is None:
                    raise ValueError("Cannot create Piecewise arm without an expression before 'if'.")
                arm_expr = expr if expr is not None else last_expr
                arms.append((arm_expr, cond))
                last_expr = arm_expr
                expr = None
                i += 1
                continue
                
            if expr is None:
                if raw != "~":
                    expr = apply_arrith(last_expr, raw)
                else:
                    expr = None
                if expr is None:
                    raise ValueError("Cannot start expression with '~' operator without a base value.")
            else:
                expr = apply_arrith(expr, raw)
            i += 1
        
        # Nach der Schleife: letzten Arm als Default (True) anhängen
        if expr is not None:
            arms.append((expr, True))

        pw = sp.Piecewise(*arms)
        if sign:
            pw = sp.sympify(f"{sign}({sp.sstr(pw)})")
        pw = sp.piecewise_fold(pw)
        pw = sp.simplify(pw)
        return pw


    # def clean_calculation_string(self, sign: str, calculations: list[str]) -> str:

    #     if len(calculations) == 0:
    #         logger.warning("No calculations found in scaling function.")
    #         return ""

    #     value = ""
    #     for op in calculations:
    #         op = op.replace(" ", "")
    #         if op == "+1" and value.startswith("~(") and value.endswith(")"):
    #             # Special case: replace negation (~(...)+1) with -(...)
    #             inner = value[2:-1]  # clean inner expression
    #             value = f"-({inner})"
    #         elif op.startswith("+"):
    #             value = f"({value} + {op[1:]})"
    #         elif op.startswith("-"):
    #             value = f"({value} - {op[1:]})"
    #         elif op.startswith("*"):
    #             value = f"({value} * {op[1:]})"
    #         elif op.startswith("/"):
    #             value = f"({value} / {op[1:]})"
    #         elif op.startswith("~"):
    #             value = f"~({value})"
    #         elif op.startswith("if"):
    #             # Handle conditional expressions
    #             condition = op[2:].strip()
    #             value = f"Piecewise(({value},x1 {condition}))"
    #         else:
    #             value = op
        
    #     if sign:
    #         value = f"{sign}({value})"

    #     print(f"in klammern: {value}", flush=True)


    #     x = sp.symbols('x1')
    #     expr = sp.sympify(value)

    #     return expr


    def _flatten_piecewise(self, expr) -> sp.Expr:
        """
        Flacht Piecewise-Ausdrücke ab, führt identische Arme zusammen und vereinfacht Bedingungen.
        """
        expr = sp.sympify(expr)
        expr = sp.piecewise_fold(expr)
        if not isinstance(expr, sp.Piecewise):
            return sp.simplify(expr)

        by_expr: dict[sp.Expr, List[Boolean]] = {}
        for arm_expr, cond in expr.args:
            e = sp.simplify(arm_expr)
            by_expr.setdefault(e, []).append(cond)

        new_args: List[sp.Tuple[sp.Expr, Boolean]] = []
        for e, conds in by_expr.items():
            try:
                new_cond = sp.simplify_logic(sp.Or(*conds), form="cnf")
            except Exception:
                new_cond = sp.Or(*conds)
            new_args.append((e, new_cond))

        if not any(c is True for _, c in new_args):
            new_args.append((new_args[-1][0], True))

        return sp.simplify(sp.Piecewise(*new_args))

    def _extract_piecewise_boundaries(self, expr, sym: sp.Symbol) -> List[float]:
        """
        Robust: sammelt Grenzen aus Bedingungen (Relational, And/Or) und Nullstellen der Zweige.
        Gibt eindeutige, sortierte float-Werte zurück.
        """
        expr = sp.piecewise_fold(sp.sympify(expr))
        boundaries: set[sp.Expr] = set()

        def add(vals):
            for v in vals:
                try:
                    if getattr(v, "is_real", False):
                        boundaries.add(sp.nsimplify(v))
                except Exception:
                    pass

        def from_cond(c):
            if c is True or c is False:
                return
            if isinstance(c, Relational):
                try:
                    add(sp.solve(sp.Eq(c.lhs, c.rhs), sym))
                except Exception:
                    pass
                return
            if isinstance(c, (And, Or)):
                for a in c.args:
                    from_cond(a)
                return
            try:
                add(sp.solve(sp.Eq(c, 0), sym))
            except Exception:
                pass

        def walk(e):
            if isinstance(e, sp.Piecewise):
                for branch, cond in e.args:
                    from_cond(cond)
                    try:
                        add(sp.solve(sp.Eq(branch, 0), sym))
                    except Exception:
                        pass
                    walk(branch)
            else:
                try:
                    add(sp.solve(sp.Eq(e, 0), sym))
                except Exception:
                    pass

        walk(expr)
        out: List[float] = []
        for b in boundaries:
            try:
                out.append(float(sp.N(b)))
            except Exception:
                pass
        return sorted(set(out))
    
    # def _to_relop(self, cond_str: str, x: sp.Symbol) -> Boolean:
    #     """
    #     Sehr einfacher Lexer für die vom Parser erzeugten "if ..."-Marker:
    #     erlaubt: >=, <=, >, <, ==, !=  mit rechter Seite als Integer.
    #     """
    #     cs = cond_str.strip()
    #     if cs.startswith(">="):
    #         return x >= int(cs[2:].strip())
    #     if cs.startswith("<="):
    #         return x <= int(cs[2:].strip())
    #     if cs.startswith(">"):
    #         return x > int(cs[1:].strip())
    #     if cs.startswith("<"):
    #         return x < int(cs[1:].strip())
    #     if cs.startswith("=="):
    #         return sp.Eq(x, int(cs[2:].strip()))
    #     if cs.startswith("!="):
    #         return sp.Ne(x, int(cs[2:].strip()))
    #     raise ValueError(f"Unsupported condition in 'if': {cond_str!r}")

    def _set_unit(self):
        '''
        Set the unit for the scaling as done in IMPREZA96 @C15B: fn_set_lower_screen_buffer_unit
        '''
        if self.mt_entry.lower_label_index == 0xFF:
            self.unit = None
            return  # No unit
        
        if self.romid_entry.menuitems_lower_label_pointer is None:
            raise ValueError("No lower label pointer available in ROM ID entry.")
        
        lower_label_pointer = self.romid_entry.menuitems_lower_label_pointer + self.mt_entry.lower_label_index * 16

        lower_label_raw = self.emulator.mem.read_bytes(lower_label_pointer, 16)
        lower_label_str = self.rom_cfg.byte_interpreter.render(lower_label_raw)

        self.unit = lower_label_str.strip()

    def _trace_rx_value_calculation(self, instr: Instruction, access: MemAccess):
        self.instr_parser.do_step(instr, access)
