from dataclasses import dataclass
import logging
from typing import Optional

import sympy as sp
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

        self.data_scaling: Optional[str] = None
        self.decimal_places: Optional[int] = None

        logger.debug(f"Running Scaling Function for MT Entry {mt_entry.menu_item_str()} with scaling index {mt_entry.scaling_index}")

        self.check_disasm_scaling()
        self.set_unit()

        self.add_function_mocks()
        self.set_instruction_parser()

        # Add function mocks where we need information from the disassembly as variable names could be unknown before
        ###self.instr_parser.add_function_mocks()

        self.emulate_receive_ssm_response()

    # TODO als Alternative nur den INdex nehmen und direkt aqus der Tabelle die Adresse holen?
    # Aber was wäre mit BARO.P usw?

    def set_instruction_parser(self):
        self.instr_parser = CalcInstructionParser(self.rom_cfg, self.emulator, read_address=self.rom_cfg.address_by_name("ssm_rx_byte_2"))
        # Add function mocks where we need information from the disassembly as variable names could be unknown before
        self.instr_parser.add_function_mocks()


    def check_disasm_scaling(self):
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
            action_fn_patterns = pattern_detector.detect_patterns(self.rom_cfg.instructions, "scaling_function_pattern")
    
    def add_function_mocks(self):
        '''
        Add necessary function mocks for the scaling functions
        '''

        def mock_skip(em: Emulator6303):
            # Just return from the function
            em.mock_return()

        self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_value"), mock_skip)

        def hook_read_ssm_rx_bytes_in_scaling_fn(addr: int, value: int, mem: MemoryManager):
            logger.debug(f"hook_read_ssm_rx_bytes_in_scaling_fn at {addr:04X}")
            #self.emulator.add_logger("scaling_fn_ssm_rx_logger", lambda instr, access: logging.debug(f"[SCALING_FN] Read SSM RX Bytes: {instr.address:04X}"))
            self.emulator.add_logger("scaling_fn_ssm_rx_logger", self.trace_rx_value_calculation)

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
    
    def emulate_receive_ssm_response(self):
        # Emulate that a response has been received
        SsmEmuHelper.set_ssm_response_received_flag(self.rom_cfg, self.emulator)

        # Reset wait counter in main loop wich lets the scaling function run only every 4th time
        self.emulator.mem.write(self.rom_cfg.address_by_name("master_table_run_scaling_wait_counter"), 4)

    
    def run_function(self):
        if self.scaling_fn_ptr in self.rom_cfg.scaling_addresses:
            logger.debug(f"Scaling function at 0x{self.scaling_fn_ptr:04X} already known, skipping emulation.")

            if self.mt_entry.item_label is not None:
                self.rom_cfg.scaling_addresses[self.scaling_fn_ptr].functions.append(self.mt_entry.item_label)
            
        else:

            ssm_rx_values = [0x00, 0xFF]  # Example SSM RX byte values to test

            additional_run_needed = True
            # Do this as long there are simulated ssm rx values to test
            while additional_run_needed and len(ssm_rx_values) > 0:
                self.emulator.mem.write(self.rom_cfg.address_by_name("ssm_rx_byte_2"), ssm_rx_values.pop(0))

                current_data_scaling = self.data_scaling
                current_decimal_places = self.decimal_places

                # Re-Set the SSM response received flag before running the scaling function again
                self.emulate_receive_ssm_response()

                # Re-Set instruction parser
                self.set_instruction_parser()

                self.emulator.set_pc(self.rom_cfg.address_by_name("mastertable_run_scaling_fn"))
                self.emulator.run_function_end(abort_pc=self.rom_cfg.address_by_name("master_table_main_loop"))
                self.run_post_actions()

                if current_data_scaling is not None and current_data_scaling != self.data_scaling:
                    raise NotImplementedError(f"Data scaling changed during scaling function loops: {current_data_scaling} -> {self.data_scaling}")

                if current_decimal_places is not None and current_decimal_places != self.decimal_places:
                    raise RuntimeError("Decimal places changed during scaling function execution")
                

                # If there were branches in the assembly depending on calculation values, another run might be needed
                additional_run_needed = self.instr_parser.value_depended_branches

                if self.instr_parser.conditions:
                    logger.debug(f"Conditions detected during scaling function execution: {self.instr_parser.conditions}")
                    self.instr_parser.conditions.clear()


            # Finally, save the results into the MasterTableEntry
            if self.mt_entry.action is None:
                raise RuntimeError("MasterTableEntry action datatype not set before saving SCALING action results.")
            
            if  self.mt_entry.item_label is not None:
                functions=[self.mt_entry.item_label]
            else:
                functions=[]
            
            if self.decimal_places is None:
                raise EmulationError("Decimal places not determined after scaling function execution.")

            self.rom_cfg.scaling_addresses[self.scaling_fn_ptr] = RomScalingDefinition(
                scaling=str(self.data_scaling),
                precision_decimals=self.decimal_places,
                unit=self.unit,
                functions=functions
            )

        # And add to this action, either from config or newly created
        if self.mt_entry.action is None:
            raise RuntimeError("MasterTableEntry action datatype not set before saving SCALING action results.")
        self.mt_entry.action.scaling = self.rom_cfg.scaling_addresses[self.scaling_fn_ptr]
            



    def run_post_actions(self):
        negative_sign = "-" if self.emulator.mem.read(self.rom_cfg.address_by_name('print_-_sign')) == 1 else ""
        positive_sign = "+" if self.emulator.mem.read(self.rom_cfg.address_by_name('print_+_sign')) == 1 else ""
        self.value_sign = f"{positive_sign}{negative_sign}"
        self.decimal_places = self.emulator.mem.read(self.rom_cfg.address_by_name('decimal_places'))
        
        if self.decimal_places > 0:
            self.instr_parser.calculations.append(f" / {10 ** self.decimal_places}")
        
        
        print(f"Vor clean (value-sign \"{self.value_sign}\"): {' '.join(self.instr_parser.calculations)} )", flush=True)

        self.data_scaling = self.clean_calculation_string(self.value_sign, self.instr_parser.calculations)
        
        

        print(f"Cleaned: {self.data_scaling}", flush=True)



    def clean_calculation_string(self, sign: str, calculations: list[str]) -> str:

        if len(calculations) == 0:
            logger.warning("No calculations found in scaling function.")
            return ""

        value = ""
        for op in calculations:
            op = op.replace(" ", "")
            if op == "+1" and value.startswith("~(") and value.endswith(")"):
                # Special case: replace negation (~(...)+1) with -(...)
                inner = value[2:-1]  # clean inner expression
                value = f"-({inner})"
            elif op.startswith("+"):
                value = f"({value} + {op[1:]})"
            elif op.startswith("-"):
                value = f"({value} - {op[1:]})"
            elif op.startswith("*"):
                value = f"({value} * {op[1:]})"
            elif op.startswith("/"):
                value = f"({value} / {op[1:]})"
            elif op.startswith("~"):
                value = f"~({value})"
            elif op.startswith("if"):
                # Handle conditional expressions
                condition = op[2:].strip()
                value = f"Piecewise(({value},x1 {condition}))"
            else:
                value = op
        
        if sign:
            value = f"{sign}({value})"

        print(f"in klammern: {value}", flush=True)


        x = sp.symbols('x1')
        expr = sp.sympify(value)

        return expr


    def set_unit(self):
        '''
        Set the unit for the scaling as done in IMPREZA96 @C15B: fn_set_lower_screen_buffer_unit
        '''
        if self.mt_entry.lower_label_index == 0xFF:
            return  # No unit
        
        if self.romid_entry.menuitems_lower_label_pointer is None:
            raise ValueError("No lower label pointer available in ROM ID entry.")
        
        lower_label_pointer = self.romid_entry.menuitems_lower_label_pointer + self.mt_entry.lower_label_index * 16

        lower_label_raw = self.emulator.mem.read_bytes(lower_label_pointer, 16)
        lower_label_str = self.rom_cfg.byte_interpreter.render(lower_label_raw)

        self.unit = lower_label_str.strip()

    def trace_rx_value_calculation(self, instr: Instruction, access: MemAccess):
        self.instr_parser.do_step(instr, access)
