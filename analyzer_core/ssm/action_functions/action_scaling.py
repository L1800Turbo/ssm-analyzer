import logging
from typing import List, Optional

import sympy as sp
from sympy.logic.boolalg import Boolean
from analyzer_core.analyze.instruction_parser import CalcInstructionParser
from analyzer_core.analyze.pattern_detector import PatternDetector
from analyzer_core.config.rom_config import RomConfig, RomScalingDefinition
from analyzer_core.config.ssm_model import CurrentSelectedDevice, MasterTableEntry, RomIdTableEntry_512kb, RomSwitchDefinition
from analyzer_core.disasm.capstone_wrap import Disassembler630x
from analyzer_core.disasm.insn_model import Instruction
from analyzer_core.emu.emulator_6303 import Emulator6303
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

        # For use of switches
        self.use_switches_mode = False
        self.switch_defs: List[RomSwitchDefinition] = []
        self.upper_screen_line: Optional[str] = None
        self.lower_screen_line: Optional[str] = None

        self.unit: Optional[str] = None

        logger.debug(f"Running Scaling Function for MT Entry {mt_entry.menu_item_str()} with scaling index {mt_entry.scaling_index}")

        self._ensure_scaling_disassembly()
        self._set_unit()
        self._add_function_mocks()

        self.instr_parser = CalcInstructionParser(self.rom_cfg, self.emulator, read_address=self.rom_cfg.address_by_name("ssm_rx_byte_2"))
        # Add function mocks where we need information from the disassembly as variable names could be unknown before
        self.instr_parser.add_function_mocks()
        self.instr_parser.init_new_instruction()

        self._emulate_receive_ssm_response()


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
            
            # TODO Versucht noch mehrere zu finden und beschwert sich dann. Muss man noch anpassen
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
            #logger.debug(f"hook_read_ssm_rx_bytes_in_scaling_fn at {addr:04X}")
            #self.emulator.add_logger("scaling_fn_ssm_rx_logger", lambda instr, access: logging.debug(f"[SCALING_FN] Read SSM RX Bytes: {instr.address:04X}"))
            self.emulator.add_logger("scaling_fn_ssm_rx_logger", self._trace_rx_value_calculation)

        def hook_pre_scaling_function(em: Emulator6303):
            #logger.debug(f"hook_pre_scaling_function at {self.scaling_fn_ptr:04X}")
            self.emulator.hooks.add_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_2"), hook_read_ssm_rx_bytes_in_scaling_fn)
        
        def hook_post_scaling_function(em: Emulator6303, access):
            #print(f"hook_post_scaling_function at {self.scaling_fn_ptr:04X}", flush=True)
            self.emulator.hooks.remove_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_2"), hook_read_ssm_rx_bytes_in_scaling_fn)
            self.emulator.remove_logger("scaling_fn_ssm_rx_logger")

        self.emulator.hooks.add_pre_hook(self.scaling_fn_ptr, hook_pre_scaling_function)
        self.emulator.hooks.add_post_hook(self.scaling_fn_ptr, hook_post_scaling_function)


        # ------ Definitions and hooks for Switches mode ------
        # def mock_print_upper_screen(em: Emulator6303):
        #     # Take upper and lower line as during this function call the variables should be set
        #     self.upper_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y0_x0')
        #     self.lower_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y1_x0')
        #     #print(f"Upper Screen [{self.upper_screen_line}]", flush=True)
        #     em.mock_return()
        
        #def mock_print_lower_screen(em: Emulator6303):
        #    self.lower_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y1_x0')
        #    #print(f"Lower Screen [{self.lower_screen_line}]", flush=True)
        #    em.mock_return()
        
        def mock_hex_value_to_ssm_light(em: Emulator6303):
            # Get switch values that should have been printed by now
            if self.upper_screen_line is None or self.lower_screen_line is None:
                raise RuntimeError("Switch screen lines not captured before hex_value_to_ssm_light call.")
            switch_labels = self._get_switch_labels(self.upper_screen_line, self.lower_screen_line)

            # At the time of this function call, the X pointer leads to the switch assignments starting with the XOR part,
            # followed by the switch bit assignments in form of a byte for each switch (0-9)

            xor_value = em.read8(em.X)

            for idx, label in switch_labels.items():
                # Get switch value from the corresponding byte
                switch_value = em.read8(em.X + 1 + idx)

                self.switch_defs.append(RomSwitchDefinition(
                    name=label,
                    inverted=(switch_value & xor_value) == 1, # TODO prüfen ob das so stimmt
                    bit=switch_value.bit_length() - 1
                ))

            em.mock_return()

        def hook_post_print_switch_screen(em: Emulator6303, access):
            self.use_switches_mode = True

            # Mock the print functions to capture the switch labels
            #self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_upper_screen"), mock_print_upper_screen)
            #self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_screen"), mock_print_lower_screen)

            # Save the screen lines directly in this function only print_upper_screen is called, the other one happens after the Scaling fn
            self.upper_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y0_x0')
            self.lower_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y1_x0')

            # Mock the hex value printer entirely as it might be simpler than emulating it for all SSM values
            self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("hex_value_to_ssm_light"), mock_hex_value_to_ssm_light)


        # Add a hook to the function 'print_switch_screen' which is responsible to printing the switch values on a DIO
        # Use this to enable Switches mode -> alternative: Check by name DIOx FAx
        # Decompilation and detection happens on the first switch, so we hook this only after we know the function address
        if self.rom_cfg.check_for_address("print_switch_screen"):
            self.emulator.hooks.add_post_hook(self.rom_cfg.address_by_name("print_switch_screen"), hook_post_print_switch_screen)

        
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
        
        decimal_places: int = 0
        
        ssm_inputs: List[int] = [0]   # initial TX values to test
        seen_samples: set[int] = set()

        eq_pieces: list[tuple[sp.Expr | None, Boolean]] = []

        while ssm_inputs:
            rx_test_value = ssm_inputs.pop(0)
            seen_samples.add(rx_test_value)

            # Reset Emulator/Parser
            self.emulator.mem.write(self.rom_cfg.address_by_name("ssm_rx_byte_2"), rx_test_value)
            self._emulate_receive_ssm_response()
            self.instr_parser.init_new_instruction()

            # Run the emulation
            self.emulator.set_pc(self.rom_cfg.address_by_name("mastertable_run_scaling_fn"))
            self.emulator.run_function_end(
                abort_pc=self.rom_cfg.address_by_name("master_table_main_loop")
            )

            # After running, collect modified variables
            decimal_places = self.emulator.mem.read(self.rom_cfg.address_by_name('decimal_places'))
            self.instr_parser.calculate_decimal_places(decimal_places)

            # TODO Decimal places müssen ja auch in die Scaling-Definition später rein, also für jede Variante und prüfen?
            # Als condition? in einen Datentyp`?`
            
            if self.emulator.mem.read(self.rom_cfg.address_by_name('print_-_sign')) == 1:
                self.instr_parser.negate_current_expression()
            

            #print(f"{rx_test_value}  Expr: {self.instr_parser.current_expr}  guard: {sp.And(*self.instr_parser.conditions)}", flush=True)

            # Get jump conditions from guards to find new test inputs
            for value in self.instr_parser.solve_jump_conditions():
                if value not in seen_samples and value not in ssm_inputs:
                    ssm_inputs.append(value)
                    #print(f"    Adding new test input value: {value}", flush=True)

            eq_pieces.append((self.instr_parser.current_expr, sp.And(*self.instr_parser.conditions)))

        # Remove duplicates with same condition
        eq_pieces = list(dict.fromkeys(eq_pieces))

        # Group by same expressions
        #grouped: dict[sp.Expr | None, list[Boolean]] = {}
        #for expr, cond in eq_pieces:
        grouped: dict[str, tuple[sp.Expr, list[Boolean]]] = {}
        for expr, cond in eq_pieces:
            key:str = sp.srepr(sp.simplify(expr))
            if key in grouped:
                grouped[key][1].append(cond)
            else:
                grouped[key] = (expr, [cond])

            #grouped.setdefault(expr, []).append(cond)

        combined_equations: list[tuple[sp.Expr | None, Boolean]] = []
        #for expr, conds in grouped.items():
        for expr, conds in grouped.values(): # Not items, take the tuple
            condition = sp.Or(*conds)
            simplified_condition = sp.simplify(condition, force=True)
            
            combined_equations.append((expr, simplified_condition))

        final_expr = sp.Piecewise(*combined_equations)

        print(f"Final Scaling Expression: {final_expr}", flush=True)

        self.final_expr = final_expr


        # Check if we are in Switches mode where we don't need a static scaling but the switch values
        # Switches are already handled in the mocks above
        if not self.use_switches_mode:
            self.rom_cfg.scaling_addresses[self.scaling_fn_ptr] = RomScalingDefinition(
                scaling=sp.simplify(final_expr, force=True),
                precision_decimals=decimal_places,
                unit=self.unit,
                functions=[self.mt_entry.item_label] if self.mt_entry.item_label else []
            )


    def run_post_actions(self):
        pass

    def get_scaling_definition(self) -> RomScalingDefinition:
        if self.scaling_fn_ptr not in self.rom_cfg.scaling_addresses:
            raise RuntimeError("Scaling function has not been emulated yet, no scaling definition available.")
        
        return self.rom_cfg.scaling_addresses[self.scaling_fn_ptr]

    def get_switch_definitions(self) -> List[RomSwitchDefinition]:
        return self.switch_defs
    
    def _get_switch_labels(self, upper_line: str, lower_line: str) -> dict[int, str]:
        labels = {}
        upper = upper_line.strip().split()
        lower = lower_line.strip().split()
        for idx, upper_val in enumerate(upper, start=0):
            if upper_val != "__":
                labels[idx] = upper_val
        for idx, lower_val in enumerate(lower, start=5):
            if lower_val != "__":
                labels[idx] = lower_val
        return labels

        

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

