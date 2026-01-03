from decimal import ROUND_HALF_DOWN, ROUND_HALF_UP, Decimal
import logging
from typing import List, Optional

import sympy as sp
from sympy.logic.boolalg import Boolean
from analyzer_core.analyze.instruction_parser import CalcInstructionParser
from analyzer_core.analyze.pattern_detector import PatternDetector
from analyzer_core.config.byte_interpreter import ByteInterpreter
from analyzer_core.config.rom_config import RomConfig, RomScalingDefinition
from analyzer_core.config.ssm_model import CurrentSelectedDevice, MasterTableEntry, RomIdTableEntry_512kb, RomSwitchDefinition
from analyzer_core.analyze.lookup_table_helper import LookupTable, LookupTableHelper as LutHelper
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

        logger.debug(f"Running Scaling Function for MT Entry '{mt_entry.item_label}' {mt_entry.menu_item_str()} with scaling index {mt_entry.scaling_index}")

        self._ensure_scaling_disassembly()
        self._set_unit()
        self._add_function_mocks()

        self.instr_parser = CalcInstructionParser(self.rom_cfg, self.emulator, read_address=self.rom_cfg.address_by_name("ssm_rx_byte_2"))
        # Add function mocks where we need information from the disassembly as variable names could be unknown before
        #self.instr_parser.add_function_mocks()
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
            disasm = Disassembler630x(mem=self.emulator.mem, rom_config=self.rom_cfg, current_device=self.current_device)
            disasm.disassemble_reachable(self.scaling_fn_ptr, self.rom_cfg.instructions, self.rom_cfg.call_tree)

            pattern_detector = PatternDetector(self.rom_cfg)
            
            # Fail silently here, as not every scaling function has already all known patterns
            pattern_detector.detect_patterns(self.rom_cfg.instructions, "scaling_function_pattern", no_warnings=True)

    
    def _add_function_mocks(self):
        '''
        Add necessary function mocks for the scaling functions
        '''

        def mock_skip(em: Emulator6303):
            # Just return from the function
            em.mock_return()

        # Don't skip lower value print, takes more emulated steps but it's possible to do a later calculation check with the output
        #self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_value"), mock_skip)

        # As soon as we read the SSM RX bytes in the scaling function, we log the tracing
        def hook_read_ssm_rx_bytes_in_scaling_fn(addr: int, value: int, mem: MemoryManager):
            #logger.debug(f"hook_read_ssm_rx_bytes_in_scaling_fn at {addr:04X}")
            #self.emulator.add_logger("scaling_fn_ssm_rx_logger", lambda instr, access: logging.debug(f"[SCALING_FN] Read SSM RX Bytes: {instr.address:04X}"))
            self.emulator.add_logger("scaling_fn_ssm_rx_logger", self._trace_rx_value_calculation)

        def hook_pre_scaling_function(em: Emulator6303):
            #logger.debug(f"hook_pre_scaling_function at {self.scaling_fn_ptr:04X}")
            # TEST 28.11. self.emulator.hooks.add_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_2"), hook_read_ssm_rx_bytes_in_scaling_fn)
            self.emulator.add_logger("scaling_fn_ssm_rx_logger", self._trace_rx_value_calculation)
        
        def hook_post_scaling_function(em: Emulator6303, access):
            #print(f"hook_post_scaling_function at {self.scaling_fn_ptr:04X}", flush=True)
            # TEST 28.11. self.emulator.hooks.remove_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_2"), hook_read_ssm_rx_bytes_in_scaling_fn)
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
            '''
            When loaded: A: SSM rx byte, X: Pointer to switch labels
            Sets the SSM lights according to the switch definitions in SSM
            '''


            upper_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y0_x0')
            lower_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y1_x0')

            switch_labels = self._get_switch_labels(upper_screen_line, lower_screen_line)

            # At the time of this function call, the X pointer leads to the switch assignments starting with the XOR part,
            # followed by the switch bit assignments in form of a byte for each switch (0-9)

            xor_value = em.read8(em.X)

            for idx, label in switch_labels.items():
                # Get switch value from the corresponding byte
                switch_value = em.read8(em.X + 1 + idx)
                bit_value = switch_value.bit_length() - 1

                # Happens e.g. in AC DI: Two switch labels with the same meaning, which combine two labels, e.g. "AC SW" 
                # For this: loop over all switches and check for same bit value
                double_index = False
                for switch in self.switch_defs:
                    if switch.bit == bit_value:
                        switch.name += f" {label}"
                        double_index = True

                if not double_index:
                    self.switch_defs.append(RomSwitchDefinition(
                        name=label,
                        inverted=(switch_value & xor_value) == 1, # TODO prüfen ob das so stimmt
                        bit=bit_value
                    ))



            em.mock_return()

        #def hook_post_print_switch_screen(em: Emulator6303, access):
            #self.use_switches_mode = True

            # Mock the print functions to capture the switch labels
            #self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_upper_screen"), mock_print_upper_screen)
            #self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_screen"), mock_print_lower_screen)

            # Save the screen lines directly in this function only print_upper_screen is called, the other one happens after the Scaling fn
            #self.upper_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y0_x0')
            #self.lower_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y1_x0')

            # Mock the hex value printer entirely as it might be simpler than emulating it for all SSM values
            #self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("hex_value_to_ssm_light"), mock_hex_value_to_ssm_light)


        # Add a hook to the function 'print_switch_screen' which is responsible to printing the switch values on a DIO
        # Use this to enable Switches mode -> alternative: Check by name DIOx FAx
        # Decompilation and detection happens on the first switch, so we hook this only after we know the function address

        ######################################################
        # TODO Funktioniert nur für EGi, bei den anderen reicht das nicht aus. Diese nutzen nciht diese Funktion print_switch_screen_from_addressIndex_pointer,
        # die erst auf romid3 geht, sondern direkt print_upper_screen -> Also doch FAyxx
        # und er muss auf std upper_ssm_lights dann seinen hook machen, nahc hex_value_to_ssm_light wird manchmal n0coh was gerechnet
        #if self.rom_cfg.check_for_name("print_switch_screen"):
        #    self.emulator.hooks.add_post_hook(self.rom_cfg.address_by_name("print_switch_screen"), hook_post_print_switch_screen)

        if self.mt_entry.menu_item_str().startswith("FA"):
            self.use_switches_mode = True

            # We mock the function to set the lights completely
            '''
            When used for several addresses it looks like this:

            ldx	#$34E5
            jsr	print_switch_screen_from_addressIndex_pointer
            ldaa	ssm_rx_buffer_0
            jsr	hex_value_to_ssm_light(A: SSM-RX-Byte, X: SwitchesPtr_HinterLabels)->D
            std	print_hex_buffer_0
            ldaa	ssm_rx_buffer_1
            jsr	hex_value_to_ssm_light(A: SSM-RX-Byte, X: SwitchesPtr_HinterLabels)->D
            addd	print_hex_buffer_0
            std	upper_ssm_lights
            rts

            Values from several addresses will only be added together

            TODO currently this will call the function multiple times if several addresses are used
            '''
            self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("hex_value_to_ssm_light"), mock_hex_value_to_ssm_light)
            
    
    def _emulate_receive_ssm_response(self):
        # Emulate that a response has been received
        SsmEmuHelper.set_ssm_response_received_flag(self.rom_cfg, self.emulator)

        # Reset wait counter in main loop wich lets the scaling function run only every 4th time
        self.emulator.mem.write(self.rom_cfg.address_by_name("master_table_run_scaling_wait_counter"), 4)

        # Reset decimal value
        self.emulator.mem.write(self.rom_cfg.address_by_name('decimal_places'), 0)

    def run_function(self):
        """Emulate scaling function with multiple inputs to determine scaling."""

        if self.scaling_fn_ptr in self.rom_cfg.scaling_addresses:
            logger.debug(f"Scaling function at 0x{self.scaling_fn_ptr:04X} already known, skipping emulation.")
            if self.mt_entry.item_label:
                # TODO: Mapped adresse dann?? Sollte besser Rom sein
                self.rom_cfg.scaling_addresses[self.scaling_fn_ptr].functions.append(self.mt_entry.item_label)
            else:
                logger.warning(f"Scaling function at 0x{self.scaling_fn_ptr:04X} has no item label.")
            return
        
        # Also, save it as a global function address
        if not self.rom_cfg.check_for_function_address(self.scaling_fn_ptr):
            fn_label_proto = f"fn_scaling_{self.current_device.name}_{self.mt_entry.item_label}"
            counter = 1
            while self.rom_cfg.check_for_name(f"{fn_label_proto}_{counter}"):
                counter += 1
            fn_label = f"{fn_label_proto}_{counter}"
            self.rom_cfg.add_refresh_mapped_function(name=fn_label, mapped_address=self.scaling_fn_ptr, current_device=self.current_device)
        
        decimal_places: int = -1
        
        ssm_inputs: List[int] = [0]   # initial TX values to test
        seen_samples: set[int] = set()
        #possible_index_values: list[int] = []
        emulated_output: dict[int, tuple[str, str]] = {}

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
            current_decimal_places = self.emulator.mem.read(self.rom_cfg.address_by_name('decimal_places'))
            self.instr_parser.calculate_decimal_places(current_decimal_places)

            if decimal_places == -1:
                decimal_places = current_decimal_places
            elif decimal_places != current_decimal_places:
                logger.warning(f"Different decimal places detected during scaling function emulation: previous {decimal_places}, current {current_decimal_places}. Using maximum.")
                decimal_places = max(decimal_places, current_decimal_places)

            self.instr_parser.negate_current_expression_if_negative()

            #if self.emulator.mem.read(self.rom_cfg.address_by_name('print_-_sign')) == 1:
            #    self.instr_parser.negate_current_expression_if_negative()

            # To check the calculation afterwards, collect the display output from this run
            upper_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, self.emulator, 'ssm_display_y0_x0')
            lower_screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, self.emulator, 'ssm_display_y1_x0')
            emulated_output[rx_test_value] = (upper_screen_line, lower_screen_line)
            
            # Get jump conditions from guards to find new test inputs
            for value in self.instr_parser.solve_jump_conditions():
                if value not in seen_samples and value not in ssm_inputs:
                    ssm_inputs.append(value)

            # Get current expression and conditions from the instruction parser and substitude to make simplification by sympy easier
            subst_expression = LutHelper.substitute_lookup_tables(self.instr_parser.current_expr)
            subst_conditions = [LutHelper.substitute_lookup_tables(cond) for cond in self.instr_parser.conditions]

            eq_pieces.append((subst_expression, sp.And(*subst_conditions))) # type: ignore


        # TODO Das dauert ewig bei vielen Bedingungen -> Text-Luts AC
        final_expr = self.instr_parser.finalize_simplify_equations(eq_pieces)

        # Check if we are in Switches mode where we don't need a static scaling but the switch values
        # Switches are already handled in the mocks above
        if not self.use_switches_mode:
            current_scaling = RomScalingDefinition(
                #scaling=sp.simplify(final_expr, force=True),
                scaling=final_expr,
                scaling_address_pointer = self.scaling_fn_ptr,
                precision_decimals=decimal_places,
                unit=self.unit,
                lookup_tables=LutHelper.get_lookup_table_values(final_expr, self.instr_parser.symbol) if self.instr_parser.found_luts > 0 else None,
                functions=[self.mt_entry.item_label] if self.mt_entry.item_label else []
            )

            self._check_label_results(emulated_output, current_scaling)
            self.rom_cfg.scaling_addresses[self.scaling_fn_ptr] = current_scaling


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

    def _check_label_results(self, emulated_output: dict[int, tuple[str, str]], scaling_definition: RomScalingDefinition) -> bool:

        # TODO Eigentlich ja auch notwendig, mittlere werte zu nehmen, wenn ein branch oder so drin ist?

        def get_label_result(self, line: str, has_lookup_tables: bool) -> float|str:
            label = line.strip()
            if self.unit:
                if label.endswith(self.unit):
                    label = label[: -len(self.unit)].rstrip()
                # for LUT values without unit, not 100% clean: INT LUTs can have a unit, but should be caught above
                elif has_lookup_tables:
                    pass
                else:
                    raise ValueError("Unit is set but label does not end with it.")
            

            if type(label) == str:
                return label
            
            # Check if we convert the label to a number
            try:
                return float(label)
            except ValueError:
                # Otherwise assume a string based lookup table and return the string
                return label
        
        for rx_value, (upper_line, lower_line) in emulated_output.items():
            label_result = get_label_result(self, lower_line, scaling_definition.lookup_tables is not None)

            # Evaluate the scaling expression for this rx_value
            expr = scaling_definition.scaling
            # Replace x1 with rx_value (and currently every other free symbol as well)
            calc_value = None
            for sym in expr.free_symbols:
                calc_value = expr.subs(sym, rx_value) # TODO so ist noch Müll...
            
            #TODO oder
            #calc_value = expr.subs({"x1": rx_value})
            
            if calc_value is None:
                raise ValueError("No calculable expression found for scaling definition.")
            
            # Check if the result is still a LookupTable function, then it should be a string LUT where we check for string equality
            if isinstance(calc_value, sp.Function) and issubclass(calc_value.func, LookupTable):
                if calc_value.func.is_String:
                    index = int(calc_value.args[0]) # type: ignore
                    if calc_value.func.table_data[index] == label_result:
                        continue
                    else:
                        raise NotImplementedError("Didn't expect a string LUT at this point")
            
            if scaling_definition.scaling_address_pointer == 0x2795:
                pass

            # Round expr to the number of decimal places in scaling_definition
            if scaling_definition.precision_decimals is not None and scaling_definition.precision_decimals >= 0:
                quant = Decimal("1").scaleb(-scaling_definition.precision_decimals)
                d = Decimal(str(sp.N(calc_value)))

                calc_value = d.quantize(quant, rounding=ROUND_HALF_UP)

                # Workaround for positive/negative numbers, as SSM software seems to round them differently
                # if d >= 0:
                #     # Use ROUND_HALF_UP for positive numbers (0.25 -> 0.3...)
                #     calc_value = d.quantize(quant, rounding=ROUND_HALF_UP)
                # else:
                #     # Use ROUND_HALF_DOWN for negative numbers (-0.25 -> 0.2...)
                #     calc_value = d.quantize(quant, rounding=ROUND_HALF_DOWN)
            else:
                quant = Decimal("1")

            if sp.Float(calc_value) != label_result:
                #if label_result == 0 and sp.Abs(calc_value) <= sp.Float(0.1):
                if (Decimal(label_result) - calc_value).quantize(quant) <= quant: # type: ignore
                    # Workaround for rounding issues
                    logger.warning(f"Calculated value '{calc_value}' at 0x{scaling_definition.scaling_address_pointer:04X} for RX value {rx_value}"
                                   f" differs slightly from expected label '{label_result}'. Accepting due to rounding from decimal places.")
                else:
                    raise ValueError(f"Calculated value '{calc_value}' at 0x{scaling_definition.scaling_address_pointer:04X} for RX value {rx_value}"
                                 f" does not match expected label '{label_result}'. Calculated: {expr}")
            
        return True
            

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
        byte_interpreter = ByteInterpreter()
        lower_label_str = byte_interpreter.render(lower_label_raw)

        self.unit = lower_label_str.strip()

    def _trace_rx_value_calculation(self, instr: Instruction, access: MemAccess):
        self.instr_parser.do_step(instr, access)

