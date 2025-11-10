import logging
import re
from typing import Optional
from analyzer_core.analyze.pattern_detector import PatternDetector
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import ActionType, CurrentSelectedDevice, MasterTableEntry, RomIdTableEntry_512kb, SsmAction
from analyzer_core.disasm.capstone_wrap import Disassembler630x
from analyzer_core.emu.emulator_6303 import EmulationError, Emulator6303
from analyzer_core.emu.ssm_emu_helper import SsmEmuHelper
from analyzer_core.ssm.action_functions.action_helper import SsmActionHelper
from analyzer_core.ssm.action_functions.action_scaling import SsmActionScalingFunction
from analyzer_core.ssm.action_functions.action_year import SsmActionYear


class MasterTableEntryAnalyzer:
    def __init__(self, emulator: Emulator6303, rom_cfg: RomConfig, current_device: CurrentSelectedDevice, romid_entry:RomIdTableEntry_512kb, mt_entry: MasterTableEntry) -> None:
        self.mt_entry = mt_entry
        self.romid_entry = romid_entry
        self.emulator = emulator
        self.rom_cfg = rom_cfg
        self.current_device = current_device
        self.logger = logging.getLogger(__name__)

        self._save_labels()

        # Define the entry action datatype
        if self.mt_entry.upper_label is None:
            raise EmulationError(f"Upper label for MasterTable entry {self.mt_entry.menu_item_str()} is None.")
        
        self.mt_entry.action = SsmAction(
            action_type=ActionType.UNDEFINED,
            upper_label_raw=self.mt_entry.upper_label,
            )

        self._run_action_function()

    def _save_labels(self):
        '''
        The upper label depends on the upper label index
        '''

        def label_to_mt(lbl_ptr:int|None, lbl_idx):
            if lbl_ptr is None:
                raise EmulationError(f"Upper label pointer for RomID {self.romid_entry.print_romid_str}")
            
            if lbl_ptr == 0xFF:
                return ""
            
            lbl_addr = lbl_ptr + lbl_idx * 0x10
            lbl_bytes = self.emulator.mem.read_bytes(lbl_addr, 0x10)
            return self.rom_cfg.byte_interpreter.render(lbl_bytes)
        
        def item_label(upper_label:str) -> str:
            '''Extract the item label from e.g.  EX.TEMP  (F23) '''
            result = re.match(r"\s*(\S+)\s+\((\S+)\)", upper_label)
            if result:
                if result.group(2) != self.mt_entry.menu_item_str():
                    raise ValueError(f"Extracted item label index '{result.group(2)}' does not match MasterTable entry menu item '{self.mt_entry.menu_item_str()}'")
                return result.group(1)
            raise ValueError(f"Could not extract item label from upper label '{upper_label}'")
            

        self.mt_entry.upper_label = label_to_mt(self.romid_entry.menuitems_upper_label_pointer, self.mt_entry.upper_label_index)
        self.mt_entry.item_label = item_label(self.mt_entry.upper_label)
        
        # TODO geht noch nicht, die Geschichte mit dem stack ist noch falsch, wird bei AC8E geladen und dann auch direkt die ACTION
        # if self.mt_entry.lower_label_index != 0xFF:
        #    self.mt_entry.lower_label = label_to_mt(self.romid_entry.menuitems_lower_label_pointer, self.mt_entry.lower_label_index)

    
    def _run_action_function(self):
        '''
        Check if this action has already been decompiled (usually not reachable with static analysis).
        Check for the pattern to the Action functions to distinguish between them and mock them correctly later on.

        TODO woanders? :Run the label printing and action function from the master table main loop, d
        '''
        self.emulator.hooks.clear_hooks_and_mocks()
        SsmEmuHelper.execute_default_mocks(self.rom_cfg, self.emulator)

        # Blinking is only visual, don't need it if it wasn't set before
        self.emulator.mem.write(self.rom_cfg.address_by_name("blink_cursor_flag"), 0)
        

        def mock_default_action(em: Emulator6303):
            # Just return from the function
            em.mock_return()
        
        def mock_print_upper_screen(em: Emulator6303):
            screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y0_x0')
            print(f"Upper Screen [{screen_line}]", flush=True)
            em.mock_return()
        
        def mock_print_lower_screen(em: Emulator6303):
            screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y1_x0')
            print(f"Lower Screen [{screen_line}]", flush=True)
            em.mock_return()


        action_ptr = self.mt_entry.action_address_rel

        # Decompile the action function if not already done
        self.check_decompile_detect_pattern(action_ptr)

        # Try to get this action function
        action_fn = self.rom_cfg.get_by_address(action_ptr)

        # If the action function couldn't be matched, at all, yet
        if action_fn is None:
            # Mock this function if not done already
            #if not self.emulator.hooks.get_mock(action_ptr):
            #    self.logger.warning(f"Action pointer address 0x{action_ptr:04X} couldn't be matched to a function.")
            self.emulator.hooks.mock_function(action_ptr, mock_default_action)
            return
        
        action_helper: Optional[SsmActionHelper] = None

        if action_fn.name == "action_year":
            # Run the YEAR interpreter
            action_helper = SsmActionYear(self.rom_cfg, self.emulator, self.current_device, self.romid_entry, self.mt_entry)
            action_helper.add_function_mocks()

            # TODO Wird da was gemacht??
            SsmEmuHelper.hook_fn_read_from_ecu(self.rom_cfg, self.emulator)
        
        elif action_fn.name == "action_read_ecu":
            from analyzer_core.ssm.action_functions.action_read_ecu import SsmActionReadEcu
            action_helper = SsmActionReadEcu(self.rom_cfg, self.emulator, self.current_device, self.romid_entry, self.mt_entry)
            action_helper.add_function_mocks()

            #SsmEmuHelper.hook_fn_read_from_ecu(self.rom_cfg, self.emulator)

        # TODO für Read-Funktion und was da noch kommt:
        # MAnche wollen ein Lower Scaling, manche nicht.
        # Read dann hier emulieren, für die Adresse
        # Dann setzt der auch für die Maintable-loop (emulieren oder von hand?) die passenden bits
        # Hier vorerst: Lower-Scaling-Mastertable-Funktion aufrufen, die dann die Scaling Funktion aufruft

        else:
            # If not already mocked, do this for unknown action patterns
            if not self.emulator.hooks.get_mock(action_ptr):
                self.logger.warning(f"No handling defined for action function {action_fn.name} (0x{action_fn.address:04X}) "
                                    f"for MasterTable entry {self.mt_entry.menu_item_str()}, mocking it.")
                self.emulator.hooks.mock_function(action_ptr, mock_default_action)

                # Also mock the print functions to just print the labels for debug
                self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_upper_screen"), mock_print_upper_screen)
                self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_screen"), mock_print_lower_screen)

                SsmEmuHelper.hook_fn_read_from_ecu(self.rom_cfg, self.emulator)


        # Run the function
        self.emulator.set_pc(self.rom_cfg.address_by_name("master_table_info_into_ram"))
        self.emulator.run_function_end(abort_pc=self.rom_cfg.address_by_name("master_table_main_loop"))

        # After running the action function, run any post-actions if defined
        if action_helper is not None:
            action_helper.run_post_actions()

            # Run if scaling function should be called, check if value-dependent branches exist which require multiple runs
            if action_helper.needs_scaling_fn:
                action_scaling_helper = SsmActionScalingFunction(self.rom_cfg, self.emulator, self.current_device, self.romid_entry, self.mt_entry)
                action_scaling_helper.run_function()

    
    def check_decompile_detect_pattern(self, action_ptr: int):
        # Prequisities: Check if this function is already known in assembly
        if action_ptr not in self.rom_cfg.action_addresses:
            disasm = Disassembler630x(self.emulator.mem.rom_image.rom) # TODO Besser raussuchen? wie bei der read action?
            disasm.disassemble_reachable(action_ptr, self.rom_cfg.instructions, self.rom_cfg.call_tree)

            pattern_detector = PatternDetector(self.rom_cfg)
            action_fn_patterns = pattern_detector.detect_patterns(self.rom_cfg.instructions, "action_table_pointer_pattern")
            for action_fn_name, action_fn_addr in action_fn_patterns.items():
                self.rom_cfg.add_function_address(action_fn_name, action_fn_addr)
                self.rom_cfg.action_addresses.add(action_ptr)

       