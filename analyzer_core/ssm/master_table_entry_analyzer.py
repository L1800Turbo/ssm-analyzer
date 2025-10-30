import logging
from analyzer_core.analyze.pattern_detector import PatternDetector
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import MasterTableEntry, RomIdTableEntry_512kb
from analyzer_core.disasm.capstone_wrap import Disassembler630x
from analyzer_core.emu.emulator_6303 import EmulationError, Emulator6303
from analyzer_core.emu.ssm_emu_helper import SsmEmuHelper


class MasterTableEntryAnalyzer:


    def __init__(self, emulator: Emulator6303, rom_cfg: RomConfig, romid_entry:RomIdTableEntry_512kb, mt_entry: MasterTableEntry) -> None:
        self.mt_entry = mt_entry
        self.romid_entry = romid_entry
        self.emulator = emulator
        self.rom_cfg = rom_cfg
        self.logger = logging.getLogger(__name__)

        self._save_labels()
        self._run_action_function()

    def _save_labels(self):
        '''
        The upper label depends on the upper label index
        '''

        def label_to_mt(lbl_ptr:int|None, lbl_idx):
            if lbl_ptr is None:
                raise EmulationError(f"Upper label pointer for RomID {self.romid_entry.print_romid_str}")
            
            lbl_addr = lbl_ptr + lbl_idx * 0x10
            lbl_bytes = self.emulator.mem.read_bytes(lbl_addr, 0x10)
            return self.rom_cfg.byte_interpreter.render(lbl_bytes)

        self.mt_entry.upper_label = label_to_mt(self.romid_entry.menuitems_upper_label_pointer, self.mt_entry.upper_label_index)
        
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
        

        def mock_default_action(em: Emulator6303):
            # Just return from the function
            em.mock_return()      
        

        # TODO evtl in eigene Year klasse auslagern, unten das auch
        def mock_year_print_upper_screen(em: Emulator6303):
            screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y0_x0')
            print(f"Upper Screen [{screen_line}]", flush=True)
            self.romid_entry.ssm_year_model_str_1 = screen_line

            em.mock_return()
        
        def mock_year_print_lower_screen(em: Emulator6303):
            screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y1_x0')
            print(f"Upper Screen [{screen_line}]", flush=True)
            self.romid_entry.ssm_year_model_str_2 = screen_line

            em.mock_return()



        action_ptr = self.mt_entry.action_address_rel

        # Prequisities: Check if this function is already known in assembly
        if action_ptr not in self.rom_cfg.action_addresses:
            disasm = Disassembler630x(self.emulator.mem.rom_image.rom) # TODO Besser raussuchen?
            disasm.disassemble_reachable(action_ptr, self.rom_cfg.instructions, self.rom_cfg.call_tree)

            pattern_detector = PatternDetector(self.rom_cfg)
            action_fn_patterns = pattern_detector.detect_patterns(self.rom_cfg.instructions, "action_table_pointer_pattern")
            for action_fn_name, action_fn_addr in action_fn_patterns.items():
                self.rom_cfg.add_function_address(action_fn_name, action_fn_addr)
                self.rom_cfg.action_addresses.add(action_ptr)

        # Try to get this action function
        action_fn = self.rom_cfg.get_by_address(action_ptr)

        if action_fn is None:
            
            # Mock this function if not done already
            #if not self.emulator.hooks.get_mock(action_ptr):
            #    self.logger.warning(f"Action pointer address 0x{action_ptr:04X} couldn't be matched to a function.")
            self.emulator.hooks.mock_function(action_ptr, mock_default_action)
            
            return
        

        def test_hook(emu):
            pass


        # TODO bei AT Action ist alles 1990. eine Var ist da wohl noch nciht gesetzt

        if(action_fn.name == "action_year"):
            self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_upper_screen"), mock_year_print_upper_screen)
            self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_screen"), mock_year_print_lower_screen)

            #self.emulator.hooks.add_pre_hook(0x966A, test_hook)

        else:
            # If not already mocked
            if not self.emulator.hooks.get_mock(action_ptr):
                self.logger.warning(f"No handling defined for action function {action_fn.name} (0x{action_fn.address:04X}) for MasterTable entry {self.mt_entry.menu_item_str()}, mocking it.")
                self.emulator.hooks.mock_function(action_ptr, mock_default_action)


        SsmEmuHelper.hook_fn_read_from_ecu(self.rom_cfg, self.emulator)

        self.emulator.set_pc(self.rom_cfg.address_by_name("master_table_info_into_ram"))
        self.emulator.run_function_end(abort_pc=self.rom_cfg.address_by_name("master_table_main_loop"))
       