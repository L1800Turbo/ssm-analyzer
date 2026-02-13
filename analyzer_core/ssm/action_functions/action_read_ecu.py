import logging
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import CurrentSelectedDevice, MasterTableEntry, RomIdTableEntryInfo
from analyzer_core.disasm.capstone_wrap import Disassembler630x
from analyzer_core.emu.memory_manager import MemoryManager
from analyzer_core.emu.ssm_emu_helper import SsmEmuHelper
from analyzer_core.ssm.action_functions.action_helper import SsmActionHelper
from analyzer_core.emu.emulator_6303 import Emulator6303


logging = logging.getLogger(__name__)


class SsmActionReadEcu(SsmActionHelper):
    """Handles action functions that read data from the ECU."""
    needs_scaling_fn = True

    def __init__(self, 
                 rom_cfg: RomConfig, 
                 emulator: Emulator6303, 
                 current_device: CurrentSelectedDevice, 
                 romid_entry: RomIdTableEntryInfo, 
                 mt_entry: MasterTableEntry) -> None:
        super().__init__(rom_cfg, emulator)
        self.current_device = current_device
        self.romid_entry = romid_entry
        self.mt_entry = mt_entry

        self.write_cmds = []

    def _add_function_mocks(self):

        def mock_skip_action(em: Emulator6303):
            # Just return from the function
            em.mock_return()

        # TODO write_cmds wird noch gar nicht benutzt?

        SsmEmuHelper.hook_fn_read_from_ecu(self.rom_cfg, self.emulator, self.write_cmds, self.mt_entry.action.ecu_addresses if self.mt_entry.action else set())
        # SsmEmuHelper.mock_read_from_ecu_todo_weg(self.rom_cfg, self.emulator, self.write_cmds, self.mt_entry.action.ecu_addresses if self.mt_entry.action else [])

        # We don't need the output now
        self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_upper_screen"), mock_skip_action)
        self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_screen"), mock_skip_action)

        # Indicate that a response has been received
        SsmEmuHelper.set_ssm_response_received_flag(self.rom_cfg, self.emulator)

    def run_post_actions(self):
        pass