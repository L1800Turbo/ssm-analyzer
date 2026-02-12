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

        # def mock_skip_action(em: Emulator6303):
        #     # Just return from the function
        #     em.mock_return()

        # def hook_write_ssm_tx_bytes_in_read_ecu(addr: int, value: int, mem: MemoryManager):
        #     ssm_tx_bytes = mem.read_bytes(self.rom_cfg.address_by_name("ssm_tx_byte_0"), 4, allow_hooks=False)
        #     #print(f"SSM TX Bytes: {' '.join(f'{b:02X}' for b in ssm_tx_bytes)}", flush=True)

        #     # Simulate a good answer: e.g. 78 12 34 00 answer would be 12 34 nn
        #     ssm_rx_bytes_ptr = self.rom_cfg.address_by_name("ssm_rx_byte_0")
        #     mem.write(ssm_rx_bytes_ptr, ssm_tx_bytes[1])
        #     mem.write(ssm_rx_bytes_ptr+1, ssm_tx_bytes[2])
        #     mem.write(ssm_rx_bytes_ptr+2, 0x00)  # Dummy answer

        #     self.write_cmds.append(ssm_tx_bytes)

        #     if self.mt_entry.action is None:
        #         raise RuntimeError("MasterTableEntry action datatype not set before saving READ_ADDRESS action results.")
        #     self.mt_entry.action.ecu_addresses.append((ssm_tx_bytes[1] << 8) | ssm_tx_bytes[2])

        #     # TODO landen hier auch die TX_bytes von den BARO.P usw?

        #     #ssm_rx_bytes = mem.read_bytes(self.rom_cfg.address_by_name("ssm_rx_byte_0"), 3, allow_hooks=False)
        #     #print(f"hook_write_ssm_tx_bytes RX Bytes: {' '.join(f'{b:02X}' for b in ssm_rx_bytes)}", flush=True)

        # def hook_read_ssm_rx_bytes(addr: int, value: int, mem: MemoryManager):
        #     ssm_rx_bytes = mem.read_bytes(self.rom_cfg.address_by_name("ssm_rx_byte_0"), 3, allow_hooks=False)
        #     print(f"hook_read_ssm_rx_bytes RX Bytes: {' '.join(f'{b:02X}' for b in ssm_rx_bytes)}", flush=True)


        # def hook_pre_read_from_ecu(em: Emulator6303):
        #     em.hooks.add_write_hook(self.rom_cfg.address_by_name("ssm_tx_byte_3"), hook_write_ssm_tx_bytes_in_read_ecu)
        #     # em.hooks.add_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_0"), hook_read_ssm_rx_bytes)
        
        # def hook_post_read_from_ecu(em: Emulator6303, access):
        #     em.hooks.remove_write_hook(self.rom_cfg.address_by_name("ssm_tx_byte_3"), hook_write_ssm_tx_bytes_in_read_ecu)

        # self.emulator.hooks.add_pre_hook(self.rom_cfg.address_by_name("read_from_ecu"), hook_pre_read_from_ecu)
        # self.emulator.hooks.add_post_hook(self.rom_cfg.address_by_name("read_from_ecu"), hook_post_read_from_ecu)

        # # We don't need the output now
        # self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_upper_screen"), mock_skip_action)
        # self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_screen"), mock_skip_action)

        # # Indicate that a response has been received
        # SsmEmuHelper.set_ssm_response_received_flag(self.rom_cfg, self.emulator)

    def run_post_actions(self):
        pass