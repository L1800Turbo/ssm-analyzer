
# Some default hooks for SSM

from analyzer_core.config.rom_config import RomConfig
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.emu.memory_manager import MemoryManager

from analyzer_core.config.byte_interpreter import ByteInterpreter


class SsmEmuHelper:

    @classmethod
    def execute_default_mocks(cls, rom_cfg: RomConfig, em: Emulator6303):
        cls.mock_fn_wait_ms(rom_cfg, em)

    @classmethod
    def mock_fn_wait_ms(cls, rom_cfg: RomConfig, em: Emulator6303):

        def mock_wait_ms(em: Emulator6303):
            em.mock_return()

        em.hooks.mock_function(rom_cfg.address_by_name("wait_ms"), mock_wait_ms)


    @staticmethod
    def get_screen_line( rom_cfg: RomConfig, em: Emulator6303, var_name: str) -> str:
        # Collect printed data from screen buffer
        ssm_display_line_buf_ptr = rom_cfg.address_by_name(var_name)
        ssm_display_line_buf = em.mem.read_bytes(ssm_display_line_buf_ptr, 16)
        byte_interpreter = ByteInterpreter()
        return byte_interpreter.render(ssm_display_line_buf)
    
    @staticmethod
    def set_ssm_response_received_flag(rom_cfg:RomConfig, emulator: Emulator6303):
        """
        Set the response received flag to simulate a successful SSM communication.
        """
        emulator.mem.write(rom_cfg.address_by_name("response_received_flag"), 0x01)

    @staticmethod
    def hook_fn_read_from_ecu(rom_cfg: RomConfig, emulator: Emulator6303, write_cmds: list = [], ecu_addresses: set = set(), answer_value: int = 0x00):

        def hook_write_ssm_tx_bytes(addr: int, value: int, mem: MemoryManager):
            ssm_tx_bytes = mem.read_bytes(rom_cfg.address_by_name("ssm_tx_byte_0"), 4, allow_hooks=False)
            #print(f"SSM TX Bytes: {' '.join(f'{b:02X}' for b in ssm_tx_bytes)}", flush=True)

            # Simulate a good answer: e.g. 78 12 34 00 answer would be 12 34 nn
            ssm_rx_bytes_ptr = rom_cfg.address_by_name("ssm_rx_byte_0")
            mem.write(ssm_rx_bytes_ptr, ssm_tx_bytes[1])
            mem.write(ssm_rx_bytes_ptr+1, ssm_tx_bytes[2])
            mem.write(ssm_rx_bytes_ptr+2, answer_value)

            # Save it if needed outside hook
            write_cmds.append(ssm_tx_bytes)
            ecu_addresses.add((ssm_tx_bytes[1] << 8) | ssm_tx_bytes[2])

            #ssm_rx_bytes = mem.read_bytes(rom_cfg.address_by_name("ssm_rx_byte_0"), 3, allow_hooks=False)
            #print(f"hook_write_ssm_tx_bytes RX Bytes: {' '.join(f'{b:02X}' for b in ssm_rx_bytes)}", flush=True)

            # TODO landen hier auch die TX_bytes von den BARO.P usw?


        def hook_read_ssm_rx_bytes(add, value, mem: MemoryManager):
            ssm_rx_bytes = mem.read_bytes(rom_cfg.address_by_name("ssm_rx_byte_0"), 3, allow_hooks=False)
            print(f"hook_read_ssm_rx_bytes RX Bytes: {' '.join(f'{b:02X}' for b in ssm_rx_bytes)}", flush=True)


        def hook_pre_read_from_ecu(em: Emulator6303):
            em.hooks.add_write_hook(rom_cfg.address_by_name("ssm_tx_byte_3"), hook_write_ssm_tx_bytes)
            #em.hooks.add_read_hook(rom_cfg.address_by_name("ssm_rx_byte_0"), hook_read_ssm_rx_bytes)
        
        def hook_post_read_from_ecu(em: Emulator6303, access):
            em.hooks.remove_write_hook(rom_cfg.address_by_name("ssm_tx_byte_3"), hook_write_ssm_tx_bytes)
        
        emulator.hooks.add_pre_hook(rom_cfg.address_by_name("read_from_ecu"), hook_pre_read_from_ecu)
        emulator.hooks.add_post_hook(rom_cfg.address_by_name("read_from_ecu"), hook_post_read_from_ecu)
    

    
    # TODO: write_cmds und so geht nicht! hook_fn_read_from_ecu ist ja schon weiter oben...
    # Sollte wohl wieder zurück in die funktionen und nur der Mock selbst grobal?
    # @staticmethod
    # def mock_read_from_ecu_todo_weg(rom_cfg:RomConfig, emulator: Emulator6303, write_cmds: list = [], ecu_addresses: list = []):

    #     def hook_write_ssm_tx_bytes_in_read_ecu(addr: int, value: int, mem: MemoryManager):
    #         ssm_tx_bytes = mem.read_bytes(rom_cfg.address_by_name("ssm_tx_byte_0"), 4, allow_hooks=False)
    #         #print(f"SSM TX Bytes: {' '.join(f'{b:02X}' for b in ssm_tx_bytes)}", flush=True)

    #         # Simulate a good answer: e.g. 78 12 34 00 answer would be 12 34 nn
    #         ssm_rx_bytes_ptr = rom_cfg.address_by_name("ssm_rx_byte_0")
    #         mem.write(ssm_rx_bytes_ptr, ssm_tx_bytes[1])
    #         mem.write(ssm_rx_bytes_ptr+1, ssm_tx_bytes[2])
    #         mem.write(ssm_rx_bytes_ptr+2, 0x00)  # Dummy answer

    #         write_cmds.append(ssm_tx_bytes)

    #         #if self.mt_entry.action is None:
    #         #    raise RuntimeError("MasterTableEntry action datatype not set before saving READ_ADDRESS action results.")
    #         ecu_addresses.append((ssm_tx_bytes[1] << 8) | ssm_tx_bytes[2])

    #         # TODO landen hier auch die TX_bytes von den BARO.P usw?

    #         #ssm_rx_bytes = mem.read_bytes(self.rom_cfg.address_by_name("ssm_rx_byte_0"), 3, allow_hooks=False)
    #         #print(f"hook_write_ssm_tx_bytes RX Bytes: {' '.join(f'{b:02X}' for b in ssm_rx_bytes)}", flush=True)

    #     def hook_read_ssm_rx_bytes(addr: int, value: int, mem: MemoryManager):
    #         ssm_rx_bytes = mem.read_bytes(rom_cfg.address_by_name("ssm_rx_byte_0"), 3, allow_hooks=False)
    #         print(f"hook_read_ssm_rx_bytes RX Bytes: {' '.join(f'{b:02X}' for b in ssm_rx_bytes)}", flush=True)


    #     def hook_pre_read_from_ecu(em: Emulator6303):
    #         em.hooks.add_write_hook(rom_cfg.address_by_name("ssm_tx_byte_3"), hook_write_ssm_tx_bytes_in_read_ecu)
    #         # em.hooks.add_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_0"), hook_read_ssm_rx_bytes)
        
    #     def hook_post_read_from_ecu(em: Emulator6303, access):
    #         em.hooks.remove_write_hook(rom_cfg.address_by_name("ssm_tx_byte_3"), hook_write_ssm_tx_bytes_in_read_ecu)


    #     emulator.hooks.add_pre_hook(rom_cfg.address_by_name("read_from_ecu"), hook_pre_read_from_ecu)
    #     emulator.hooks.add_post_hook(rom_cfg.address_by_name("read_from_ecu"), hook_post_read_from_ecu)


    # TODO Weitere Standard-Hooks:
    # BEE3: clear_lower_ssm_screen
    # ... generell noch was von 903C ausgeht