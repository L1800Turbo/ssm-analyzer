from typing import Optional, List, Tuple
import logging

from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.config.rom_config import RomConfig, RomConfigError
from analyzer_core.config.ssm_model import RomEmulationError, RomIdTableEntry_512kb, CurrentSelectedDevice, RomIdTableInfo
from analyzer_core.emu.memory_manager import MemoryManager
from analyzer_core.emu.ssm_emu_helper import SsmEmuHelper

class RomIdEntryAnalyzer:
    """
    Hilfsklasse: analysiert / emuliert Verhalten für ein einzelnes RomId-Table-Entry.
    Erwartet einen bereits initialisierten Emulator (mit ggf. gesetztem mapped region).
    """

    def __init__(self, emulator: Emulator6303, rom_cfg: RomConfig, romid_table: RomIdTableInfo, entry: RomIdTableEntry_512kb):
        self.logger = logging.getLogger(__name__)

        self.romid_table = romid_table
        self.entry = entry
        self.emulator = emulator
        self.rom_cfg = rom_cfg
        

    def prepare_for_device(self, device: CurrentSelectedDevice) -> None:
        """Setzt das aktuelle Device-Byte in RAM, damit Funktionen sich richtig verhalten."""
        addr = self.rom_cfg.address_by_name("current_selected_device")
        self.emulator.write8(addr, device.value)

    def collect_cmd_protocols(self) -> None:
        """
        Fährt attach_ssm_comm_type (mit Hooks/Mocks) und liefert Liste (cmd, protocol).
        Entspricht dem bisherigen __execute_get_cmd_com_types.
        """
        rom_cfg = self.rom_cfg
        self.emulator = self.emulator

        attach_ssm_comm_type = rom_cfg.address_by_name("attach_ssm_comm_type")
        ssm_receive_status = rom_cfg.address_by_name('ssm_receive_status')
        current_ssm_cmd = rom_cfg.address_by_name("current_ssm_cmd")
        current_ssm_protocol_version = rom_cfg.address_by_name("current_ssm_protocol_version")
        no_success_on_first_connection_flag = rom_cfg.address_by_name("no_success_on_first_connection_flag")

        collected: List[Tuple[int,int]] = []

        self.emulator.set_pc(attach_ssm_comm_type)

        def hook_ssm_check_receive_status_set_error(addr:int, val:int, mem: MemoryManager):
            # Simulate error by clearing ssm_receive_status
            mem.write(self.rom_cfg.address_by_name('ssm_receive_status'), 0)

        # Mock the hardware relevant part executed in set_communication_protocol
        # Only take the current command and the protocol value
        def mock_set_communication_protocol(em: Emulator6303):
            collected.append((
                em.read8(current_ssm_cmd),
                em.read8(current_ssm_protocol_version)
            ))
            em.mock_return()

            # # TODO Quit-Mock-Funktion
            # # Just for a parameter in rts, rts wouldn't need it
            # insn = em.dasm.disassemble_step(em.PC)
            # if insn:
            #     em.rts(insn)
            # else:
            #     raise RuntimeError("Couldn't fetch instruction in mock_set_communication_protocol")


        self.emulator.hooks.add_read_hook(ssm_receive_status, hook_ssm_check_receive_status_set_error)
        self.emulator.write8(no_success_on_first_connection_flag, 0)
        self.emulator.hooks.mock_function(rom_cfg.address_by_name("set_communication_protocol"), mock_set_communication_protocol)
        
        SsmEmuHelper.execute_default_mocks(self.rom_cfg, self.emulator)

        self.emulator.run_function_end()

        #print(f"RomID {romid.romid0:02X} {romid.romid1:02X} {romid.romid2:02X} Command Protocols: {[(hex(cmd), hex(proto)) for cmd, proto in romid_cmd_protocols]}")

        # TODO: Hier muss aber noch geprüft werden, ob die Funktion wirklich zur RomID passt, das wird im ASM an anderer Stelle gemacht!

        # TODO clear mocks/hooks added here is left to caller or global lifecycle
        #return collected
        self.entry.ssm_cmd_protocols = collected

    def request_romid_and_capture(self, current_device: CurrentSelectedDevice) -> None:
        """
        Fährt request_romid_save_romid und versucht, dabei hard-coded RomID/ command zu erfassen.
        Liefert das zuletzt erfasste request_cmd tuple (4 bytes).
        Entspricht __execute_request_romid_save_romid (vereinfachte Übersetzung).
        """
        rom_cfg = self.rom_cfg
        self.current_request_romid_cmd = (0,0,0,0)

        self.logger.debug(f"Running request_romid_save_romid function for {self.entry.print_romid_str()}...")

        def hook_get_ssm_receive_status(addr:int, val:int, mem: MemoryManager):
            #Current RomID request command we received
            # print(f"{emulator.read8(self.rom_config.address_by_name('ssm_tx_byte_0')):02X} "
            #       f"{emulator.read8(self.rom_config.address_by_name('ssm_tx_byte_1')):02X} "
            #       f"{emulator.read8(self.rom_config.address_by_name('ssm_tx_byte_2')):02X}")

            # Also fake a receive status
            mem.write(rom_cfg.address_by_name('ssm_receive_status'), 0x05)

            self.current_request_romid_cmd = (
                mem.read(self.rom_cfg.address_by_name('ssm_tx_byte_0')),
                mem.read(self.rom_cfg.address_by_name('ssm_tx_byte_1')),
                mem.read(self.rom_cfg.address_by_name('ssm_tx_byte_2')),
                mem.read(self.rom_cfg.address_by_name('ssm_tx_byte_3'))
            )

            # Simulate the current RomID as "correct answer" if we're asked
            mem.write(self.rom_cfg.address_by_name('ssm_rx_byte_0'), self.entry.romid0)
            mem.write(self.rom_cfg.address_by_name('ssm_rx_byte_1'), self.entry.romid1)
            mem.write(self.rom_cfg.address_by_name('ssm_rx_byte_2'), self.entry.romid2)

        # We don't really want to search the RomID, we already know it. So just return.
        def mock_search_matching_romid(em: Emulator6303):
            em.mock_return()

            # search_matching_romid defines if it's an Axx RomID, set it manually
            if current_device == CurrentSelectedDevice.EGI and (self.entry.romid0 & 0xA0) == 0xA0:
                self.emulator.write8(rom_cfg.address_by_name('romid_EGi_Axxx_scheme'), 0x1)
            else:
                self.emulator.write8(rom_cfg.address_by_name('romid_EGi_Axxx_scheme'), 0x0)

            # AT Axx RomIDs don't exist before '97
            if rom_cfg.check_for_name('romid_AT_Axxx_scheme'):
                if current_device == CurrentSelectedDevice.AT and (self.entry.romid0 >> 8) == 0xA:
                    self.emulator.write8(rom_cfg.address_by_name('romid_AT_Axxx_scheme'), 0x1)
                else:
                    self.emulator.write8(rom_cfg.address_by_name('romid_AT_Axxx_scheme'), 0x0)
            
            # Copy RomID values, this usually also happens in search_matching_romid
            self.emulator.write8(rom_cfg.address_by_name('romid_0_2'), self.entry.romid0)
            self.emulator.write8(rom_cfg.address_by_name('romid_1_2'), self.entry.romid1)
            self.emulator.write8(rom_cfg.address_by_name('romid_2_2'), self.entry.romid2)


        # Get the right funktion pointer
        try:
            search_matching_romid_ptr = rom_cfg.address_by_name("search_matching_romid_96")
        except RomEmulationError:
            search_matching_romid_ptr = rom_cfg.address_by_name("search_matching_romid_97")

        if self.entry.ssm_cmd_protocols is None or len(self.entry.ssm_cmd_protocols) == 0:
            raise RomEmulationError(f"Can't request RomID for {self.entry.romid0:02X} {self.entry.romid1:02X} {self.entry.romid2:02X} without knowing SSM command and protocol!")

        # For multiple SSM commands and Protocols we have to run the function multiple times
        for ssm_cmd, ssm_protocol in self.entry.ssm_cmd_protocols:
            # Set the current SSM command and protocol in memory before running the function
            current_ssm_cmd = self.rom_cfg.address_by_name("current_ssm_cmd")
            current_ssm_protocol_version = self.rom_cfg.address_by_name("current_ssm_protocol_version")
            self.emulator.write8(current_ssm_cmd, ssm_cmd)
            self.emulator.write8(current_ssm_protocol_version, ssm_protocol)

            # Get the right funktion pointer
            try:
                search_matching_romid_ptr = self.rom_cfg.address_by_name("search_matching_romid_96")
            except RomEmulationError:
                search_matching_romid_ptr = self.rom_cfg.address_by_name("search_matching_romid_97")   

            # Reset the PC to the start of the function
            self.emulator.set_pc(self.rom_cfg.address_by_name("request_romid_save_romid"))

            # Set hooks and mocks
            self.emulator.hooks.add_read_hook(self.rom_cfg.address_by_name('ssm_receive_status'), hook_get_ssm_receive_status)
            self.emulator.hooks.mock_function(search_matching_romid_ptr, mock_search_matching_romid)

            self.emulator.run_function_end()

            # Get static and emulated RomID parts for comparison
            romid_parts = (self.entry.romid0, self.entry.romid1, self.entry.romid2)
            emulator_parts = (
                self.emulator.read8(self.rom_cfg.address_by_name('romid_0')),
                self.emulator.read8(self.rom_cfg.address_by_name('romid_1')),
                self.emulator.read8(self.rom_cfg.address_by_name('romid_2'))
            )

            # We let the code run through, so that we get any hard coded RomIDs.
            # If they differ, we dump this RomID combination
            if romid_parts != emulator_parts:
                # Take this protocol out of the list, it doesn't work
                self.entry.ssm_cmd_protocols.remove((ssm_cmd, ssm_protocol))

        self.entry.request_romid_cmd = self.current_request_romid_cmd


    def execute_set_current_romid_values(self) -> None:
        '''
        Mostly to have a proper working emulator: Save vars from current RomID table into respective memory locations
        '''

        # Set PC to function "set_current_romid_values"
        self.emulator.set_pc(self.rom_cfg.address_by_name("set_current_romid_values"))

        # Get pointer for this RomID in RomID List
        current_romid_line_pointer_addr = self.rom_cfg.address_by_name("current_romid_line_pointer")
        
        if self.entry.entry_ptr_address is None:
            raise RomEmulationError(f"No pointer address defined for RomID {self.entry.print_romid_str()}")
        self.emulator.write16(current_romid_line_pointer_addr, self.entry.entry_ptr_address)

        self.emulator.run_function_end()

    def run_attach_cu_specific_addresses(self) -> None:
        """
        Fährt attach_cu_specific_addresses und liest die diversen address-pointers zurück in das entry-Objekt.
        Entspricht __execute_attach_cu_specific_addresses.
        """
        rom_cfg = self.rom_cfg
        emu = self.emulator

        attach_addr = rom_cfg.address_by_name("attach_cu_specific_addresses")
        emu.set_pc(attach_addr)
        emu.run_function_end()

        # Read back configured addresses into the entry (if present in rom_cfg)
        def ra16(name):
            return emu.read16(rom_cfg.address_by_name(name))

        self.entry.max_length_menuitems = emu.read8(rom_cfg.address_by_name('max_length_menuitems_1'))
        self.entry.max_length_hidden_menuitems = emu.read8(rom_cfg.address_by_name('max_length_hidden_menuitems'))
        self.entry.temporary_menuitems_pointer = ra16('temporary_menuitems_pointer')
        self.entry.temporary_hidden_menuitems_pointer = ra16('possible_hidden_menuitems_pointer')
        self.entry.menuitems_upper_label_pointer = ra16('menuitems_upper_label_pointer')
        self.entry.menuitems_lower_label_pointer = ra16('menuitems_lower_label_pointer')
        self.entry.adjustments_label_pointer = ra16('adjustments_label_pointer')
        self.entry.current_scale_fn_table_pointer = ra16('current_scale_fn_table_pointer')
        self.entry.romid_upper_label_pointer = ra16('romid_upper_label_pointer')
        self.entry.romid_lower_label_pointer = ra16('romid_lower_label_pointer')

        # Called by subcall to set_maximum_menuitem_and_hidden_menuitem_indexes
        self.entry.final_menuitems_pointer = ra16('final_menuitems_pointer')

        # TODO noch last_visible_menuitem_index, kann man auch selbst sonst mit FF, bzw die Funktion set_current_pointer_possible_hidden_menuitems