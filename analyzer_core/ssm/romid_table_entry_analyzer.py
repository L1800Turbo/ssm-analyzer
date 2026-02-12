from typing import Optional, List, Tuple
import logging

from analyzer_core.analyze.instruction_parser import CalcInstructionParser
from analyzer_core.disasm.insn_model import Instruction
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.config.rom_config import RomConfig, RomConfigError
from analyzer_core.config.ssm_model import RomEmulationError, RomIdTableEntryInfo, RomIdTableEntryRaw8, RomIdTableEntryRaw12, CurrentSelectedDevice, RomIdTableInfo
from analyzer_core.emu.memory_manager import MemoryManager
from analyzer_core.emu.ssm_emu_helper import SsmEmuHelper
from analyzer_core.emu.tracing import MemAccess

logger = logging.getLogger(__name__)

class RomIdEntryAnalyzer:
    """
    Hilfsklasse: analysiert / emuliert Verhalten für ein einzelnes RomId-Table-Entry.
    Erwartet einen bereits initialisierten Emulator (mit ggf. gesetztem mapped region).
    """

    def __init__(self, emulator: Emulator6303, rom_cfg: RomConfig, romid_table: RomIdTableInfo, entry: RomIdTableEntryInfo) -> None:

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

        self.emulator.hooks.clear_hooks_and_mocks()

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
        Run request_romid_save_romid to capture hardcoded RomID / command values.
        """
        rom_cfg = self.rom_cfg
        self.current_request_romid_cmd = (0,0,0,0)

        logger.debug(f"Running request_romid_save_romid function for {self.entry.print_romid_str()}...")

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
        
        def hook_set_current_romid_line_pointer(addr:int, val:int, mem: MemoryManager):
            # Just for debugging, to see when the RomID line pointer is set during the function
            set_romid_line_pointer = int.from_bytes(mem.read_bytes(self.rom_cfg.address_by_name('current_romid_line_pointer'),2), 'big')
            logger.debug(f"current_romid_line_pointer set to {set_romid_line_pointer:04X} during request_romid_save_romid for RomID {self.entry.print_romid_str()}")

            if(set_romid_line_pointer != self.entry.entry_ptr_address):
                logger.debug(f"current_romid_line_pointer set for RomID {self.entry.print_romid_str()} during request_romid_save_romid, "
                             f"expected was {self.entry.entry_ptr_address:04X}, set value is {set_romid_line_pointer:04X}!")

        def test_ssm_protocol(ssm_cmd, ssm_protocol):
            # Set the current SSM command and protocol in memory before running the function
            current_ssm_cmd = self.rom_cfg.address_by_name("current_ssm_cmd")
            current_ssm_protocol_version = self.rom_cfg.address_by_name("current_ssm_protocol_version")
            self.emulator.write8(current_ssm_cmd, ssm_cmd)
            self.emulator.write8(current_ssm_protocol_version, ssm_protocol)

            # Reset the PC to the start of the function
            self.emulator.set_pc(self.rom_cfg.address_by_name("request_romid_save_romid"))

            # Set hooks and mocks
            self.emulator.hooks.add_read_hook(self.rom_cfg.address_by_name('ssm_receive_status'), hook_get_ssm_receive_status)

            # Hook when the line pointer is being written, take +1 as it's 16bit and we want to see the final value
            self.emulator.hooks.add_write_hook(self.rom_cfg.address_by_name('current_romid_line_pointer')+1, hook_set_current_romid_line_pointer)

            self.emulator.run_function_end()


        if self.entry.ssm_cmd_protocols is None or len(self.entry.ssm_cmd_protocols) == 0:
            raise RomEmulationError(f"Can't request RomID for {self.entry.romid0:02X} {self.entry.romid1:02X} {self.entry.romid2:02X} without knowing SSM command and protocol!")

        # For multiple SSM commands and Protocols we have to run the function multiple times
        for ssm_cmd, ssm_protocol in self.entry.ssm_cmd_protocols:
            test_ssm_protocol(ssm_cmd, ssm_protocol)

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
                # Take this protocol out of the list, it doesn't work, but keep the last one
                if len(self.entry.ssm_cmd_protocols) > 1:
                    # TODO Rauslöschen von indizies innerhalb der Schleife -> anpassen, damit es nicht zu Problemen kommt
                    self.entry.ssm_cmd_protocols.remove((ssm_cmd, ssm_protocol))
                else:
                    logger.warning(f"SSM command and protocol combination for RomID {self.entry.print_romid_str()} doesn't seem to work: "
                                   f"got RomID {emulator_parts[0]:02X} {emulator_parts[1]:02X} {emulator_parts[2]:02X}, "
                                   f"expected was {romid_parts[0]:02X} {romid_parts[1]:02X} {romid_parts[2]:02X}. Keeping this combination for now.")
        
        if len(self.entry.ssm_cmd_protocols) > 1:
            logger.warning(f"Multiple SSM command and protocol combinations found for RomID {self.entry.print_romid_str()}: "
                           f"{[(hex(cmd), hex(proto)) for cmd, proto in self.entry.ssm_cmd_protocols]}, but handling this is not implemented yet!")
        
        # After testing all protocols including the wrong ones, we should run one time with a working protocol to adjust the memory
        test_ssm_protocol(self.entry.ssm_cmd_protocols[0][0], self.entry.ssm_cmd_protocols[0][1])

        self.entry.request_romid_cmd = self.current_request_romid_cmd


    def execute_set_current_romid_values(self) -> None:
        '''
        Mostly to have a proper working emulator: Save vars from current RomID table into respective memory locations
        '''

        def emulate_set_current_romid_values(read_addr, value) -> None:
            # Clear previous hooks/mocks
            self.emulator.hooks.clear_hooks_and_mocks()
            SsmEmuHelper.execute_default_mocks(self.rom_cfg, self.emulator)

            #SsmEmuHelper.mock_read_from_ecu_todo_weg(self.rom_cfg, self.emulator, ecu_addresses=read_adresses) # TODO auch Adressen als pointer rein
            SsmEmuHelper.hook_fn_read_from_ecu(self.rom_cfg, self.emulator, ecu_addresses=read_addr, answer_value=value) 

            # TODO er darf nicht die Pointer adresse hier nehmen, weil er die noch im Code manipulieren soll!!
            # an welcher Steller wird der Pointer normal gesetztz?!?

            #assert self.entry.entry_ptr_address is not None # as it's called only when defined
            #self.emulator.write16(current_romid_line_pointer_addr, self.entry.entry_ptr_address)

            # Set PC to function "set_current_romid_values"
            self.emulator.set_pc(self.rom_cfg.address_by_name("set_current_romid_values"))

            self.emulator.run_function_end()


        # Get pointer for this RomID in RomID List
        current_romid_line_pointer_addr = self.rom_cfg.address_by_name("current_romid_line_pointer")
        if self.entry.entry_ptr_address is None:
            raise RomEmulationError(f"No pointer address defined for RomID {self.entry.print_romid_str()}")
        
        current_romid_line_pointer_value = self.emulator.read16(current_romid_line_pointer_addr)
        if current_romid_line_pointer_value != self.entry.entry_ptr_address:
            logger.debug(f"Before executing set_current_romid_values, current_romid_line_pointer is {current_romid_line_pointer_value:04X}, expected is {self.entry.entry_ptr_address:04X} for RomID {self.entry.print_romid_str()}!")
        
        read_addresses: set[int] = set()
        
        emulate_set_current_romid_values(read_addresses, 0x00)

        # If there were read addresses during RomID setup, we need to analyze them as they influence which RomID table is selected
        if len(read_addresses) == 1:
            logger.warning(f"execute_set_current_romid_values: read addresses during RomID setup: {[hex(addr) for addr in read_addresses]}")
            # TODO hier etwas mit den Adressen machen, bsp SVX96: es gibt 2x AC-Tabellen mit einer RomID, die aber ein bit an 0x0015 auslesen und avon abhängig machen, welche Tabelle genutzt wird.
            # TODO Struktur ermitteln, die dann gleiche RomIDs ermöglicht, ist ja letztlich nur eine Liste, aber es fehlt dann ein bestimmtdes Flag in der Definition

            # TODO: hier unten: das passt noch nicht mit den parser. Der muss ja irgendwei die abhängigkeiten der RomID-Tabelle erkennen
            # aber wo wird den das Sammeln der RoMID tabellen gemacht? Das muss ja irgndwie abgeglichen werden
            # RomID-Tabellen werden fix gebaut, aber man könnte dort dann ja die Bedingung anhängen, wnen der Start passt?


            

            # auf current_romid_line_pointer prüfen, wenn der gleich ist -> Bedingung anhängen?
            # aber mit welchem Wert -> zuerst 0, dann die anderen Bedingunen?

            # TODO die z.B. 0015 müsste man dann ja auch später beio den Scalings setzen, wenn das in der RomID-Tabelle steht



        
            ssm_inputs: List[int] = [0] 
            seen_samples: set[int] = set()

            instr_parser = CalcInstructionParser(self.rom_cfg, self.emulator, read_addresses=[self.rom_cfg.address_by_name("ssm_rx_byte_2")])

            def trace_rx_value_calculation(instr: Instruction, access: MemAccess):
                instr_parser.do_step(instr, access)
            
            matching_romid_found = False

            while ssm_inputs:
                rx_test_value = ssm_inputs.pop(0)
                seen_samples.add(rx_test_value)

                self.emulator.add_logger("set_current_romid_values_logger", trace_rx_value_calculation)
                instr_parser.init_new_instruction()

                emulate_set_current_romid_values(read_addresses, rx_test_value)

                self.emulator.remove_logger("set_current_romid_values_logger")

                # Get jump conditions from guards to find new test inputs
                for value in instr_parser.solve_jump_conditions():
                    if value not in seen_samples and value not in ssm_inputs:
                        ssm_inputs.append(value)

                # Compare current RomID entry with emulated memory state
                if not self._compare_romid_entry_with_emulated(self.entry, self.emulator.mem):
                    continue  # RomID entry doesn't match, try next input value

                if matching_romid_found:
                    raise RomEmulationError(f"Multiple matching RomID tables found for RomID {self.entry.print_romid_str()} with different read address values during set_current_romid_values: {[hex(addr) for addr in read_addresses]}")
                
                matching_romid_found = True
                self.entry.romid_identifier_value = (read_addresses.pop(), rx_test_value)
                # We must not do further testing here as the values in the ROM do match now. Otherwise we would need a second run to get this value
                break 


                # TODO Linepointer ist quatsch -> das wird nur auf X aufgerechnet und dann direkt geladen
                # wir müssen die aktuellen RomID-Tabelleninhalte vergleichen

                # TODO und false zur+ück geben, wenn wir feststellen, dass wir nicht die richtige RomID-Tabelle haben? Werden ja sowieso alle durchlaufen
            
            if not matching_romid_found:
                raise RomEmulationError(f"Couldn't find matching RomID table for RomID {self.entry.print_romid_str()} with any read address value during set_current_romid_values: {[hex(addr) for addr in read_addresses]}")
            
            # Finally, force the pointer from the RomID entry
            #self.emulator.write16(current_romid_line_pointer_addr, self.entry.entry_ptr_address)
            
        elif len(read_addresses) > 1:
            raise NotImplementedError("Handling of multiple read addresses during RomID setup not implemented yet.")
        
            
            # TODO conditional romid tabelle ergänzen, jetzt kommen ja mehrere mastertabellen



    
            # erst als test nur


            # def hook_pre_scaling_function(em: Emulator6303):
            #     #logger.debug(f"hook_pre_scaling_function at {self.scaling_fn_ptr:04X}")
            #     # TEST 28.11. self.emulator.hooks.add_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_2"), hook_read_ssm_rx_bytes_in_scaling_fn)
            #     self.emulator.add_logger("scaling_fn_ssm_rx_logger", trace_rx_value_calculation)
            
            # def hook_post_scaling_function(em: Emulator6303, access):
            #     #print(f"hook_post_scaling_function at {self.scaling_fn_ptr:04X}", flush=True)
            #     # TEST 28.11. self.emulator.hooks.remove_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_2"), hook_read_ssm_rx_bytes_in_scaling_fn)

            # self.emulator.hooks.add_pre_hook(self.emulator.PC, hook_pre_scaling_function)
            # self.emulator.hooks.add_post_hook(self.emulator.PC, hook_post_scaling_function)

            
    def _compare_romid_entry_with_emulated(self, romid_entry: RomIdTableEntryInfo, memory: MemoryManager) -> bool:
        '''
        Compare all relevant fields of the RomID table entry with the emulated memory state.
        '''

        if isinstance(romid_entry, RomIdTableEntryRaw8):
            raise NotImplementedError("Comparison for RomIdTableEntry_256kb not implemented yet.")

        # Mapping: (Attributname im Entry, RAM-Name, Lesefunktion)
        fields = [
            (romid_entry.romid0, 'romid_0', 1),
            (romid_entry.romid1, 'romid_1', 1),
            (romid_entry.romid2, 'romid_2', 1),
            (romid_entry.scaling_index, 'current_romid_scaling_index', 1),
            (romid_entry.label_index, 'current_romid_label_index', 1),
            (romid_entry.menuitems_index, 'current_romid_menuitems_index', 1),
            (romid_entry.master_table_address_rel, 'current_romid_mastertable_address', 2),
            #(romid_entry.romid_a, 'current_romid_a', 1),
            #(romid_entry.tbd_b, 'current_romid_b', 1),
            #(romid_entry.romid_model_index, 'current_romid_model_index', 1),
            #(romid_entry.flagbytes, 'current_romid_flagcmd', 1),
        ]

        for romid_attr, ram_name, var_len in fields:
            ram_addr = self.rom_cfg.address_by_name(ram_name)
            ram_val = int.from_bytes(memory.read_bytes(ram_addr, var_len), byteorder='big')
            if romid_attr != ram_val:
                return False
        return True
            

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