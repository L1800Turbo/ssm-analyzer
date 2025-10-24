import logging
from analyzer_core.config.memory_map import MemoryMap
from analyzer_core.config.rom_config import OFFSET_PIN_ASSIGNMENTS, RomConfig
from analyzer_core.config.ssm_model import CurrentSelectedDevice, MasterTableInfo, RomIdTableEntry_256kb, RomIdTableEntry_512kb, RomIdTableInfo
from analyzer_core.data.rom_image import RomImage
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.emu.memory_manager import MemoryManager
from analyzer_core.ssm.master_table_analyzer import MasterTableAnalyzer
from analyzer_core.ssm.romid_table_analyzer import RomIdTableAnalyzer



class SsmFunctionEmulator:
    '''
    Run SSM specific functions with matching hooks
    '''
    def __init__(self, rom_image:RomImage, rom_cfg:RomConfig) -> None:
        self.logger = logging.getLogger(__name__)

        self.rom_image = rom_image
        self.rom_cfg = rom_cfg

    def run_ssm_functions(self):
        self.__execute_offset_function()
        self.__execute_attach_romid_table_ptr()
        self.__collect_romid_tables()

    def set_attached_rom_area(self, mem:MemoryManager, dev: CurrentSelectedDevice):
        mem.set_mapped_region(self.rom_cfg.get_offset(dev))

    def __execute_offset_function(self):
        '''
        Analyze the function 'set_address_offsets' to determine the offset 
        values set based on port states.
        '''

        def get_p5_2(port5_value:int) -> int:
            return 0 if (port5_value & 0x04) == 0 else 1
        
        def get_p6_7(port6_value:int) -> int:
            return 0 if (port6_value & 0x80) == 0 else 1
        
        start_address = self.rom_cfg.address_by_name('set_address_offsets')

        port_5_addr = self.rom_cfg.address_by_name('PORT5')
        port_6_addr = self.rom_cfg.address_by_name('PORT6')

        # Set for current selected device
        current_selected_device_addr = self.rom_cfg.address_by_name('current_selected_device')

        # Loop over all thinkable (not yet known if possible) ECU types 
        for current_device in CurrentSelectedDevice:

            # Initialize an emulator seperately for each run
            emulator = Emulator6303(rom_image=self.rom_image, rom_config=self.rom_cfg)
            emulator.set_pc(start_address)

            # Initial state
            emulator.write8(port_5_addr, 0xFF)
            emulator.write8(port_6_addr, 0xFF)
            
            # Set the current device in memory before running the function
            emulator.write8(current_selected_device_addr, current_device.value)

            emulator.run_function_end()

            # Loop over all known offset pin assignments to find a match
            for assignment in OFFSET_PIN_ASSIGNMENTS:
                if get_p5_2(emulator.read8(port_5_addr)) == assignment['p5_2'] and \
                   get_p6_7(emulator.read8(port_6_addr)) == assignment['p6_7']:
                      self.rom_cfg.add_offset(current_device, assignment['offset'])
                      
                      self.logger.debug(f"Detected offset for device {current_device.name} "
                                        f"(0x{current_device.value:02X}): 0x{assignment['offset']:04X}")
                      break
        
                
    def __execute_attach_romid_table_ptr(self):

        start_address = self.rom_cfg.address_by_name('attach_romid_table_ptr')

        romid_table_pointer = self.rom_cfg.address_by_name('romid_table_ptr')
        romid_table_max_index = self.rom_cfg.address_by_name('romid_table_max_index')
        current_selected_device_addr = self.rom_cfg.address_by_name('current_selected_device')

        # Take every device posibility, find out if they actually exist
        for current_device in CurrentSelectedDevice:
            emulator = Emulator6303(rom_image=self.rom_image, rom_config=self.rom_cfg)
            emulator.set_pc(start_address)

            # Adjust offset for the current device
            #self.set_attached_rom_area(emulator.mem, current_device) TODO Warum noch kein error?

            # Set the current device in memory before running the function
            emulator.write8(current_selected_device_addr, current_device.value)

            emulator.run_function_end()

            # If there was never the RomID table value written, this selected device doesn't exist on the cassette
            # Otherwise add it to the possible ones
            if romid_table_pointer in emulator.mem.get_written_memory_addresses():
                self.rom_cfg.selectable_devices.append(current_device)
            else:
                continue

            # Take the offset for the current device
            self.rom_cfg.romid_tables[current_device] = RomIdTableInfo(
                relative_pointer_addr = emulator.read16(romid_table_pointer),
                # Size is alway maximum index +1 
                length = emulator.read8(romid_table_max_index) + 1,
                entries=[]
            )
    
    def __collect_romid_tables(self):
        '''
        Collects all RomID table information based on the RomIDs that were directly taken out of the ROM
        '''

        # for current_device in self.rom_cfg.selectable_devices:
        #     current_table_info = self.rom_cfg.romid_tables[current_device]

        #     # Let seperate emulation run for each ECU
        #     emulator = Emulator6303(rom_image=self.rom_image)
        #     emulator.set_pc(0xFFFF)

        #     # Adjust offset for the current device
        #     self.set_attached_rom_area(emulator.mem, current_device)

        #     # Create entries for current ECU
        #     romid_tbl = RomIdTableAnalyzer(emulator, current_table_info)

        #     # Get Master tables for current RomID
        #     # TODO Analyse von div. Funktionen erst noch erforderlich für RomID3 usw...!
        #     for current_romid in romid_tbl.table.entries:

        #         emulator.write8(self.rom_cfg.address_by_name("current_selected_device"), current_device.value)

        #         if isinstance(current_romid, RomIdTableEntry_256kb):
        #             raise NotImplementedError("Noch kein 256kb ROM")

        #         # Run function to collect all possible protocols and SSM command bytes
        #         current_romid.ssm_cmd_protocols = self.__execute_get_cmd_com_types(emulator, current_romid)

        #         # Let the process of preparing RomID command run, so that we get the SSM command and check for hard coded RomIDs.
        #         current_romid.request_romid_cmd = self.__execute_request_romid_save_romid(emulator, current_romid)

        #         # # Save current RomID table pointer to memory, so that it can be used by other functions
        #         self.__execute_save_romid_table_to_memory(emulator, romid_tbl, current_romid)

        #         # TODO hier ? 81A6 : BD 8B 0E 	"   "		jsr	get_RomID_Flagbytes

        #         self.__execute_attach_cu_specific_addresses(emulator, current_device, current_romid)


        #         # TODO: Mastertable-Adresse schreiben 81D4 : DE 85 		"  "		ldx	current_mastertable_address_h
        #         # Versuch, es ohne zu machen...

        #         current_romid.master_table = MasterTableAnalyzer(
        #             emulator, 
        #             MasterTableInfo(
        #                 current_romid.master_table_address_rel,
        #                 current_romid.entry_size, 
        #                 []
        #                 )
        #              )

        # Use RomIdTableAnalyzer / RomIdEntryAnalyzer for the per-device / per-entry work.
        for current_device in self.rom_cfg.selectable_devices:
            current_table_info = self.rom_cfg.romid_tables[current_device]

            # Let separate emulation run for each ECU
            emulator = Emulator6303(rom_image=self.rom_image, rom_config=self.rom_cfg)
            emulator.set_pc(0xFFFF)

            # Adjust offset for the current device (mapped ROM area)
            self.set_attached_rom_area(emulator.mem, current_device)

            # Create entries for current ECU and enrich them
            romid_tbl = RomIdTableAnalyzer(emulator, current_table_info, self.rom_cfg)
            romid_tbl.enrich_entries(self.rom_cfg, current_device)
            # master_table was created inside enrich_entries for each entry
               




    
    # def __execute_get_cmd_com_types(self, emulator:Emulator6303, romid:RomIdTableEntry_512kb) -> list[tuple[int,int]]:

    #     self.logger.debug(f"Running attach_ssm_comm_type function for RomID {romid.romid0:02X} {romid.romid1:02X} {romid.romid2:02X}...")

    #     romid_cmd_protocols: list[tuple[int,int]] = []

    #     attach_ssm_comm_type = self.rom_cfg.address_by_name("attach_ssm_comm_type")
    #     ssm_receive_status = self.rom_cfg.address_by_name('ssm_receive_status')
    #     current_ssm_cmd = self.rom_cfg.address_by_name("current_ssm_cmd")
    #     current_ssm_protocol_version = self.rom_cfg.address_by_name("current_ssm_protocol_version")
    #     no_success_on_first_connection_flag = self.rom_cfg.address_by_name("no_success_on_first_connection_flag")

    #     emulator.set_pc(attach_ssm_comm_type)

    #     def hook_ssm_check_receive_status(addr:int, val:int):
    #         # Simulate error by clearing ssm_receive_status
    #         emulator.write8(ssm_receive_status, 0)

    #     # Mock the hardware relevant part executed in set_communication_protocol
    #     # Only take the current command and the protocol value
    #     def mock_set_communication_protocol(emulator: Emulator6303):
    #         romid_cmd_protocols.append((
    #             emulator.read8(current_ssm_cmd),
    #             emulator.read8(current_ssm_protocol_version)
    #         ))

    #         # TODO Quit-Mock-Funktion
    #         # Just for a parameter in rts, rts wouldn't need it
    #         insn = emulator.dasm.disassemble_step(emulator.PC)
    #         if insn:
    #             emulator.rts(insn)
    #         else:
    #             raise RuntimeError("Couldn't fetch set_communication_protocol instruction")
        
    #     # Simply ignore wait_ms function
    #     def mock_wait_ms(emulator: Emulator6303):
    #         insn = emulator.dasm.disassemble_step(emulator.PC)
    #         if insn:
    #             emulator.rts(insn)
    #         else:
    #             raise RuntimeError("Couldn't fetch set_communication_protocol instruction")
        
    #     emulator.hooks.add_read_hook(ssm_receive_status, hook_ssm_check_receive_status)

    #     # Init flag for unsuccessful first connection with 0
    #     emulator.write8(no_success_on_first_connection_flag, 0)

    #     emulator.hooks.mock_function(self.rom_cfg.address_by_name("set_communication_protocol"), mock_set_communication_protocol)
    #     emulator.hooks.mock_function(self.rom_cfg.address_by_name("wait_ms"), mock_wait_ms)

    #     emulator.run_function_end()


    #     #print(f"RomID {romid.romid0:02X} {romid.romid1:02X} {romid.romid2:02X} Command Protocols: {[(hex(cmd), hex(proto)) for cmd, proto in romid_cmd_protocols]}")

    #     # TODO: Hier muss aber noch geprüft werden, ob die Funktion wirklich zur RomID passt, das wird im ASM an anderer Stelle gemacht!
        
    #     return romid_cmd_protocols

    # def __execute_request_romid_save_romid(self, emulator: Emulator6303, romid:RomIdTableEntry_512kb): # TODO 256kb
    #     '''
    #     Run the function request_romid_save_romid from ROM to simulate the process of requesting the RomID.
    #     Here, we'll just insert our current RomID from the list. This will provide hard coded "fake" RomIDs like for CruiseControl which can be checked later on
    #     '''

    #     self.logger.debug(f"Running request_romid_save_romid function for {romid.romid0:02X} {romid.romid1:02X} {romid.romid2:02X}...")

    #     self.current_request_romid_cmd = (0,0,0,0)
        
    #     def hook_get_ssm_receive_status(addr:int, val:int):

    #         # Current RomID request command we received
    #         # print(f"{emulator.read8(self.rom_config.address_by_name('ssm_tx_byte_0')):02X} "
    #         #       f"{emulator.read8(self.rom_config.address_by_name('ssm_tx_byte_1')):02X} "
    #         #       f"{emulator.read8(self.rom_config.address_by_name('ssm_tx_byte_2')):02X}")
            
    #         self.current_request_romid_cmd = (emulator.read8(self.rom_cfg.address_by_name('ssm_tx_byte_0')),
    #                              emulator.read8(self.rom_cfg.address_by_name('ssm_tx_byte_1')),
    #                              emulator.read8(self.rom_cfg.address_by_name('ssm_tx_byte_2')),
    #                              emulator.read8(self.rom_cfg.address_by_name('ssm_tx_byte_3')))

    #         # Simulate the current RomID as "correct answer" if we're asked
    #         emulator.write8(self.rom_cfg.address_by_name('ssm_rx_byte_0'), romid.romid0)
    #         emulator.write8(self.rom_cfg.address_by_name('ssm_rx_byte_1'), romid.romid1)
    #         emulator.write8(self.rom_cfg.address_by_name('ssm_rx_byte_2'), romid.romid2)


        
    #     def mock_search_matching_romid_96(emulator:Emulator6303):
    #         '''
    #         We don't really want to search the RomID, we already know it. So just return.
    #         '''
    #         insn = emulator.dasm.disassemble_step(emulator.PC)
    #         if not insn: raise RuntimeError("Couldn't fetch mock_search_matching_romid_96 instruction")
    #         # Flag that we found a matching RomID
    #         emulator.clc(insn)
    #         emulator.rts(insn)


    #     if romid.ssm_cmd_protocols is None or len(romid.ssm_cmd_protocols) == 0:
    #         raise RomEmulationError(f"Can't request RomID for {romid.romid0:02X} {romid.romid1:02X} {romid.romid2:02X} without knowing SSM command and protocol!")

    #     # For multiple SSM commands and Protocols we have to run the function multiple times
    #     for ssm_cmd, ssm_protocol in romid.ssm_cmd_protocols:
    #         # Set the current SSM command and protocol in memory before running the function
    #         current_ssm_cmd = self.rom_cfg.address_by_name("current_ssm_cmd")
    #         current_ssm_protocol_version = self.rom_cfg.address_by_name("current_ssm_protocol_version")
    #         emulator.write8(current_ssm_cmd, ssm_cmd)
    #         emulator.write8(current_ssm_protocol_version, ssm_protocol)

    #         # Get the right funktion pointer
    #         try:
    #             search_matching_romid_ptr = self.rom_cfg.address_by_name("search_matching_romid_96")
    #         except RomEmulationError:
    #             search_matching_romid_ptr = self.rom_cfg.address_by_name("search_matching_romid_97")   

    #         # Reset the PC to the start of the function
    #         emulator.set_pc(self.rom_cfg.address_by_name("request_romid_save_romid"))
    #         emulator.hooks.add_read_hook(self.rom_cfg.address_by_name('ssm_receive_status'), hook_get_ssm_receive_status)
    #         emulator.hooks.mock_function(search_matching_romid_ptr, mock_search_matching_romid_96)

    #         emulator.run_function_end()

    #         # Vergleiche die 3 RomID-Teile und gebe eine Nachricht, wenn sie nicht übereinstimmen
    #         romid_parts = (romid.romid0, romid.romid1, romid.romid2)
    #         emulator_parts = (
    #             emulator.read8(self.rom_cfg.address_by_name('romid_0')),
    #             emulator.read8(self.rom_cfg.address_by_name('romid_1')),
    #             emulator.read8(self.rom_cfg.address_by_name('romid_2'))
    #         )

    #         # We let the code run through, so that we get any hard coded RomIDs.
    #         # If they differ, we dump this RomID combination
    #         if romid_parts != emulator_parts:
    #             # Take this protocol out of the list, it doesn't work
    #             romid.ssm_cmd_protocols.remove((ssm_cmd, ssm_protocol))
            

    #     return self.current_request_romid_cmd

    # def __execute_save_romid_table_to_memory(self, emulator: Emulator6303, romid_tbl: RomIdTableAnalyzer, current_romid: RomIdTableEntry_512kb):
    #     '''
    #     Mostly to have a proper working emulator: Save vars from current RomID table into respective memory locations
    #     '''
    #     set_current_romid_values = self.rom_cfg.address_by_name("set_current_romid_values")
    #     emulator.set_pc(set_current_romid_values)

    #     # Get pointer for this RomID in RomID List
    #     current_romid_line_pointer_addr = self.rom_cfg.address_by_name("current_romid_line_pointer")
    #     current_romid_line_pointer = romid_tbl.get_table_pointer_by_romid(current_romid.romid0, current_romid.romid1, current_romid.romid2)
    #     emulator.write16(current_romid_line_pointer_addr, current_romid_line_pointer)

    #     emulator.run_function_end()

    
    # def __execute_attach_cu_specific_addresses(self, 
    #                                            emulator: Emulator6303, 
    #                                            current_device:CurrentSelectedDevice, 
    #                                            current_romid: RomIdTableEntry_512kb):
    #     '''
    #     Run the function attach_cu_specific_addresses to get the number of menu items and label pointer, ...
    #     '''
    #     attach_cu_specific_addresses = self.rom_cfg.address_by_name("attach_cu_specific_addresses")
    #     emulator.set_pc(attach_cu_specific_addresses)

    #     emulator.run_function_end()

    #     current_romid.max_length_menuitems = emulator.read8(
    #         self.rom_cfg.address_by_name('max_length_menuitems_1'))
        
    #     current_romid.max_length_hidden_menuitems = emulator.read8(
    #         self.rom_cfg.address_by_name('max_length_hidden_menuitems'))
        
    #     current_romid.temporary_menuitems_pointer = emulator.read16(self.rom_cfg.address_by_name('temporary_menuitems_pointer'))
    #     current_romid.temporary_hidden_menuitems_pointer = emulator.read16(self.rom_cfg.address_by_name('possible_hidden_menuitems_pointer'))
    #     current_romid.menuitems_upper_label_pointer = emulator.read16(self.rom_cfg.address_by_name('menuitems_upper_label_pointer'))
    #     current_romid.menuitems_lower_label_pointer = emulator.read16(self.rom_cfg.address_by_name('menuitems_lower_label_pointer'))
    #     current_romid.adjustments_label_pointer = emulator.read16(self.rom_cfg.address_by_name('adjustments_label_pointer'))
    #     current_romid.current_scale_table_pointer = emulator.read16(self.rom_cfg.address_by_name('current_scale_table_pointer'))
    #     current_romid.romid_upper_label_pointer = emulator.read16(self.rom_cfg.address_by_name('romid_upper_label_pointer'))
    #     current_romid.romid_lower_label_pointer = emulator.read16(self.rom_cfg.address_by_name('romid_lower_label_pointer'))

        # TODO noch finalen Menuitems-Pointer, evtl last_visible_menuitem_index, kann man auch selbst sonst mit FF