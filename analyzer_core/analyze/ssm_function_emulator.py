import logging
from analyzer_core.config.rom_config import OFFSET_PIN_ASSIGNMENTS, RomConfig
from analyzer_core.config.ssm_model import CurrentSelectedDevice, RomIdTableInfo
from analyzer_core.data.rom_image import RomImage
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.emu.memory_manager import MemoryManager


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
            emulator = Emulator6303(rom_image=self.rom_image)
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

        for current_device in CurrentSelectedDevice:
            emulator = Emulator6303(rom_image=self.rom_image)
            emulator.set_pc(start_address)

            # Adjust offset
            self.set_attached_rom_area(emulator.mem, current_device)

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
                pointer_addr = emulator.read16(romid_table_pointer),
                # Size is alway maximum index +1 
                length = emulator.read8(romid_table_max_index) + 1,
                entries=[]
            )
    
    def __collect_romid_tables(self):
        '''
        Collects all RomID table information based on the RomIDs that were directly taken out of the ROM
        '''
        for current_device in self.rom_cfg.selectable_devices:
            current_table_info = self.rom_cfg.romid_tables[current_device]

            romid_tbl = RomIdTable(self.rom, current_table_info)

            # Get Master tables for current RomID
            # TODO Analyse von div. Funktionen erst noch erforderlich für RomID3 usw...!
            for current_romid in current_table_info.entries:
                # Let seperate emulation run for each current RomID
                emulator = PrimitiveHD6303Emulator(self.rom, dasm, self.rom_cfg, start_address=0xFFFF)

                current_selected_device = self.rom_config.address_by_name("current_selected_device")
                emulator.write8(current_selected_device, current_device.value)

                # Run function to collect all possible protocols and SSM command bytes
                current_romid.ssm_cmd_protocols = self.__execute_get_cmd_com_types(emulator, current_romid)

                # Let the process of preparing RomID command run, so that we get the SSM command and check for hard coded RomIDs.
                current_romid.request_romid_cmd = self.__execute_request_romid_save_romid(emulator, current_romid)

                # Save current RomID table pointer to memory, so that it can be used by other functions
                self.__execute_save_romid_table_to_memory(emulator, romid_tbl, current_romid)

                self.__execute_attach_cu_specific_addresses(emulator, current_device, current_romid)


                current_romid.master_table = MasterTable(
                    self.rom, 
                    MasterTableInfo(
                        self.rom_config.get_offset_value(current_device, current_romid.master_table_address_rel),
                        current_romid.entry_size, 
                        []
                        )
                    )


