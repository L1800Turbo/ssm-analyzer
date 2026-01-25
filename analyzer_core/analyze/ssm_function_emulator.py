import logging
from pathlib import Path
from analyzer_core.config.memory_map import MemoryMap
from analyzer_core.config.rom_config import OFFSET_PIN_ASSIGNMENTS, RomConfig
from analyzer_core.config.ssm_model import CurrentSelectedDevice, MasterTableInfo, RomIdTableEntry_256kb, RomIdTableEntry_512kb, RomIdTableInfo
from analyzer_core.data.rom_image import RomImage
from analyzer_core.emu.asm_html_logger import AsmHtmlLogger
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.emu.memory_manager import MemoryManager
from analyzer_core.emu.ssm_emu_helper import SsmEmuHelper
from analyzer_core.ssm.master_table_analyzer import MasterTableAnalyzer
from analyzer_core.ssm.romid_table_analyzer import RomIdTableAnalyzer


# TODO: Diese ganze Klasse evtl weg und in Service integrieren?

logger = logging.getLogger(__name__)

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
        self.__execute_select_system_confirm_ecus()
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
            emulator = Emulator6303(rom_image=self.rom_image, rom_config=self.rom_cfg, current_device=current_device)
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
            emulator = Emulator6303(rom_image=self.rom_image, rom_config=self.rom_cfg, current_device=current_device)
            #self.add_default_hooks(emulator)
            emulator.set_pc(start_address)

            # Adjust offset for the current device
            #self.set_attached_rom_area(emulator.mem, current_device) TODO Warum noch kein error?

            # Set the current device in memory before running the function
            emulator.write8(current_selected_device_addr, current_device.value)

            emulator.run_function_end()

            # If there was never the RomID table value written, this selected device doesn't exist on the cassette
            # Otherwise add it to the possible ones

            # TODO Das reicht so nicht, in SELECT_SYSTEM wird bei svx97 ein AND 0x0F gemacht und ABS fliegt raus, heir wird er aber gesetzt
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

    def __execute_select_system_confirm_ecus(self):
        '''
        Attaching the offsets for ROM areas isn't enough to confirm if an ECU really exists.
        On SVX97, there will be a RomID table pointer created for ABS and TCS, but it is not present on the cassette.
        The SELECT SYSTEM function filters out non-existing ECUs
        '''
        def mock_default_action(em: Emulator6303):
            # Just return from the function
            em.mock_return()
        
        def mock_last_pushed_button_to_value(em: Emulator6303):
            em.flags.C = 0  # Clear carry to simulate a pressed button
            em.mock_return()

        current_selected_device_addr = self.rom_cfg.address_by_name('current_selected_device')

        confirmed_selectable_devices: list[CurrentSelectedDevice] = []

        for current_device in self.rom_cfg.selectable_devices:
            emulator = Emulator6303(rom_image=self.rom_image, rom_config=self.rom_cfg, current_device=current_device)
            emulator.set_pc(self.rom_cfg.address_by_name('select_system'))

            SsmEmuHelper.execute_default_mocks(self.rom_cfg, emulator)

            emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_upper_screen"), mock_default_action)
            emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_screen"), mock_default_action)
            emulator.hooks.mock_function(self.rom_cfg.address_by_name("attach_ssm_comm_type"), mock_default_action)
            emulator.hooks.mock_function(self.rom_cfg.address_by_name("last_pushed_button_to_value"), mock_last_pushed_button_to_value)

            # Set the current device in memory before running the function
            emulator.write8(current_selected_device_addr, current_device.value)

            emulator.run_function_end()

            # If the current device wasn't altered, it was accepted, if it was changed, e.g. to default (EGi),
            # it doesn't exist on the cassette
            final_device_value = emulator.read8(current_selected_device_addr)
            if final_device_value == current_device.value:
                confirmed_selectable_devices.append(current_device)

        self.rom_cfg.selectable_devices = confirmed_selectable_devices

    
    def __collect_romid_tables(self):
        '''
        Collects all RomID table information based on the RomIDs that were directly taken out of the ROM
        '''

        # Use RomIdTableAnalyzer / RomIdEntryAnalyzer for the per-device / per-entry work.
        for current_device in self.rom_cfg.selectable_devices:
            logger.debug(f"Collecting RomID tables for device {current_device.name}")
            current_table_info = self.rom_cfg.romid_tables[current_device]

            # Let separate emulation run for each ECU
            emulator = Emulator6303(rom_image=self.rom_image, rom_config=self.rom_cfg, current_device=current_device)
            #self.add_default_hooks(emulator)
            emulator.set_pc(self.rom_image.reset_vector())

            # Initialize a logger for asm instructions
            
            log_path = Path(f"logs/{self.rom_image.file_name}_{current_device.name}_asm_trace.html")
            asm_html_logger = AsmHtmlLogger(log_path, append=False)
            emulator.add_logger("html_logger", asm_html_logger.log)

            # Adjust offset for the current device (mapped ROM area)
            self.set_attached_rom_area(emulator.mem, current_device)

            # Create entries for current ECU and enrich them
            romid_tbl = RomIdTableAnalyzer(emulator, current_table_info, self.rom_cfg)
            romid_tbl.enrich_entries(self.rom_cfg, current_device)
            # master_table was created inside enrich_entries for each entry
