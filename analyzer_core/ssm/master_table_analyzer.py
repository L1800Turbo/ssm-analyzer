from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import MasterTableEntry, MasterTableInfo, RomEmulationError, RomIdTableEntry_512kb
from analyzer_core.emu.emulator_6303 import Emulator6303


class MasterTableAnalyzer:
    '''
    Static analysis of SSM code to collect master table entries
    '''
    
    def __init__(self, emulator: Emulator6303, rom_cfg: RomConfig, romid_entry : RomIdTableEntry_512kb):
        self.__emulator = emulator
        self.__rom_cfg = rom_cfg
        self.__romid_entry = romid_entry


        #self.entries = self.__create_master_table()
    
    def __create_master_table(self):
        pass

    def collect_master_table_entries(self):
        
        master_table_ptr = self.__romid_entry.master_table_address_rel
        possible_items_ptr = self.__romid_entry.final_menuitems_pointer
        menuitems = self.__romid_entry.max_length_menuitems

        if master_table_ptr is None or possible_items_ptr is None or menuitems is None:
            raise RomEmulationError("Missing parameter")
        
        if self.__romid_entry.master_table is None:
            raise RomEmulationError("MasterTableAnalyzer needs defined RomIdTableEntry")
        
        entry_size = MasterTableEntry.entry_size
        
        for i in range(menuitems-1):
            current_mt_index = self.__emulator.mem.read(possible_items_ptr + i)

            # On FF we are finished with possible entries
            if current_mt_index == 0xFF:
                break
            elif current_mt_index > 0xFF:
                raise RomEmulationError(f"Invalid master table index: {current_mt_index:02X}")

            mt_entry_bytes = self.__emulator.mem.read_bytes(master_table_ptr + current_mt_index * entry_size, entry_size)

            entry = MasterTableEntry.from_bytes(mt_entry_bytes)
            self.__romid_entry.master_table.entries.append(entry)

