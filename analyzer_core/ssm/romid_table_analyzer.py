
from analyzer_core.config.ssm_model import RomIdTableEntry_512kb, RomIdTableInfo
from analyzer_core.emu.memory_manager import MemoryManager


class RomIdNotFoundError(Exception):
    pass

class RomIdTableAnalyzer(RomIdTableInfo):

    def __init__(self, mem: MemoryManager, table_info:RomIdTableInfo) -> None:
        self.mem = mem

        for key, value in table_info.__dict__.items():
            setattr(self, key, value)

        self.__create_romid_table()

    def __create_romid_table(self):
        
        # TODO 256kb Roms hier noch differenzieren. als eigene fn erkennen lassen? Über Plausibilität?

        for i in range(self.length):
            start = self.relative_pointer_addr + i * RomIdTableEntry_512kb.entry_size

            table_bytes = self.mem.read_bytes(start, RomIdTableEntry_512kb.entry_size)
            
            entry = RomIdTableEntry_512kb.from_bytes(table_bytes)
            self.entries.append(entry)
        
        #return romid_table
    
    def get_table_pointer_by_romid(self, romid0:int, romid1:int, romid2:int) -> int:

        offset_address = self.relative_pointer_addr
        entry_size = self.entries[0].entry_size  # oder RomIdTableEntry_512kb.entry_size

        for i, entry in enumerate(self.entries):
            if entry.romid0 == romid0 and entry.romid1 == romid1 and entry.romid2 == romid2:
                return offset_address + i * entry_size

        raise RomIdNotFoundError(f"RomID {romid0:02X} {romid1:02X} {romid2:02X} not found")



    # TODO: function_select_system wird vorher noch aufgerufen... werden da die SSM-CMDs zugeordnet?
    # TODO: set_current_romid_values emulieren?, chk_attach_addresses_88D8 emulieren?
        