
from dataclasses import replace
from typing import Optional
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import MasterTableInfo, RomIdTableEntry_256kb, RomIdTableEntry_512kb, RomIdTableInfo
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.ssm.master_table_analyzer import MasterTableAnalyzer
from analyzer_core.ssm.romid_table_entry_analyzer import RomIdEntryAnalyzer


class RomIdNotFoundError(Exception):
    pass

class RomIdTableAnalyzer:

    def __init__(self, emulator: Emulator6303, table_info:RomIdTableInfo, rom_cfg: RomConfig) -> None:
        self.emulator = emulator
        self.rom_cfg = rom_cfg

        #self.table = replace(table_info, entries=[])
        self.table = table_info

        self.__create_romid_table()

    # @classmethod
    # def from_raw(cls, emulator: Emulator6303, relative_pointer_addr: int, length: int, entry_type=None):
    #     """Alternative Factory, falls keine RomIdTableInfo vorhanden ist."""
    #     info = RomIdTableInfo(relative_pointer_addr=relative_pointer_addr, length=length, entries=[])
    #     return cls(emulator, info)

    def __create_romid_table(self):

        if self.table.length <= 0:
            return
        
        # TODO 256kb Roms hier noch differenzieren. als eigene fn erkennen lassen? Über Plausibilität?

        # Wir lesen das erste Entry, um die entry_size zu bestimmen, falls nötig
        # Hier gehen wir davon aus, dass table_info.entries[0] ggf. Typinformationen enthält,
        # ansonsten nutzen wir den bekannten 512kb-Eintragstyp als Standard.
        entry_size = RomIdTableEntry_512kb.entry_size

        for i in range(self.table.length):
            start = self.table.relative_pointer_addr + i * entry_size
            table_bytes = self.emulator.mem.read_bytes(start, entry_size)
            entry = self._parse_entry_bytes(table_bytes, entry_size)
            self.table.entries.append(entry)
        
    def _parse_entry_bytes(self, table_bytes: bytes, entry_size: int):
        """
        Wählt den passenden Entry-Parser basierend auf entry_size.
        Erweitere hier bei Bedarf um weitere Formate.
        """
        if entry_size == RomIdTableEntry_512kb.entry_size:
            return RomIdTableEntry_512kb.from_bytes(table_bytes)
        elif entry_size == getattr(RomIdTableEntry_256kb, "entry_size", 0) and RomIdTableEntry_256kb.entry_size > 0:
            return RomIdTableEntry_256kb.from_bytes(table_bytes)
        else:
            # Fallback: rohdaten in eine einfache Instanz packen oder Fehler werfen
            raise ValueError(f"Unsupported RomIdTableEntry size: {entry_size}")
        
    def get_table_pointer_by_romid(self, romid0:int, romid1:int, romid2:int) -> int:
        """
        Liefert die absolute Adresse des Table-Eintrags (Offset) für eine gegebene RomID.
        """
        offset_address = self.table.relative_pointer_addr
        if not self.table.entries:
            raise RomIdNotFoundError("Table is empty")

        entry_size = self.table.entries[0].entry_size

        for i, entry in enumerate(self.table.entries):
            if entry.romid0 == romid0 and entry.romid1 == romid1 and entry.romid2 == romid2:
                return offset_address + i * entry_size

        raise RomIdNotFoundError(f"RomID {romid0:02X} {romid1:02X} {romid2:02X} not found")
    
    def enrich_entries(self, rom_cfg: RomConfig, current_device) -> None:
        """
        Für jede Tabellen-Entry zusätzliche Infos mittels Emulation ermitteln:
         - Protokoll-Liste (ssm_cmd_protocols)
         - request_romid_cmd (Hardcoded RomID request)
         - Save pointer to RAM
         - attach_cu_specific_addresses -> read back pointers/limits
        Erwartet, dass self.emulator bereits die richtige Memory-Mapping / Umgebung hat.
        """

        for entry in self.table.entries:
            # skip unsupported formats
            if isinstance(entry, RomIdTableEntry_256kb):
                # keep previous behaviour (raise or skip)
                raise NotImplementedError("Noch kein 256kb ROM")
            
            entry_analyzer = RomIdEntryAnalyzer(self.emulator, rom_cfg, entry)

            # mark device in RAM so functions behave as on-device
            entry_analyzer.prepare_for_device(current_device)


            # collect possible (cmd, protocol) combos
            entry_analyzer.collect_cmd_protocols()

            # request romid to capture hardcoded values (may prune protocols etc.)
            entry_analyzer.request_romid_and_capture(current_device)

            # write the pointer for this entry into RAM for other functions to use
            self.__execute_save_table_pointer_to_memory(entry)

            # attach cu-specific addresses (reads various pointers/limits back into entry)
            entry_analyzer.run_attach_cu_specific_addresses()


            # Create MasterTable analyzer for this entry (done by caller or here)
            entry.master_table = MasterTableInfo(
                                    pointer_addr_rel = entry.master_table_address_rel,
                                    length = entry.entry_size,
                                    entries = []
                                )
            master_table_analyzer = MasterTableAnalyzer(self.emulator, rom_cfg, entry)
            master_table_analyzer.collect_master_table_entries()

    # TODO: move to RomIdEntryAnalyzer
    def __execute_save_table_pointer_to_memory(self, entry: RomIdTableEntry_512kb) -> None:
        '''
        Mostly to have a proper working emulator: Save vars from current RomID table into respective memory locations
        '''

        # Set PC to function "set_current_romid_values"
        self.emulator.set_pc(self.rom_cfg.address_by_name("set_current_romid_values"))

        # Get pointer for this RomID in RomID List
        current_romid_line_pointer_addr = self.rom_cfg.address_by_name("current_romid_line_pointer")
        current_romid_line_pointer = self.get_table_pointer_by_romid(entry.romid0, entry.romid1, entry.romid2)
        self.emulator.write16(current_romid_line_pointer_addr, current_romid_line_pointer)

        self.emulator.run_function_end()


    # Hilfs-APIs, die nützlich sein können:
    def get_entry_by_index(self, idx: int):
        return self.table.entries[idx]

    def find_by_romid_tuple(self, romid_tuple: tuple[int,int,int]) -> Optional[int]:
        try:
            return self.get_table_pointer_by_romid(*romid_tuple)
        except RomIdNotFoundError:
            return None
        




    # TODO: function_select_system wird vorher noch aufgerufen... werden da die SSM-CMDs zugeordnet?
    # TODO: set_current_romid_values emulieren?, chk_attach_addresses_88D8 emulieren?
        