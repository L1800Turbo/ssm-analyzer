
from dataclasses import replace
import logging
from typing import Optional
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import CurrentSelectedDevice, MasterTableInfo, RomIdTableEntry_256kb, RomIdTableEntry_512kb, RomIdTableInfo
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.ssm.master_table_analyzer import MasterTableAnalyzer
from analyzer_core.ssm.romid_table_entry_analyzer import RomIdEntryAnalyzer


class RomIdNotFoundError(Exception):
    pass

class RomIdTableAnalyzer:

    def __init__(self, emulator: Emulator6303, table_info:RomIdTableInfo, rom_cfg: RomConfig) -> None:
        self.logger = logging.getLogger(__name__)
        
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
            entry.entry_ptr_address = start
            self.table.entries.append(entry)
        
        # TODO List ist ja eigentlich falsch, das könnte man umsortieren, geht für den Pointer dann nicht
        
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
        
    
    def enrich_entries(self, rom_cfg: RomConfig, current_device: CurrentSelectedDevice) -> None:
        """
        Für jede Tabellen-Entry zusätzliche Infos mittels Emulation ermitteln:
         - Protokoll-Liste (ssm_cmd_protocols)
         - request_romid_cmd (Hardcoded RomID request)
         - Save pointer to RAM
         - attach_cu_specific_addresses -> read back pointers/limits
        Erwartet, dass self.emulator bereits die richtige Memory-Mapping / Umgebung hat.

        TODO warum rom_cfg übergeben, ist doch self.rom_cfg?
        """

        for entry in self.table.entries:
            # skip unsupported formats
            if isinstance(entry, RomIdTableEntry_256kb):
                # keep previous behaviour (raise or skip)
                raise NotImplementedError("Noch kein 256kb ROM")
            
            entry_analyzer = RomIdEntryAnalyzer(self.emulator, rom_cfg, self.table, entry)

            if entry.romid0 & 0xF0 == 0xA0:
                print(f"Skipping Axx RomID {entry.print_romid_str()} for device {current_device.name}")
                continue

            # mark device in RAM so functions behave as on-device
            entry_analyzer.prepare_for_device(current_device)

            # collect possible (cmd, protocol) combos
            entry_analyzer.collect_cmd_protocols()

            # request romid to capture hardcoded values (may prune protocols etc.)
            entry_analyzer.request_romid_and_capture(current_device)


            #if current_device != CurrentSelectedDevice.CC:
            #   continue 



            # write the pointer for this entry into RAM for other functions to use
            entry_analyzer.execute_set_current_romid_values()

            # attach cu-specific addresses (reads various pointers/limits back into entry)
            entry_analyzer.run_attach_cu_specific_addresses()

            # TODO Für Debuggen und schneller suchen
            #if entry.print_romid_str() != "74 BD 00" and entry.print_romid_str() != "71 93 00":  # 76 5D B0  71 93 00
            #   return
            


            # Create MasterTable analyzer for this entry (done by caller or here)
            entry.master_table = MasterTableInfo(
                                    pointer_addr_rel = entry.master_table_address_rel,
                                    length = entry.entry_size,
                                    entries = []
                                )
            master_table_analyzer = MasterTableAnalyzer(self.emulator, rom_cfg, entry)
            master_table_analyzer.collect_master_table_entries(current_device)



    # Hilfs-APIs, die nützlich sein können:
    def get_entry_by_index(self, idx: int):
        return self.table.entries[idx]

    # def find_by_romid_tuple(self, romid_tuple: tuple[int,int,int]) -> Optional[int]:
    #     try:
    #         return self.get_table_pointer_by_romid(*romid_tuple)
    #     except RomIdNotFoundError:
    #         return None
        




    # TODO: function_select_system wird vorher noch aufgerufen... werden da die SSM-CMDs zugeordnet?
    # TODO: set_current_romid_values emulieren?, chk_attach_addresses_88D8 emulieren?
        