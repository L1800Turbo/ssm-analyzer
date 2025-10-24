import logging
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import MasterTableEntry, RomIdTableEntry_512kb
from analyzer_core.emu.emulator_6303 import EmulationError, Emulator6303


class MasterTableEntryAnalyzer:


    def __init__(self, emulator: Emulator6303, rom_cfg: RomConfig, romid_entry:RomIdTableEntry_512kb, mt_entry: MasterTableEntry) -> None:
        self.mt_entry = mt_entry
        self.romid_entry = romid_entry
        self.__emulator = emulator
        self.__rom_cfg = rom_cfg
        self.logger = logging.getLogger(__name__)

        self._save_labels()

    def _save_labels(self):
        '''
        The upper label depends on the upper label index
        '''

        def label_to_mt(lbl_ptr:int|None, lbl_idx):
            if lbl_ptr is None:
                raise EmulationError(f"Upper label pointer for RomID {self.romid_entry.print_romid_str}")
            
            lbl_addr = lbl_ptr + lbl_idx * 0x10
            lbl_bytes = self.__emulator.mem.read_bytes(lbl_addr, 0x10)
            return self.__rom_cfg.byte_interpreter.render(lbl_bytes)

        self.mt_entry.upper_label = label_to_mt(self.romid_entry.menuitems_upper_label_pointer, self.mt_entry.upper_label_index)
        
        # TODO geht noch nicht, die Geschichte mit dem stack ist noch falsch, wird bei AC8E geladen und dann auch direkt die ACTION
        # if self.mt_entry.lower_label_index != 0xFF:
        #    self.mt_entry.lower_label = label_to_mt(self.romid_entry.menuitems_lower_label_pointer, self.mt_entry.lower_label_index)

       