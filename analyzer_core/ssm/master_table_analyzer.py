from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import MasterTableInfo
from analyzer_core.emu.emulator_6303 import Emulator6303


class MasterTableAnalyzer:
    '''
    Static analysis of SSM code to collect master table entries
    '''
    
    def __init__(self, emulator: Emulator6303, rom_cfg: RomConfig, master_table_info:MasterTableInfo):
        self.emulator = emulator
        self.rom_cfg = rom_cfg

        self.master_table = master_table_info


        #self.entries = self.__create_master_table()
    
    def __create_master_table(self):
        pass

