import logging
import re
from typing import Optional
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import ActionType, CurrentSelectedDevice, MasterTableEntry, RomIdTableEntry_512kb, SsmAction
from analyzer_core.emu.emulator_6303 import EmulationError, Emulator6303
from analyzer_core.emu.ssm_emu_helper import SsmEmuHelper
from analyzer_core.ssm.action_functions.action_helper import SsmActionHelper

logger = logging.getLogger(__name__)


class SsmActionYear(SsmActionHelper):
    
    def __init__(self, 
                 rom_cfg: RomConfig, 
                 emulator: Emulator6303, 
                 current_device: CurrentSelectedDevice, 
                 romid_entry:RomIdTableEntry_512kb, 
                 mt_entry: MasterTableEntry) -> None:

        self.rom_cfg = rom_cfg
        self.emulator = emulator

        self.current_device = current_device
        self.romid_entry = romid_entry
        self.mt_entry = mt_entry

        self.year_model_upper_str: Optional[str] = None
        self.year_model_lower_str: Optional[str] = None

    def add_function_mocks(self):
        '''
        Add the necessary function mocks for YEAR action
        '''

        def mock_year_print_upper_screen(em: Emulator6303):
            screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y0_x0')
            #print(f"Upper Screen [{screen_line}]", flush=True)
            self.year_model_upper_str = screen_line

            em.mock_return()
        
        def mock_year_print_lower_screen(em: Emulator6303):
            screen_line = SsmEmuHelper.get_screen_line(self.rom_cfg, em, 'ssm_display_y1_x0')
            #print(f"Lower Screen [{screen_line}]", flush=True)
            self.year_model_lower_str = screen_line

            em.mock_return()

        self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_upper_screen"), mock_year_print_upper_screen)
        self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_screen"), mock_year_print_lower_screen)


    def run_post_actions(self):
        '''
        Actions to be run after the YEAR action function has been emulated
        '''
        self.__save_year_model_strings()
        

    def __save_year_model_strings(self):
        '''
        Save the year model strings into the RomID entry
        '''
        
        if self.year_model_upper_str is None or self.year_model_lower_str is None:
            raise EmulationError("YEAR action did not set both year model strings.")
        
        if self.mt_entry.action is None:
            raise RuntimeError("MasterTableEntry action datatype not set before saving YEAR action results.")

        self.romid_entry.ssm_year, self.romid_entry.ssm_model = self.__interpret_year_string(self.year_model_upper_str + " " + self.year_model_lower_str)

        self.mt_entry.action.action_type = ActionType.YEAR
        self.mt_entry.action.lower_label_raw = self.year_model_lower_str
        logger.debug(f"Found RomID entry for year: {self.romid_entry.ssm_year}, model: {self.romid_entry.ssm_model}")
    

    def __interpret_year_string(self, year_model_str: str) -> tuple[int, str]:
        '''
        Interpret the raw strings and fetch information like year and model
        [ 1996     (F00) ]
        [  2.0    TURBO  ]

        [ E-4AT    (F00) ]
        [  4WD     1996  ]

        [ YEAR     (F00) ]      [ 1994     (F00) ]
        [     1995       ]      [   AUTO A/C     ]

        [ YEAR     (F00) ]      [ CRUISE   (F00) ]
        [     1995       ]      [   CONTROL      ]

        [ 1995     (F00) ]
        [ ABS᛫TCS  FF    ]

        '''

        # Switch through known patterns and extract year and model

        # [ 1996     (F00)   2.0    TURBO  ]
        m = re.search(r"(19\d{2})\s+\(F00\)\s(.*)", year_model_str)
        if m:
            year = int(m.group(1))
            model = re.sub(r"\s+", " ", m.group(2).strip())
            return year, model
        
        # [ E-4AT    (F00)   4WD     1996  ]
        m = re.search(r"(\S+)\s+\(F00\)\s+(\S+)\s+(19\d{2})", year_model_str)
        if m:
            year = int(m.group(3))
            model = m.group(1).strip()+" "+m.group(2).strip()
            return year, model
        
        # [ YEAR     (F00)     1995       ]
        m = re.search(r"YEAR\s+\(F00\)\s+(19\d{2})", year_model_str)
        if m:
            year = int(m.group(1))
            model = self.current_device.name
            return year, model
        
        # [ CRUISE   (F00)    CONTROL      ]
        m = re.search(r"(.*)\s+\(F00\)\s+(.*)", year_model_str)
        if m:
           year = 0000 # TODO unknown
           model = m.group(1).strip()+" "+m.group(2).strip()
           return year, model
        
        
        raise EmulationError(f"Could not interpret YEAR/MODEL string: [{year_model_str}]")

