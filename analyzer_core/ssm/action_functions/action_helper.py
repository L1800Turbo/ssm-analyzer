from abc import ABC, abstractmethod
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.emu.emulator_6303 import Emulator6303


class SsmActionHelper(ABC):
    needs_scaling_fn = False
    
    def __init__(self, rom_cfg: RomConfig, emulator: Emulator6303):
        self.rom_cfg = rom_cfg
        self.emulator = emulator

    @abstractmethod
    def add_function_mocks(self):
        pass

    @abstractmethod
    def run_post_actions(self) -> bool:
        return False

