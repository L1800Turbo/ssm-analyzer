# RomService (Facade)
# Central facade for CLI/GUI. Methods: load, analyze, get_catalog

import logging
from pathlib import Path
import struct
from typing import List, Optional, Tuple
from analyzer_core.analyze.ssm_function_emulator import SsmFunctionEmulator
from analyzer_core.analyze.string_finder import RomStringFinder
from analyzer_core.data.rom_image import RomImage
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.emu.tracing import MemAccess

#from analyzer_core.discovery import RomDiscoveryService
#from analyzer_core.catalog import RomCatalog
from analyzer_core.analyze.pattern_detector import PatternDetector
from analyzer_core.analyze.repo import PatternRepository
from analyzer_core.pipeline import AnalysisPipeline
from analyzer_core.disasm.capstone_wrap import Disassembler630x
from analyzer_core.disasm.insn_model import Instruction

class RomService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.rom_cfg = RomConfig()

    # TODO Ruft noch keiner auf gerade -> Hier könnte die Analyse-Pipeline integriert werden
    def analyze(self, rom_image: RomImage):

        self.rom_cfg.instructions, self.rom_cfg.call_tree = self.disassemble_from_reset(rom_image)

        # Adjust stack pointer if found
        stack_pointers = Disassembler630x.find_stackpointer(self.rom_cfg.instructions)
        if isinstance(stack_pointers, int):
            self.logger.debug(f"Setting default stack pointer to {stack_pointers}")
            self.rom_cfg.set_stack_pointer(stack_pointers)
        elif isinstance(stack_pointers, set):
            raise NotImplementedError("Only one stack pointer definition is currently supported")
            


        # Get pattern repository TODO festen Pfad ändern
        self.rom_cfg.pattern_repo = PatternRepository(Path("./ressources/rom_patterns.json"))

        # Collect strings from ROM
        string_finder = RomStringFinder(rom_image, self.rom_cfg.pattern_repo, self.rom_cfg)
        string_finder.find_string_references()
        
        # Detect assembly patterns from by Reset reachable functions
        pattern_detector = PatternDetector(self.rom_cfg)
        pattern_detector.detect_patterns(self.rom_cfg.instructions, "static_rom_pattern")

        # TODO Noch auslagern?
        # Detect functions called by master table worker pointer list
        worker_function_count = 8
        master_table_workers = []
        for i in range(worker_function_count):
            offset = self.rom_cfg.address_by_name("master_table_worker_functions_ptr") + i * 2 # 16bit
            ptr_bytes = rom_image.rom[offset:offset+2]
            master_table_workers.append(struct.unpack(">H", ptr_bytes)[0])

        self.disassemble_from_pointer_list(
            start_addresses=master_table_workers,
            rom_image=rom_image,
            instructions=self.rom_cfg.instructions,
            call_tree=self.rom_cfg.call_tree
            )
        
        # Second part pattern detections for functions that weren't statically reachable
        pattern_detector.detect_patterns(self.rom_cfg.instructions, "master_table_pointer_pattern")

        # Emulate functions to extract information
        ssm_fn_emu = SsmFunctionEmulator(rom_image, self.rom_cfg)
        ssm_fn_emu.run_ssm_functions()

        


        # TODO: für die Pipeline einbauen, vorher wohl einzeln
        # - Pattern-Detector, mit Ref auf self.config und rom und alles?
        # - Emulator


    # def get_catalog(self, root_folder: Path) -> RomCatalog:
    #     """Discover and return ROM catalog (lazy discovery)."""
    #     discovery = RomDiscoveryService()
    #     roms = discovery.find_roms(root_folder)
    #     catalog = RomCatalog(roms)
    #     return catalog

    @classmethod
    def list_roms(cls, root_folder: Path) -> list[Path]:
        """List all ROM files in the given folder."""
        return list(root_folder.glob("*.bin"))

    # TODO Das RomImage dann nicht in Self rein? muss ja gar nicht bis in die GUI getragen werden?
    def load_rom_image(self, rom_path: Path) -> RomImage:
        """Load ROM image from file."""
        return RomImage(rom_path)    

    def disassemble_from_reset(self, rom_image: RomImage) -> Tuple[dict[int, Instruction], dict]:
        """
        Disassembliert nur tatsächlich erreichbaren Code ab Reset-Vektor und JSR/JMP-Zielen (rekursiv).
        """
        disasm = Disassembler630x(rom_image.rom)

        # Start fresh instruction and call tree lists
        instructions: dict[int, Instruction] = {}
        call_tree: dict = {}
        try:
            start_addr = rom_image.reset_vector()
        except Exception:
            self.logger.warning("Failed to determine start address, defaulting to 0x0000")
            start_addr = 0x0000
        disasm.disassemble_reachable(start_addr, instructions, call_tree)

        return instructions, call_tree
    
    def disassemble_from_pointer_list(self, start_addresses: list[int], rom_image: RomImage, instructions: dict[int, Instruction], call_tree: dict):
        '''
        Disassemble code by a given list of addresses which work as a pointer
        '''
        disasm = Disassembler630x(rom_image.rom)


        for start_addr in start_addresses:
            new_instructions, new_call_tree = disasm.disassemble_reachable(start_addr, instructions, call_tree)
        
        return instructions, call_tree



    def init_emulator(self, rom_image: RomImage) -> None:
        """Initialize the emulator."""
        self.logger.info("Initializing emulator.")
        self.emulator = Emulator6303(rom_image=rom_image, rom_config=self.rom_cfg)

        # TODO Nur als Test


    
    def step_from_address(self, addr: int) -> Optional[MemAccess]:
        """Execute code from a specific address."""
        if self.emulator is None:
            self.logger.warning("Emulator not initialized.")
            return None
        
        self.logger.info(f"Executing code from address: {addr:#04x}")
        self.emulator.set_pc(addr)
        #self.emulator.run_function_end()
        return self.emulator.step()

    def run_to_function_end(self, addr: int) -> Optional[MemAccess]:
        """Run the emulator until the end of the current function."""
        if self.emulator is None:
            self.logger.warning("Emulator not initialized.")
            return None

        self.logger.info("Running emulator to function end.")
        self.emulator.set_pc(addr)
        return self.emulator.run_function_end()
        