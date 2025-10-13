# RomService (Facade)
# Central facade for CLI/GUI. Methods: load, analyze, get_catalog

import logging
from pathlib import Path
from typing import List, Optional, Tuple
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
        self.config = RomConfig()

        # TODO nur zum testen
        #self.config.add_function("wait_ms", 0xBD84)
        
    def load(self, rom_path: Path) -> tuple[RomImage, RomConfig, dict]:
        """Load ROM, config and initial metadata."""
        from analyzer_core.data.rom_image import SSM1RomImage
        rom_image = RomImage(rom_path.read_bytes())
        config = RomConfig() #TODO weg
        if isinstance(rom_image, SSM1RomImage):
            reset_vector = rom_image.reset_vector()
        else:
            reset_vector = None
        metadata = {
            "reset_vector": reset_vector,
            "size": len(rom_image.rom),
            # Add more metadata extraction as needed
        }
        return rom_image, config, metadata

    # TODO Ruft noch keiner auf gerade -> Hier könnte die Analyse-Pipeline integriert werden
    def analyze(self, rom_image: RomImage):

        self.instr_list, self.call_tree = self.disassemble_from_reset(rom_image)


        # Get pattern repository TODO festen Pfad ändern
        pattern_repo = PatternRepository(Path("./ressources/rom_patterns.json"))

        # Collect strings from ROM
        string_finder = RomStringFinder(rom_image, pattern_repo, self.config)
        string_finder.find_string_references()
        
        # Detect assembly patterns
        self.pattern_detector = PatternDetector(pattern_repo, self.config)
        self.pattern_detector.detect_patterns(self.instr_list)

        # TODO Patterndetector hier einbauen, der soll über die Instructions gehene

        # TODO: für die Pipeline einbauen, vorher wohl einzeln
        # - Pattern-Detector, mit Ref auf self.config und rom und alles?
        # - Emulator



        """Run analysis pipeline and return result DTO."""
        # rom_image, config, metadata = self.load(rom_path)
        # pipeline = AnalysisPipeline(pipeline_cfg)
        # result = pipeline.run(rom_image, config, metadata)
        # return result

    # def get_catalog(self, root_folder: Path) -> RomCatalog:
    #     """Discover and return ROM catalog (lazy discovery)."""
    #     discovery = RomDiscoveryService()
    #     roms = discovery.find_roms(root_folder)
    #     catalog = RomCatalog(roms)
    #     return catalog

    def list_roms(self, root_folder: Path) -> list[Path]:
        """List all ROM files in the given folder."""
        return list(root_folder.glob("*.bin"))

    # TODO Das RomImage dann nicht in Self rein? muss ja gar nicht bis in die GUI getragen werden?
    def load_rom_image(self, rom_path: Path) -> RomImage:
        """Load ROM image from file."""
        return RomImage(rom_path.read_bytes())

    def disassemble_from_reset(self, rom_image: RomImage) -> Tuple[List[Instruction], dict]:
        """
        Disassembliert nur tatsächlich erreichbaren Code ab Reset-Vektor und JSR/JMP-Zielen (rekursiv).
        """
        disasm = Disassembler630x(rom_image.rom)
        try:
            from analyzer_core.data.rom_image import SSM1RomImage
            if isinstance(rom_image, SSM1RomImage):
                start_addr = rom_image.reset_vector()
            else:
                start_addr = int.from_bytes(rom_image.rom[-4:-2], 'big')
        except Exception:
            self.logger.warning("Failed to determine start address, defaulting to 0x0000")
            start_addr = 0x0000
        return disasm.disassemble_reachable(rom_image.rom, start_addr)

    def init_emulator(self, rom_image: RomImage) -> None:
        """Initialize the emulator."""
        self.logger.info("Initializing emulator.")
        self.emulator = Emulator6303(rom_image=rom_image)

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
        