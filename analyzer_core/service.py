import logging
from pathlib import Path
import struct
from typing import Tuple
from analyzer_core.analyze.ssm_function_emulator import SsmFunctionEmulator
from analyzer_core.analyze.string_finder import RomStringFinder
from analyzer_core.config.memory_map import MemoryMap
from analyzer_core.config.ssm_model import CurrentSelectedDevice
from analyzer_core.data.rom_image import RomImage
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.emu.memory_manager import MemoryManager
from analyzer_core.analyze.pattern_detector import PatternDetector
from analyzer_core.analyze.repo import PatternRepository
from analyzer_core.disasm.capstone_wrap import Disassembler630x
from analyzer_core.disasm.insn_model import Instruction

class RomService:
    def __init__(self, image_file: Path):
        self.logger = logging.getLogger(__name__)
        self.rom_cfg = RomConfig()
        self.rom_image = RomImage(image_file)

    
    def analyze(self):
        '''
        Main method to analyze the ROM of this service and fill the RomConfig with all information.
        '''

        self.rom_cfg.instructions, self.rom_cfg.call_tree = self.disassemble_from_reset(self.rom_image)

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
        string_finder = RomStringFinder(self.rom_image, self.rom_cfg.pattern_repo, self.rom_cfg, CurrentSelectedDevice.UNDEFINED)
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
            ptr_bytes = self.rom_image.rom[offset:offset+2]
            master_table_workers.append(struct.unpack(">H", ptr_bytes)[0])

        self.disassemble_from_pointer_list(
            start_addresses=master_table_workers,
            rom_image=self.rom_image,
            instructions=self.rom_cfg.instructions,
            call_tree=self.rom_cfg.call_tree
            )
        
        # Second part pattern detections for functions that weren't statically reachable
        pattern_detector.detect_patterns(self.rom_cfg.instructions, "master_table_pointer_pattern")

        # Emulate functions to extract information
        ssm_fn_emu = SsmFunctionEmulator(self.rom_image, self.rom_cfg)
        ssm_fn_emu.run_ssm_functions()



    @classmethod
    def list_roms(cls, root_folder: Path) -> list[Path]:
        """List all ROM files in the given folder."""
        return list(root_folder.glob("*.bin"))

    # TODO Das RomImage dann nicht in Self rein? muss ja gar nicht bis in die GUI getragen werden?
    # def load_rom_image(self, rom_path: Path) -> RomImage:
    #     """Load ROM image from file."""
    #     return RomImage(rom_path)    

    def disassemble_from_reset(self, rom_image: RomImage) -> Tuple[dict[int, Instruction], dict]:
        """
        Disassemble code starting from the reset vector, which is the main entry point of the ROM. Returns a tuple of instructions and call tree.
        """
        mem = MemoryManager(MemoryMap(), rom_image)
        disasm = Disassembler630x(mem, self.rom_cfg)

        # Start fresh instruction and call tree lists
        instructions: dict[int, Instruction] = {}
        call_tree: dict = {}        

        disasm.disassemble_reachable(rom_image.reset_vector(), instructions, call_tree)

        return instructions, call_tree
    
    
    def disassemble_from_pointer_list(self, start_addresses: list[int], rom_image: RomImage, instructions: dict[int, Instruction], call_tree: dict):
        """
        Disassemble code by a given list of addresses which work as a pointer
        """
        mem = MemoryManager(MemoryMap(), rom_image)
        disasm = Disassembler630x(mem, self.rom_cfg)

        for start_addr in start_addresses:
            disasm.disassemble_reachable(start_addr, instructions, call_tree)

