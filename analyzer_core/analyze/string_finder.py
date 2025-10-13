
from analyzer_core.analyze.repo import PatternRepository
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.data.rom_image import RomImage


class RomStringFinder:
    def __init__(self, rom_image: RomImage, pattern_repo: PatternRepository, rom_config: RomConfig):
        self.rom_image = rom_image
        self.rom_config = rom_config

        self.str_patterns = pattern_repo.get_string_patterns()

    def find_string_references(self):
        """
        Find all memory accesses to string literals in the ROM image, attaches them to the config.
        """

        for name, value in self.str_patterns.items():
            address = self.rom_image.find_string_address(value)
            if address is not None:
                self.rom_config.add_string(
                    name=name,
                    address=address,
                    length=len(value)
                )
