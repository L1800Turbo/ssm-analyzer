import logging
from pathlib import Path
from typing import List, Optional


class RomImageError(Exception):
    pass

class RomImage:
    def __init__(self, rom_file: Path):
        self.rom = rom_file.read_bytes()
        self.file_name = rom_file.name
        self.image_name = rom_file.stem

        self.logger = logging.getLogger(f"{__name__}_{self.file_name}")

    def contents(self) -> bytes:
        '''
        Return the full contents of the ROM image.
        '''
        return self.rom

    def reset_vector(self) -> int:
        '''
        Return the reset vector address from the ROM image.
        '''
        return int.from_bytes(self.rom[0xFFFC:0xFFFE], 'big')

    def find_bytes(self, needle: bytes, start: int = 0) -> Optional[int]:
        '''Find the first occurrence of a given byte sequence.'''
        idx = self.rom.find(needle, start)
        return idx if idx != -1 else None

    def find_all(self, needle: bytes, start: int = 0) -> List[int]:
        '''Find all occurrences of a given byte sequence.'''
        hits = []
        start = 0
        while True:
            i = self.find_bytes(needle, start)
            if i is None:
                break
            hits.append(i)
            start = i + 1
        return hits
    
    def find_strings(self, text: str) -> List[int]:
        """Find the first occurrence of a given ASCII string (not zero-terminated search)."""
        needle = text.encode("ascii", errors="ignore")
        return self.find_all(needle)
    
    def find_string_address(self, text: str) -> int:
        """Find the first occurrence of a given ASCII string (not zero-terminated search)."""
        strings = self.find_strings(text)

        if len(strings) == 0:
            raise RomImageError(f"String '{text}' not found in ROM image")
        elif len(strings) > 1:
            raise RomImageError(f"String '{text}' found multiple times in ROM image: {strings}")
        
        return strings[0]
    

    
    