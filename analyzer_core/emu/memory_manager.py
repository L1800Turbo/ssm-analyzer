from typing import Optional
from analyzer_core.config.memory_map import MemoryMap, MemoryRegion, RegionKind
from analyzer_core.data.rom_image import RomImage
from analyzer_core.emu.hooks import HookManager

class MemoryManager:

    def __init__(self, memory_map: MemoryMap, rom_image: RomImage, ram: Optional[bytearray] = None, hooks: Optional[HookManager] = None):
        self.memory_map = memory_map
        self.rom_image = rom_image
        self.ram = ram if ram is not None else bytearray(0x2000)  # Default RAM size
        self.hooks = hooks

        self.mapped_rom_offset = None

        # Trace which memory was read and written during this run
        # TODO Evtl mit MemAccess Klasse was machen?
        self.__read_memory = set()
        self.__written_memory = set()

        self.__add_default_values()

    def set_mapped_region(self, offset:int):
        '''
        Attach a memory area from the '96 onwards cassettes
        A 64kb cassette is used, the area 0x0000-0x8000 is filled with blocks of 0x2000 length.
        They get shifted to the block from 0x2000
        '''
        self.mapped_rom_offset = offset

    def read(self, address: int) -> int:
        region = self.memory_map.region_lookup(address)
        if not region:
            raise ValueError(f"Address 0x{address:04X} not mapped to any region.")
        value = None
        if region.kind == RegionKind.RAM:
            value = self.ram[address - region.start]
            # TODO Warnung, wenn die RAM-Stelle nicht initialisiert ist!
        elif region.kind == RegionKind.ROM:
            # ROM is being read without any offset as it's the original ROM file
            value = self.rom_image.rom[address]
        elif region.kind == RegionKind.MAPPED_ROM:
            # Check if there is an offset mapped before (don't take default values)
            if not self.mapped_rom_offset:
                raise MemoryError(f"Mapped memory offset for access to {address:#04X} is not defined! Define it first.")
            value = self.rom_image.rom[address + self.mapped_rom_offset]
        elif region.kind == RegionKind.IO:
            # IO access could be handled by hooks/mocks TODO macht das so überhaupt Sinn?
            if self.hooks and self.hooks.run_read_hooks(address, 0):
                value = 0  # Default/mock value
            else:
                raise NotImplementedError("IO region access not implemented.")
        else:
            raise ValueError(f"Unknown region kind: {region.kind}")
        if self.hooks:
            self.hooks.run_read_hooks(address, value)
        
        self.__read_memory.add(address)
        return value

    def write(self, address: int, value: int):
        region = self.memory_map.region_lookup(address)
        if not region:
            raise ValueError(f"Address 0x{address:04X} not mapped to any region.")
        if region.kind == RegionKind.RAM:
            self.ram[address - region.start] = value & 0xFF
        elif region.kind == RegionKind.IO:
            # IO access could be handled by hooks/mocks
            if self.hooks:
                self.hooks.run_write_hooks(address, value)
            else:
                raise NotImplementedError("IO region write not implemented.") # TODO Generell die Frage: IOs haben auch den RAM-Bereich?
        elif region.kind in (RegionKind.ROM, RegionKind.MAPPED_ROM):
            raise PermissionError(f"Cannot write to ROM or MAPPED_ROM region at 0x{address:04X}.")
        else:
            raise ValueError(f"Unknown region kind: {region.kind}")
        
        self.__written_memory.add(address)

    def region_for(self, address: int) -> Optional[MemoryRegion]:
        return self.memory_map.region_lookup(address)
    
    def get_read_memory_addresses(self):
        return self.__read_memory

    def get_written_memory_addresses(self):
        return self.__written_memory

    def __add_default_values(self):
        """
        Setzt typische Default-Werte für HD6303 (Stack Pointer etc.) in den RAM.
        """
        # Beispiel: Initial Stack Pointer Value und weitere Defaults
        # Annahme: RAM beginnt bei 0x0000
        # 0x01FF: Stack Pointer
        # 0x0200, 0x0201: weitere Initialwerte
        # Die Adressen werden auf RAM-Offset gemappt
        mapping = {
            0x01FF: 0xFF,
            0x0200: 0x00,
            0x0201: 0x00,
        }
        for addr, value in mapping.items():
            region = self.memory_map.region_lookup(addr)
            if region and region.kind == RegionKind.RAM:
                self.ram[addr - region.start] = value & 0xFF
