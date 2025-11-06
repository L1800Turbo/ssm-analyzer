from typing import Iterable, Optional, Tuple
from analyzer_core.config.memory_map import MemoryMap, MemoryRegion, RegionKind
from analyzer_core.data.rom_image import RomImage
from analyzer_core.emu.hooks import HookManager
from analyzer_core.emu.ram import Ram

class MemoryManager:
    def __init__(self, memory_map: MemoryMap, rom_image: RomImage, hooks: Optional[HookManager] = None):
        self.memory_map = memory_map
        self.rom_image = rom_image
        self.ram = Ram(0x2000)  # Default RAM size
        #self.ram = ram if ram is not None else bytearray(0x2000)  # Default RAM size
        self.hooks = hooks

        self.mapped_rom_offset = None

        # Trace which memory was read and written during this run
        # TODO Evtl mit MemAccess Klasse was machen?
        self.__read_memory = set()
        self.__written_memory = set()

        #self.__add_default_values()

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

        if self.hooks:
            self.hooks.run_read_hooks(address, value, self)

        if region.kind == RegionKind.RAM:
            value = self.ram.read8(address - region.start)
            # TODO Warnung, wenn die RAM-Stelle nicht initialisiert ist!
        elif region.kind == RegionKind.ROM:
            # ROM is being read without any offset as it's the original ROM file
            value = self.rom_image.rom[address]
        elif region.kind == RegionKind.MAPPED_ROM:
            # Check if there is an offset mapped before (don't take default values)
            if self.mapped_rom_offset is None:
                raise MemoryError(f"Mapped memory offset for access to {address:#04X} is not defined! Define it first.")
            value = self.rom_image.rom[address + self.mapped_rom_offset]
        elif region.kind == RegionKind.IO:
            # IO access could be handled by hooks/mocks TODO macht das so überhaupt Sinn?
            if self.hooks and self.hooks.run_read_hooks(address, 0, self):
                print("TODO: IO read hook handled value...")
                value = 0  # Default/mock value
            else:
                raise NotImplementedError("IO region access not implemented.")
        else:
            raise ValueError(f"Unknown region kind: {region.kind}")
        
        #if address==0xD1:
        #    print(f"Read from 0x{address:04X}: 0x{value:02X}")

        
        self.__read_memory.add(address)
        return value

    def write(self, address: int, value: int):
        region = self.memory_map.region_lookup(address)
        if not region:
            raise ValueError(f"Address 0x{address:04X} not mapped to any region.")
            
        if region.kind == RegionKind.RAM:
            self.ram.write8(address - region.start, value)
        elif region.kind == RegionKind.IO:
            # IO access could be handled by hooks/mocks
            # TODO noch anders
            if self.hooks:
                self.hooks.run_write_hooks(address, value, self)
            else:
                raise NotImplementedError("IO region write not implemented.") # TODO Generell die Frage: IOs haben auch den RAM-Bereich?
        elif region.kind in (RegionKind.ROM, RegionKind.MAPPED_ROM):
            raise PermissionError(f"Cannot write to ROM or MAPPED_ROM region at 0x{address:04X}.")
        else:
            raise ValueError(f"Unknown region kind: {region.kind}")
        
        # If any write hooks, let them sabotage after the ROM code
        if self.hooks:
            self.hooks.run_write_hooks(address, value, self)
        
        self.__written_memory.add(address)

    def region_for(self, address: int) -> Optional[MemoryRegion]:
        return self.memory_map.region_lookup(address)
    
    def get_read_memory_addresses(self):
        return self.__read_memory

    def get_written_memory_addresses(self):
        return self.__written_memory

    # def __add_default_values(self):
    #     """
    #     Setzt typische Default-Werte für HD6303 (Stack Pointer etc.) in den RAM.
    #     """
    #     # Beispiel: Initial Stack Pointer Value und weitere Defaults
    #     # Annahme: RAM beginnt bei 0x0000
    #     # 0x01FF: Stack Pointer
    #     # 0x0200, 0x0201: weitere Initialwerte
    #     # Die Adressen werden auf RAM-Offset gemappt
    #     mapping = {
    #         0x01FF: 0xFF,
    #         0x0200: 0x00,
    #         0x0201: 0x00,
    #     }
    #     for addr, value in mapping.items():
    #         region = self.memory_map.region_lookup(addr)
    #         if region and region.kind == RegionKind.RAM:
    #             self.ram[addr - region.start] = value & 0xFF

    

    def read_bytes(self, address: int, length: int, *, allow_cross_region: bool = False, allow_hooks = True) -> bytes:
        """
        Liest 'length' Bytes ab 'address' effizient.
        - Nutzt Slicing statt Byte-für-Byte-Lesen.
        - Standardmäßig muss der Bereich in EINER Region liegen (schneller & sicherer).
        - Optional kann regionsübergreifend gelesen werden (allow_cross_region=True).
        """
        if length < 0:
            raise ValueError("length must be >= 0")
        if length == 0:
            return b""

        if not allow_cross_region:
            region = self.memory_map.region_lookup(address)
            if not region:
                raise ValueError(f"Address 0x{address:04X} not mapped to any region.")
            # Ermitteln, wie weit die Region reicht
            region_end = self._region_end_exclusive(region)
            end_addr = address + length
            if end_addr > region_end:
                raise ValueError(
                    f"Read range 0x{address:04X}-0x{end_addr-1:04X} crosses region boundary "
                    f"(region 0x{region.start:04X}-0x{region_end-1:04X}). "
                    "Set allow_cross_region=True if this is intentional."
                )
            view = self._slice_from_region(region, address, length)
            data = bytes(view)  # Kopie als immutable bytes (API-freundlich)
        else:
            # regionsübergreifend segmentieren
            segments = list(self._split_by_region(address, length))
            out = bytearray(length)
            out_pos = 0
            for seg_region, seg_addr, seg_len in segments:
                view = self._slice_from_region(seg_region, seg_addr, seg_len)
                out[out_pos:out_pos + seg_len] = view
                out_pos += seg_len
            data = bytes(out)

        # Hooks: einmal pro Block aufrufen (statt pro Byte)
        if self.hooks and allow_hooks:
            # Falls dein Hook-System einen Block-Hook unterstützt, hier verwenden:
            # self.hooks.run_read_block_hooks(address, data)
            # Fallback: einmaliger Call, ansonsten bitte Hook-API erweitern
            self.hooks.run_read_hooks(address, data[0] if data else 0, self)

        # Trace aktualisieren (alle Adressen markieren)
        self.__read_memory.update(range(address, address + length))
        return data

    def read_into(self, address: int, out_buffer: bytearray, *, allow_cross_region: bool = False) -> int:
        """
        Liest Bytes direkt in einen bereitgestellten Puffer (vermeidet zusätzliche Allokation).
        Gibt die Anzahl der geschriebenen Bytes zurück.
        """
        length = len(out_buffer)
        if length == 0:
            return 0

        if not allow_cross_region:
            region = self.memory_map.region_lookup(address)
            if not region:
                raise ValueError(f"Address 0x{address:04X} not mapped to any region.")
            region_end = self._region_end_exclusive(region)
            end_addr = address + length
            if end_addr > region_end:
                raise ValueError(
                    f"Read range 0x{address:04X}-0x{end_addr-1:04X} crosses region boundary "
                    f"(region 0x{region.start:04X}-0x{region_end-1:04X}). "
                    "Set allow_cross_region=True if this is intentional."
                )
            view = self._slice_from_region(region, address, length)
            out_buffer[:] = view
        else:
            segments = list(self._split_by_region(address, length))
            out_pos = 0
            for seg_region, seg_addr, seg_len in segments:
                view = self._slice_from_region(seg_region, seg_addr, seg_len)
                out_buffer[out_pos:out_pos + seg_len] = view
                out_pos += seg_len

        if self.hooks:
            self.hooks.run_read_hooks(address, out_buffer[0] if out_buffer else 0, self)

        self.__read_memory.update(range(address, address + length))
        return length

    # --------- Interne Helfer ---------

    def _region_end_exclusive(self, region) -> int:
        """
        Liefert das exklusive Ende der Region (eine Art 'stop'-Adresse).
        Passt sich an unterschiedliche Feldnamen der MemoryRegion an.
        """
        if hasattr(region, "end"):
            # Annahme: end ist EXKLUSIV
            return region.end
        if hasattr(region, "stop"):
            return region.stop
        if hasattr(region, "length"):
            return region.start + region.length
        if hasattr(region, "size"):
            return region.start + region.size
        # Fallback/Fehler – je nach deiner MemoryRegion-Definition evtl. anpassen
        raise AttributeError("MemoryRegion benötigt 'end', 'stop', 'length' oder 'size'.")

    def _slice_from_region(self, region, address: int, length: int):
        """
        Gibt eine memoryview-Scheibe auf die richtige Quelle (RAM/ROM/MAPPED_ROM) zurück.
        Achtung: Bei bytes (ROM) ist die view read-only (was ok ist fürs Lesen).
        """
        kind = region.kind
        if kind == RegionKind.RAM:
            offset = address - region.start
            data = self.ram.read_bytes(offset, length)
            return memoryview(data)

        if kind == RegionKind.ROM:
            # ROM: direkt aus dem Original-Image
            return memoryview(self.rom_image.rom)[address:address + length]

        if kind == RegionKind.MAPPED_ROM:
            if self.mapped_rom_offset is None:
                raise MemoryError(f"Mapped memory offset for access to 0x{address:04X} is not defined! Define it first.")
            base = address + self.mapped_rom_offset
            return memoryview(self.rom_image.rom)[base:base + length]

        if kind == RegionKind.IO:
            # Block-IO – je nach Hook-Design. Hier bewusst nicht automatisch simuliert.
            raise NotImplementedError("Block-Read für IO-Regionen ist nicht implementiert. Bitte Hooks verwenden.")
        raise ValueError(f"Unknown region kind: {kind}")

    def _split_by_region(self, address: int, length: int) -> Iterable[Tuple[MemoryRegion, int, int]]:
        """
        Teilt [address, address+length) in Region-separate Segmente auf.
        Gibt Tupel (region, seg_addr, seg_len) in Reihenfolge zurück.
        """
        remaining = length
        cur = address
        while remaining > 0:
            region = self.memory_map.region_lookup(cur)
            if not region:
                raise ValueError(f"Address 0x{cur:04X} not mapped to any region.")
            region_end = self._region_end_exclusive(region)
            # Anzahl Bytes, die noch in diese Region passen
            seg_len = min(remaining, region_end - cur)
            if seg_len <= 0:
                # Schutz, falls region_end == cur (inkonsistente Map)
                raise RuntimeError(f"Zero-length segment at 0x{cur:04X}; check MemoryMap for gaps/overlaps.")
            yield region, cur, seg_len
            cur += seg_len
            remaining -= seg_len
