
import logging


logger = logging.getLogger(__name__)

class Ram:
    ''' 
    Represents the RAM of the emulated system.
    Not initialized memory should return a warning on read access.
    '''

    def __init__(self, size: int):
        self.size = size
        self.memory = bytearray(size)
        self.mask = bytearray(size // 8)  # Track initialized bytes

    @staticmethod
    def wrap(addr: int) -> int:        
        return addr & 0xFFFF

    def _get_bit(self, idx: int) -> int:
        return (self.mask[idx >> 3] >> (idx & 0x07)) & 0x01
    
    def _set_bit(self, idx: int):
        self.mask[idx >> 3] |= (1 << (idx & 0x07))
    

    def reset_mask(self):
        self.mask = bytearray(len(self.mask))  # Reset all to 0
    
    def read8(self, addr:int, default_value:int=0) -> int:
        addr = self.wrap(addr)
        
        if self._get_bit(addr) == 0:
            logger.warning(f"Read uninitialized RAM at 0x{addr:04X}, returning default value 0x{default_value:02X}")
            return default_value
        
        return self.memory[addr]
    
    def write8(self, addr:int, value:int):
        addr = self.wrap(addr)

        if not (0 <= value <= 0xFF):
            raise ValueError(f"Value {value} out of range for 8-bit write")

        self.memory[addr] = value & 0xFF
        self._set_bit(addr)

    
    def read_bytes(self, addr:int, length:int, default_value:int=0) -> bytearray:
        addr = self.wrap(addr)
        data = bytearray()

        for i in range(length):
            data.append(self.read8(addr + i, default_value=default_value))
        
        return data
    
    def write_bytes(self, addr:int, data:bytearray):
        addr = self.wrap(addr)

        for i, byte in enumerate(data):
            self.write8(addr + i, byte)
