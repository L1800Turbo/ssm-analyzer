

class ByteInterpreter:
    '''
    SSMs use individual charsets for some tokens. They can be added here
    '''

    def __init__(self, mapping = None, printable=(32,127), hex_fallback = True) -> None:
        self.mapping = mapping or {}
        self.printable = printable
        self.hex_fallback = hex_fallback
    
    def add(self, b: int, s:str):
        self.mapping[b & 0xFF] = s
    
    def render(self, data:bytes) -> str:
        lo,hi = self.printable
        out = []

        for b in data:
            if b in self.mapping:
                out.append(self.mapping[b])
            elif lo <= b < hi:
                out.append(chr(b))
            else:
                # Aggressive for tests
                raise ValueError(f"Unknown byte {b:02X}")
                out.append(f"\\x{b:02X}" if self.hex_fallback else "?")
        
        return "".join(out)

