# SymbolTable: Verwaltung von Funktionen, Variablen, Ports und Strings
# Bidirektionale Zuordnung Name↔Adresse, Konflikt-Checks, keine ROM-Zugriffe

from enum import Enum, auto
from typing import Dict, Optional, Set, List

class SymbolError(Exception):
    pass

class SymbolType(Enum):
    FUNCTION = auto()
    VARIABLE = auto()
    PORT = auto()
    STRING = auto()

class Symbol:
    def __init__(self, name: str, address: int, typ: SymbolType):
        self.name = name
        self.address = address
        self.type = typ
    def __repr__(self):
        return f"<Symbol name={self.name!r} addr=0x{self.address:04X} type={self.type.name}>"

class SymbolTable:
    def __init__(self):
        self._symbols_by_addr: Dict[int, Symbol] = {}
        self._symbols_by_name: Dict[str, Symbol] = {}
        self._types: Dict[SymbolType, Set[str]] = {t: set() for t in SymbolType}

    def add_symbol(self, name: str, address: int, typ: SymbolType) -> Optional[str]:
        # Konflikt- und Duplikat-Check
        if name in self._symbols_by_name:
            raise SymbolError(f"Name {name} already exists.")
        if address in self._symbols_by_addr:
            raise SymbolError(f"Address 0x{address:04X} already exists.")
        sym = Symbol(name, address, typ)
        self._symbols_by_name[name] = sym
        self._symbols_by_addr[address] = sym
        self._types[typ].add(name)
        return None

    def get_by_address(self, address: int) -> Optional[Symbol]:
        return self._symbols_by_addr.get(address)

    def get_by_name(self, name: str) -> Optional[Symbol]:
        return self._symbols_by_name.get(name)

    def all_symbols(self, typ: Optional[SymbolType] = None) -> List[Symbol]:
        if typ:
            return [self._symbols_by_name[n] for n in self._types[typ]]
        return list(self._symbols_by_name.values())

    def address_by_name(self, name: str) -> Optional[int]:
        sym = self._symbols_by_name.get(name)
        return sym.address if sym else None

    def name_by_address(self, address: int) -> Optional[str]:
        sym = self._symbols_by_addr.get(address)
        return sym.name if sym else None

    # def check_duplicates(self) -> List[str]:
    #     # Prüft auf doppelte Namen/Adressen
    #     errors = []
    #     names = set()
    #     addrs = set()
    #     for sym in self._symbols_by_name.values():
    #         if sym.name in names:
    #             errors.append(f"Duplikat Name: {sym.name}")
    #         names.add(sym.name)
    #         if sym.address in addrs:
    #             errors.append(f"Duplikat Adresse: 0x{sym.address:04X}")
    #         addrs.add(sym.address)
    #     return errors

    def __repr__(self):
        return f"SymbolTable({len(self._symbols_by_name)} Symbole)"
