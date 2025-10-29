from enum import Enum, auto
from dataclasses import dataclass
from typing import List, Optional, Union

from analyzer_core.analyze.repo import PatternRepository
from analyzer_core.config.byte_interpreter import ByteInterpreter
from analyzer_core.config.ssm_model import CurrentSelectedDevice, RomIdTableInfo
from analyzer_core.disasm.insn_model import Instruction

class RomConfigError(Exception):
    pass

class RomVarType(Enum):
    FUNCTION = auto()
    VARIABLE = auto()
    PORT = auto()
    STRING = auto()

@dataclass
class RomVarDefinition:
    name: str
    address: Optional[int]
    type: RomVarType
    size: Optional[int] = None

# TODO Noch sinnvoll hier:
# RomVarType enthalt jetzt STIRNGS, aber was ist mit Adressen wie z.B. einer Mastertabelle und sowas? Also alles, was irgendwie "fix" im ROM klebt


OFFSET_PIN_ASSIGNMENTS = [
    {"p5_2": 0, "p6_7": 0, "offset": -0x2000},
    {"p5_2": 1, "p6_7": 0, "offset": 0x0000},
    {"p5_2": 0, "p6_7": 1, "offset": 0x2000},
    {"p5_2": 0, "p6_7": 1, "offset": 0x2000},
    {"p5_2": 1, "p6_7": 1, "offset": 0x4000},
    {"p5_2": 1, "p6_7": 1, "offset": 0x4000},
]

class RomConfig:

    def __init__(self):
        self._by_name: dict[str, RomVarDefinition] = {}
        self._by_address: dict[int, RomVarDefinition] = {}

        self._rom_vars: dict[str, RomVarDefinition] = {}

        # Instructions and call tree being collected by disassembler
        self.instructions: dict[int, Instruction] = {}
        self.call_tree: dict = {}
        self.action_addresses: set[int] = set()

        # Pattern for detection
        self.pattern_repo: PatternRepository

        # Devices that actually exist on the cassette
        self.selectable_devices: list[CurrentSelectedDevice] = []

        self.__offsets: dict[CurrentSelectedDevice, int] = {}
        self.romid_tables: dict[CurrentSelectedDevice, RomIdTableInfo] = {}

        self.byte_interpreter = ByteInterpreter()
        self.byte_interpreter.add(0xA5, "᛫")
        self.byte_interpreter.add(0xDF, "°")

        # Ports/DDR
        # TODO nicht auf Dauer hier lassen
        self.add_port("PORT2", 0x03)
        self.add_port("DDR2",  0x01)
        self.add_port("PORT5", 0x15)
        self.add_port("PORT6", 0x17)
        self.add_port("DDR6",  0x16)

        self.__stack_pointer = 0x01FF

    # ------------------- Add -------------------
    def add_port(self, name: str, address: int):
        var = RomVarDefinition(name=name, address=address, type=RomVarType.PORT)
        self._register(var)

    def add_function(self, name: str, address=None):
        var = RomVarDefinition(name=name, address=address, type=RomVarType.FUNCTION)
        self._register(var)
    
    def add_var(self, name: str, address=None):
        var = RomVarDefinition(name=name, address=address, type=RomVarType.VARIABLE)
        self._register(var)

    def add_string(self, name: str, address: int, length: int):
        var = RomVarDefinition(name=name, address=address, type=RomVarType.STRING, size=length)
        self._register(var)

    def add_function_address(self, name:str, address:int):
        var = self.get_by_name(name)
        if var is None:
            self._register(RomVarDefinition(name=name, address=address, type=RomVarType.FUNCTION))
        else:
            var.address = address

    def add_var_address(self, name:str, address:int):
        var = self.get_by_name(name)
        if var is None:
            self._register(RomVarDefinition(name=name, address=address, type=RomVarType.VARIABLE))
        else:
            var.address = address

    def _register(self, var: RomVarDefinition):
        if var.name in self._by_name:
            raise ValueError(f"Variable mit Namen '{var.name}' existiert bereits.")
        if var.address is not None and var.address in self._by_address:
            raise ValueError(f"Variable mit Adresse '{var.address}' existiert bereits.")
    
        self._by_name[var.name] = var
        if var.address is not None:
            self._by_address[var.address] = var
        # setattr erlaubt Zugriff als Attribut
        setattr(self, var.name, var)

    # ------------------- Access -------------------
    def get_by_name(self, name: str) -> Union[RomVarDefinition, None]:
        return self._by_name.get(name)

    def get_by_address(self, address: int) -> Union[RomVarDefinition, None]:
        return self._by_address.get(address)

    def check_for_address(self, name: str) -> bool:
        rom_var = self.get_by_name(name)
        return rom_var is not None and rom_var.address is not None

    def address_by_name(self, name: str) -> int:
        rom_var = self.get_by_name(name)
        if rom_var is None:
            raise RomConfigError(f"{name} address unknown")
        if rom_var.address is None:
            raise RomConfigError(f"{name} address is None")
        return rom_var.address


    def all_items(self):
        return self._by_name

    # Optional: Iteration nach Typ
    def all_ports(self):
        return {k: v for k, v in self._by_name.items() if v.type == RomVarType.PORT}

    def all_functions(self):
        return {k: v for k, v in self._by_name.items() if v.type == RomVarType.FUNCTION}
    
    def all_vars(self):
        return {k: v for k, v in self._by_name.items() if v.type == RomVarType.VARIABLE}
    
    # ------------------- ROM Offsets -------------------
    def add_offset(self, dev: CurrentSelectedDevice, offset: int):
        self.__offsets[dev] = offset
    
    def get_offset(self, dev: CurrentSelectedDevice) -> int:
        return self.__offsets[dev]
    
    # ------------------- Stack pointers -------------------
    def set_stack_pointer(self, stack_pointer:int) -> None:
        self.__stack_pointer = stack_pointer
    
    def get_stack_pointer(self) -> int:
        return self.__stack_pointer
