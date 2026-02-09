from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Union

#from analyzer_core.analyze.lookup_table_helper import LookupTable
from analyzer_core.analyze.repo import PatternRepository
from analyzer_core.config.memory_map import MemoryMap
from analyzer_core.config.ssm_model import CurrentSelectedDevice, RomIdTableInfo, RomScalingDefinition
from analyzer_core.disasm.insn_model import Instruction
from analyzer_core.emu.memory_manager import MemoryManager

class RomConfigError(Exception):
    pass

class RomVarType(Enum):
    FUNCTION = auto()
    VARIABLE = auto()
    PORT = auto()
    STRING = auto()
    LOOKUP_TABLE = auto()
    LABEL = auto()

@dataclass
class RomVarDefinition:
    name: str
    rom_address: Optional[int]
    mapped_address: Optional[int] # Usually the mapped address, so including offsets
    type: RomVarType
    size: Optional[int] = None

    callers: Optional[list[int]] = None  # For functions and labels: list of addresses that call this function

@dataclass(frozen=True)
class ScalingFunctionIdentifier:
    mapped_address: int
    current_device: CurrentSelectedDevice   
    

    # When a scaling functions needs to be called multiple times as it's depending on RomID values
    # E.g. IMPREZA96 cruise: 0x3793 gets called for two RomIDs, but the function inside depends on RomID[5] (current_romid_scaling_index)
    dependend_values: tuple[tuple[ int, int ], ...] = field(default_factory=tuple)

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
        # As index: use the original ROM address, not the mapped one
        self.instructions: dict[int, Instruction] = {}
        self.call_tree: dict = {}
        self.action_addresses: set[int] = set()
        self.scaling_addresses: dict[ScalingFunctionIdentifier, RomScalingDefinition] = {}
        self.lookup_tables: dict[str, type["LookupTable"]] = {} # type: ignore

        # Pattern for detection
        self.pattern_repo: PatternRepository

        # Devices that actually exist on the cassette
        self.selectable_devices: list[CurrentSelectedDevice] = []

        self.__offsets: dict[CurrentSelectedDevice, int] = {}
        self.romid_tables: dict[CurrentSelectedDevice, RomIdTableInfo] = {}

        self.add_offset(CurrentSelectedDevice.UNDEFINED, 0x0000)

        # Ports/DDR
        # TODO nicht auf Dauer hier lassen
        self.add_port("PORT2", CurrentSelectedDevice.UNDEFINED, 0x03)
        self.add_port("DDR2", CurrentSelectedDevice.UNDEFINED, 0x01)
        self.add_port("PORT5", CurrentSelectedDevice.UNDEFINED, 0x15)
        self.add_port("PORT6", CurrentSelectedDevice.UNDEFINED, 0x17)
        self.add_port("DDR6", CurrentSelectedDevice.UNDEFINED, 0x16)
        self.__stack_pointer = 0x01FF

    # ------------------- Add -------------------
    def add_port(self, name: str, current_device: CurrentSelectedDevice, address: int):
        var = RomVarDefinition(name=name, rom_address=address, mapped_address=self.get_mapped_address(address, current_device), type=RomVarType.PORT)
        self._register(var)

    def add_rom_var_type(self, var_def: RomVarDefinition):
        # TODO skippen wenn schon da
        self._register(var_def)
    
    def add_var(self, name: str, current_device: CurrentSelectedDevice, address:Optional[int]=None):
        var = RomVarDefinition(name=name, rom_address=address, mapped_address=self.get_mapped_address(address, current_device) if address is not None else None, type=RomVarType.VARIABLE)
        self._register(var)

    def add_string(self, name: str, address: int, length: int, current_device: CurrentSelectedDevice):
        var = RomVarDefinition(name=name, rom_address=address, mapped_address=self.get_mapped_address(address, current_device), type=RomVarType.STRING, size=length)
        self._register(var)
    
    def add_lut(self, name: str, address: int, size: int, current_device: CurrentSelectedDevice):
        var = RomVarDefinition(name=name, rom_address=address, mapped_address=self.get_mapped_address(address, current_device), type=RomVarType.LOOKUP_TABLE, size=size)
        self._register(var)

    def add_refresh_function(self, name:str, rom_address: int, current_device: CurrentSelectedDevice, callers: Optional[list[int]] = [], rename: bool = False):
        var = self.get_by_address(rom_address)
        if var is None:
            self._register(RomVarDefinition(name=name, rom_address=rom_address, mapped_address=self.get_mapped_address(rom_address, current_device), type=RomVarType.FUNCTION, callers=callers))            
        else:
            self._refresh_function(var, name, rom_address, callers, rename)
    
    def add_refresh_mapped_function(self, name: str, mapped_address: int, current_device: CurrentSelectedDevice, callers: Optional[list[int]] = [], rename: bool = False):
        # TODO eigentlich get_original_address hier, aber mit z.b. egi -0x2000 würde er ja z.b. 2de4 auf 4de4 mappen statt 0de4
        rom_address = self.get_mapped_address(mapped_address, current_device)
        var = self.get_by_address(rom_address)
        if var is None:
            self._register(RomVarDefinition(name=name, rom_address=rom_address, mapped_address=mapped_address, type=RomVarType.FUNCTION, callers=callers))            
        else:
            self._refresh_function(var, name, rom_address, callers, rename)
    
    def add_refresh_label(self, name:str, rom_address: int, current_device: CurrentSelectedDevice, callers: Optional[list[int]] = [], rename: bool = False):
        var = self.get_by_address(rom_address)
        if var is None:
            self._register(RomVarDefinition(name=name, rom_address=rom_address, mapped_address=self.get_mapped_address(rom_address, current_device), type=RomVarType.LABEL, callers=callers))            
        else:
            self._refresh_function(var, name, rom_address, callers, rename)

    def _refresh_function(self, var: RomVarDefinition, name:str, rom_address: int, callers: Optional[list[int]] = [], rename: bool = False):
        var.rom_address = rom_address
        if var.callers is None:
            var.callers = []

        # if rom_address in var.callers:
        #     pass
        for caller in callers or []:
            if caller not in var.callers:
                var.callers.append(caller)
        
        if rename and var.name != name:
            self._rename(var.name, name)
    
    def add_var_address(self, name:str, address:int, current_device: CurrentSelectedDevice):
        var = self.get_by_name(name)
        if var is None:
            self._register(RomVarDefinition(name=name, rom_address=address, mapped_address=self.get_mapped_address(address, current_device), type=RomVarType.VARIABLE))
        else:
            var.rom_address = address

    def _register(self, var: RomVarDefinition):
        if var.name in self._by_name:
            raise ValueError(f"Variable with name '{var.name}' already exists.")
        if var.rom_address is not None and var.rom_address in self._by_address:
            raise ValueError(f"Variable with address '{var.rom_address}' already exists.")
    
        self._by_name[var.name] = var
        if var.rom_address is not None:
            self._by_address[var.rom_address] = var
        # setattr erlaubt Zugriff als Attribut
        setattr(self, var.name, var)

    def _rename(self, old_name: str, new_name: str):
        var = self.get_by_name(old_name)
        if var is None:
            raise RomConfigError(f"Variable with name '{old_name}' does not exist.")
        if new_name in self._by_name:
            raise RomConfigError(f"Variable with name '{new_name}' already exists.")
        
        del self._by_name[old_name]
        var.name = new_name
        self._by_name[new_name] = var
        setattr(self, new_name, var)
        delattr(self, old_name)

    # ------------------- Access -------------------
    def get_by_name(self, name: str) -> Union[RomVarDefinition, None]:
        return self._by_name.get(name)

    def get_by_address(self, address: int) -> Union[RomVarDefinition, None]:
        return self._by_address.get(address)

    def check_for_name(self, name: str) -> bool:
        rom_var = self.get_by_name(name)
        return rom_var is not None and rom_var.rom_address is not None
    
    def check_for_function_address(self, address: int) -> bool:
        rom_var = self.get_by_address(address)
        return rom_var is not None and rom_var.type == RomVarType.FUNCTION and rom_var.rom_address is not None

    def address_by_name(self, name: str) -> int:
        rom_var = self.get_by_name(name)
        if rom_var is None:
            raise RomConfigError(f"{name} address unknown")
        if rom_var.rom_address is None:
            raise RomConfigError(f"{name} address is None")
        return rom_var.rom_address
    
    # def mapped_address_by_name(self, name: str) -> int:
    #     rom_var = self.get_by_name(name)
    #     if rom_var is None:
    #         raise RomConfigError(f"{name} mapped address unknown")
    #     if rom_var.mapped_address is None:
    #         raise RomConfigError(f"{name} mapped address is None")
    #     return rom_var.mapped_address


    def all_items(self):
        return self._by_name

    # Optional: Iteration nach Typ
    def all_ports(self):
        return {k: v for k, v in self._by_name.items() if v.type == RomVarType.PORT}

    def all_functions(self):
        return {k: v for k, v in self._by_address.items() if v.type == RomVarType.FUNCTION}
    
    def all_vars(self):
        return {k: v for k, v in self._by_name.items() if v.type == RomVarType.VARIABLE}
    
    # ------------------- ROM Offsets -------------------
    def add_offset(self, dev: CurrentSelectedDevice, offset: int):
        self.__offsets[dev] = offset
    
    def get_offset(self, dev: CurrentSelectedDevice) -> int:
        return self.__offsets[dev]
    
    def get_mapped_address(self, original_address: int, current_device: CurrentSelectedDevice) -> int:
        '''
        Return the mapped address for a given original ROM address, considering mapped regions.
        '''

        # Check if it's in mapped region
        if MemoryMap().in_mapped_rom(original_address):
            #if current_device == CurrentSelectedDevice.UNDEFINED:
            #    raise RomConfigError("Current device is UNDEFINED, cannot get mapped address.")
        
            offset = self.get_offset(current_device)
            return original_address + offset
        return original_address
    
    # def get_original_address(self, mapped_address: int, current_device: CurrentSelectedDevice) -> int:
    #     '''
    #     Return the original ROM address for a given mapped address, considering mapped regions.
    #     '''

    #     # Check if it's in mapped region
    #     offset = self.get_offset(current_device)
    #     possible_original = mapped_address - offset
    #     if MemoryMap().in_mapped_rom(possible_original):
    #         return possible_original
    #     return mapped_address
    
    # ------------------- Stack pointers -------------------
    def set_stack_pointer(self, stack_pointer:int) -> None:
        self.__stack_pointer = stack_pointer
    
    def get_stack_pointer(self) -> int:
        return self.__stack_pointer
    

    def get_scaling_functions(self, current_device: CurrentSelectedDevice, mapped_address: int) -> dict[ScalingFunctionIdentifier, RomScalingDefinition]:
        return { identifier: scaling for identifier, scaling in self.scaling_addresses.items() if identifier.mapped_address == mapped_address and identifier.current_device == current_device }

        