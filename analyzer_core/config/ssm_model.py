# SsmModel
# RomIdTableInfo, MasterTableInfo, Label/Scaling Metadaten.


from dataclasses import dataclass, field
from enum import IntEnum
import struct
from typing import Optional, Union

# Circular imports avoided
# from analyzer_core.ssm.action_functions.action_helper import SsmAction

class RomEmulationError(Exception):
    pass

class CurrentSelectedDevice(IntEnum):
    EGI = 0x01
    AT  = 0x02
    AC  = 0x04
    CC  = 0x08
    ABS = 0x10
    TCS = 0x20
    FWS = 0x40 # 4WS

@dataclass
class RomIdTableInfo:
    #device: "CurrentSelectedDevice"
    relative_pointer_addr: int
    length: int

    #entries: list["RomIdTableEntry_512kb"] # TODO und die andere?
    entries: list[Union["RomIdTableEntry_256kb", "RomIdTableEntry_512kb"]]


@dataclass
class RomIdTableEntry:
    romid0:int
    romid1:int
    romid2:int

    scaling_index:int
    label_index:int
    menuitems_index:int
    ecu_addresses_rel:int # Needs offset adaption on some ECUs

@dataclass
class RomIdTableEntry_256kb(RomIdTableEntry):
    entry_size=0 # TODO, wie breit?

    struct_format = "<B" # Dummy, da noch nicht definiert
    entry_size = struct.calcsize(struct_format)  # = 12 Bytes

    ssm_year: Optional[int] = None  # TODO Das eigentlich noch nach oben, aber wie füllt man dann die RomIDtabelle vernünftig
    ssm_model: Optional[str] = None

    @classmethod
    def from_bytes(cls, table_bytes:bytes) -> "RomIdTableEntry_512kb":
        unpacked = struct.unpack(cls.struct_format, table_bytes)
        return RomIdTableEntry_512kb(*unpacked)
    


@dataclass
class RomIdTableEntry_512kb(RomIdTableEntry):
    '''
    RomID table as used on '96 onwards
    '''
    master_table_address_rel:int # Needs offset adaption on some ECUs
    romid_a:int #<!-- Adjustment index only high byte! --><!-- TODO: und Error 66 check flag in HI -->
    tbd_b:int
    romid_model_index:int
    flagbytes:int

    struct_format = ">BBBBBBHHBBBB"
    entry_size = struct.calcsize(struct_format)  # = 12 Bytes

    ssm_cmd_protocols: Optional[list[tuple[int,int]]] = None
    request_romid_cmd: Optional[tuple[int,int,int,int]] = None

    entry_ptr_address: Optional[int] = None

    # Values defined in fn_attach_cu_specific_addresses
    # These values depend in most cases only on the ECU type, but rarely also on the RomID
    max_length_menuitems:Optional[int] = None
    max_length_hidden_menuitems:Optional[int] = None
    temporary_menuitems_pointer:Optional[int] = None # Will be adjusted from RomID[5] into final_menuitems_pointer
    temporary_hidden_menuitems_pointer:Optional[int] = None # This pointer should depend on RomID[5] in a following function
    menuitems_upper_label_pointer:Optional[int] = None
    menuitems_lower_label_pointer:Optional[int] = None
    adjustments_label_pointer:Optional[int] = None
    current_scale_fn_table_pointer:Optional[int] = None
    romid_upper_label_pointer:Optional[int] = None
    romid_lower_label_pointer:Optional[int] = None

    final_menuitems_pointer:Optional[int] = None

    # To be determined by YEAR action
    ssm_year: Optional[int] = None
    ssm_model: Optional[str] = None

    # TODO Year in ausgewertet dazu

    master_table: Optional["MasterTableInfo"] = None

    @classmethod
    def from_bytes(cls, table_bytes:bytes) -> "RomIdTableEntry_512kb":
        unpacked = struct.unpack(cls.struct_format, table_bytes)
        return RomIdTableEntry_512kb(*unpacked)
    
    def print_romid_str(self):
        return f"{self.romid0:02X} {self.romid1:02X} {self.romid2:02X}"
    

@dataclass
class MasterTableInfo:
    pointer_addr_rel: int # Offset depends on ECU
    length: int

    entries: list["MasterTableEntry"]

@dataclass
class MasterTableEntry:
    menu_item_0: int # like  8F	80	81
    menu_item_1: int
    menu_item_2: int
    mt_index_3_tbd: int
    action_address_rel: int # Offset depends on ECU
    scaling_index: int
    address_index: int
    upper_label_index: int
    lower_label_index: int
    adjustments_label_index: int

    # TODO Undefined, yet
    master_table_0xB: int
    master_table_0xC: int
    master_table_0xD: int

    struct_format = ">BBBBHBBBBBBBB"
    entry_size = struct.calcsize(struct_format)  # = 12 Bytes

    hidden: Optional[bool] = False

    # The upper label as shown on SSM
    upper_label: Optional[str] = ""
    #lower_label: Optional[str] = "" # TODO noch weg, oder? Kommt erst in der Action

    # The actual item's label
    item_label: Optional[str] = None

    action: Optional["SsmAction"] = None

    def menu_item_str(self):
        return f"{(self.menu_item_0&0xF):0X}{(self.menu_item_1&0xF):0X}{(self.menu_item_2&0xF):0X}"

    @classmethod
    def from_bytes(cls, table_bytes:bytes) -> "MasterTableEntry":
        unpacked = struct.unpack(cls.struct_format, table_bytes)
        return MasterTableEntry(*unpacked)


class ActionType(IntEnum):
    UNDEFINED = 0
    YEAR = 1
    READ_ADDRESS = 2
    #...

@dataclass
class RomScalingDefinition:
    scaling: str
    precision_decimals: int
    unit: Optional[str] = None
    functions: list[str] = field(default_factory=list)

@dataclass
class RomSwitchDefinition:
    name: str
    inverted: bool
    bit: int # 0-7

    
@dataclass
class SsmAction:
    action_type: ActionType

    upper_label_raw: str
    lower_label_raw: Optional[str] = None

    ecu_addresses: list[int] = field(default_factory=list)

    scaling: Optional[RomScalingDefinition] = None
    switches: Optional[list[RomSwitchDefinition]] = None




    