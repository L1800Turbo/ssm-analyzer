from dataclasses import dataclass, field
import logging
from typing import Optional
from analyzer_core.config.ssm_model import ActionType, CurrentSelectedDevice, MasterTableEntry, MasterTableInfo, RomIdTableEntry_512kb, RomIdTableInfo, RomScalingDefinition, RomSwitchDefinition

@dataclass(frozen=True)
class MastertableIdentifier:
    '''
    Identifier for a ROMID Table Entry, consisting of Device and RomID
    '''
    romid: int  # Combined romid0, romid1, romid2 as integer

    dependend_values: Optional[tuple[ int, int ]] = None  # e.g., SVX96 AC: 2 Mastertables with 1 RomID but dependend on readout values

@dataclass
class SimpleMasterTableEntry:
    '''
    Simplified version of a Master Table Entry, only containing the data to be compared
    with other SSM cassettes
    '''
    label: str
    addresses: set[int]


@dataclass
class SimpleMeasurement(SimpleMasterTableEntry):
    #name: str
    scaling_expr: str
    unit: Optional[str] = None
    precision: Optional[int] = None
    lookup_table: Optional[dict[int|str, int|str]] = None

@dataclass
class SimpleSwitchDefinition(SimpleMasterTableEntry):
    # Can be taken from ssm_model as it's simple enough
    switches: list[RomSwitchDefinition] = field(default_factory=list)
    

@dataclass
class SimpleMasterTable:
    romid_str: str
    model: str
    year: str

    # TODO anders, einzeln
    #entries: dict[str, SimpleMasterTableEntry]

    measurements: dict[str, SimpleMeasurement] = field(default_factory=dict)
    switches: dict[str, SimpleSwitchDefinition] = field(default_factory=dict)

    # diags
    # ajustments
    # ...
    

logger = logging.getLogger(__name__)

class RomIdTableCollector:
    def __init__(self):
        self.romid_tables: dict[CurrentSelectedDevice, dict[MastertableIdentifier, SimpleMasterTable]] = {}  # key: device , romid -> SimpleMasterTable
        self.measurements: dict[str, SimpleMeasurement] = {}  # key: scaling name
    
    def add_ssm_cassette(self, ssm_romid_tables: dict[CurrentSelectedDevice, RomIdTableInfo]):
        for device, romid_table in ssm_romid_tables.items():
            for romid_entry in romid_table.entries:
                if isinstance(romid_entry, RomIdTableEntry_512kb):
                    self.add_romid_table(device, romid_entry)
                else:
                    raise NotImplementedError("Only RomIdTableEntry_512kb is currently supported")
    
    def add_romid_table(self, device:CurrentSelectedDevice, ssm_romid_table:RomIdTableEntry_512kb):

        if not device in self.romid_tables:
            self.romid_tables[device] = {}

        current_romid = (ssm_romid_table.romid0 << 16) + (ssm_romid_table.romid1 << 8) + ssm_romid_table.romid2
        current_identifier = MastertableIdentifier(romid=current_romid, dependend_values=ssm_romid_table.romid_identifier_value)

        if ssm_romid_table.master_table is None:
            logger.warning(f"RomIdTableEntry for device {device} RomID {current_romid:06X} has no MasterTable, skipping!")
            return

        create_new_entry = False
        # Check if the RomID already exists or create a new entry
        if not current_identifier in self.romid_tables[device]:
            self.romid_tables[device][current_identifier] = SimpleMasterTable(
                romid_str=ssm_romid_table.print_romid_str(),
                model=ssm_romid_table.ssm_model if ssm_romid_table.ssm_model else "",
                year=str(ssm_romid_table.ssm_year) if ssm_romid_table.ssm_year else ""
            )
            create_new_entry = True
        
        # Loop over all SSM Mastertable entries and add them if they match
        for ssm_mastertable in ssm_romid_table.master_table.entries:
            # Only add known actions
            if ssm_mastertable.action is None:
                continue

            if ssm_mastertable.action.action_type == ActionType.READ_ADDRESS:
                if ssm_mastertable.item_label is None:
                    raise ValueError(f"MasterTableEntry with Action {ssm_mastertable.action.action_type.name} has no item_label!")
                
                entry = None
                
                # Measurement entry
                if ssm_mastertable.action.scaling is not None:
                    entry = self.__get_create_scaling(
                        ssm_mastertable.item_label, 
                        ssm_mastertable.action.ecu_addresses, 
                        ssm_mastertable.action.scaling
                        )
                elif ssm_mastertable.action.switches:
                    entry = self.__get_create_switches(
                        ssm_mastertable.item_label,
                        ssm_mastertable.action.ecu_addresses,
                        ssm_mastertable.action.switches
                    )

                if entry is None:
                    continue  # unsupported action, skip for now

                counter = 1
                entry_label = f"{entry.label}_{counter}"
                while entry_label in self.romid_tables[device][current_identifier].measurements:
                    counter += 1
                    entry_label = f"{entry.label}_{counter}"
                

                # If this is a new RomID, just add the entry
                if create_new_entry:
                    if isinstance(entry, SimpleMeasurement):
                        self.romid_tables[device][current_identifier].measurements[entry_label] = entry   
                    elif isinstance(entry, SimpleSwitchDefinition):
                        self.romid_tables[device][current_identifier].switches[entry_label] = entry

                # Otherwise, compare existing entrys
                else:
                    if entry_label not in self.romid_tables[device][current_identifier].measurements:
                        raise NotImplementedError(f"New entry {entry_label} for device {device.name}, RomID identifier {current_identifier} not found in existing RomID table! Is this a second RomID table with the same RomID?")
                    existing_entry = self.romid_tables[device][current_identifier].measurements[entry_label]
                    
                    if existing_entry != entry:
                        raise ValueError(f"Conflict detected for device {device.name}, RomID {current_romid:06X}, entry {entry.label}!")


        
    
    def __get_create_scaling(self, action_name: str, ecu_addresses: set[int], ssm_scaling: RomScalingDefinition) -> SimpleMeasurement:
        
        # Create a unique name
        counter = 1
        name = f"{action_name}_{counter}"
        while name in self.measurements:
            counter += 1
            name = f"{action_name}_{counter}"
        
        current_scaling = SimpleMeasurement(
            label=action_name,
            addresses=ecu_addresses,
            scaling_expr=str(ssm_scaling.scaling),
            unit=ssm_scaling.unit,
            precision=ssm_scaling.precision_decimals,
            lookup_table=ssm_scaling.lookup_tables
        )

        self.measurements[name] = current_scaling
        return current_scaling
    
    def __get_create_switches(self, action_name: str, ecu_addresses: set[int], ssm_switches: list[RomSwitchDefinition]) -> SimpleSwitchDefinition:
        # TODO Doppelte Switch-Namen noch implementieren später
        
        current_switches = SimpleSwitchDefinition(
            label=action_name,
            addresses=ecu_addresses,
            switches=ssm_switches
        )

        return current_switches
        

