from dataclasses import dataclass, field
import logging
from typing import Any, Optional
from analyzer_core.analyze.lookup_table_helper import LookupTableHelper
from analyzer_core.config.ssm_model import ActionType, CurrentSelectedDevice, RomIdTableEntryInfo, RomIdTableEntryRaw12, RomIdTableInfo, RomScalingDefinition, RomSwitchDefinition

@dataclass(frozen=True)
class MastertableIdentifier:
    '''
    Identifier for a ROMID Table Entry, consisting of Device and RomID
    '''
    romid: int  # Combined romid0, romid1, romid2 as integer

    dependend_values: Optional[tuple[ int, int ]] = None  # e.g., SVX96 AC: 2 Mastertables with 1 RomID but dependend on readout values

    def __str__(self):
        dependend_str = f", dependend_values={self.dependend_values}" if self.dependend_values else ""
        return f"MastertableIdentifier(romid=0x{self.romid:06X}{dependend_str})"

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

    source_cassettes: set[str] = field(default_factory=set)

    measurements: dict[str, SimpleMeasurement] = field(default_factory=dict)
    switches: dict[str, SimpleSwitchDefinition] = field(default_factory=dict)

    romid_identifier_value: Optional[tuple[int, int]] = None # Additional values like SVX96 AC


    # diags
    # ajustments
    # ...
    
class RomMismatchError(Exception):
    pass

logger = logging.getLogger(__name__)

class RomIdTableCollector:
    def __init__(self):
        self.romid_tables: dict[CurrentSelectedDevice, dict[MastertableIdentifier, SimpleMasterTable]] = {}  # key: device , romid -> SimpleMasterTable
        self.measurements: dict[str, SimpleMeasurement] = {}  # key: scaling name
    
    def add_ssm_cassette(self, cassette_name:str, ssm_romid_tables: dict[CurrentSelectedDevice, RomIdTableInfo]):
        for device, romid_table in ssm_romid_tables.items():
            for romid_entry in romid_table.entries:
                self.add_romid_table(cassette_name, device, romid_entry)
    
    def add_romid_table(self, cassette_name:str, device:CurrentSelectedDevice, ssm_romid_table:RomIdTableEntryInfo):
        '''
        Add a RomID with master table entry to the collector, create a new entry if the RomID doesn't exist
        '''

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
                year=str(ssm_romid_table.ssm_year) if ssm_romid_table.ssm_year else "",
                source_cassettes={cassette_name},
                romid_identifier_value=ssm_romid_table.romid_identifier_value
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
                
                new_entry = None
                
                # Measurement entry
                if ssm_mastertable.action.scaling is not None:
                    new_entry = self.__get_create_scaling(
                        ssm_mastertable.item_label, 
                        ssm_mastertable.action.ecu_addresses, 
                        ssm_mastertable.action.scaling
                        )
                elif ssm_mastertable.action.switches:
                    new_entry = self.__get_create_switches(
                        ssm_mastertable.item_label,
                        ssm_mastertable.action.ecu_addresses,
                        ssm_mastertable.action.switches
                    )

                if new_entry is None:
                    continue  # unsupported action, skip for now

                # Determine the number of labels and create a unique label if a new one will need to be created
                counter = 1
                entry_label = f"{new_entry.label}_{counter}"
                while entry_label in self.romid_tables[device][current_identifier].measurements:
                    counter += 1
                    entry_label = f"{new_entry.label}_{counter}"
                

                # If this is a new RomID, just add the entry
                if create_new_entry:
                    if isinstance(new_entry, SimpleMeasurement):
                        self.romid_tables[device][current_identifier].measurements[entry_label] = new_entry   
                    elif isinstance(new_entry, SimpleSwitchDefinition):
                        self.romid_tables[device][current_identifier].switches[entry_label] = new_entry

                # Otherwise, compare existing entries
                else:
                    # Add the current cassette's name as source for this entry
                    self.romid_tables[device][current_identifier].source_cassettes.add(cassette_name)


                    # Loop over all existing entries with the same label and check if one matches, otherwise raise conflict
                    if isinstance(new_entry, SimpleMeasurement):
                        existing_entries = self.romid_tables[device][current_identifier].measurements
                        no_possible_entries = counter + 1

                        for i in range(1, no_possible_entries+1):
                            existing_label = f"{new_entry.label}_{i}"
                            if existing_label in existing_entries:
                                existing_entry = existing_entries[existing_label]
                                if existing_entry == new_entry:
                                    return True
                        
                        raise RomMismatchError(f"Conflict detected for device {device.name}, RomID {current_romid:06X}, entry {new_entry.label}")
                    elif isinstance(new_entry, SimpleSwitchDefinition):
                        existing_entries = self.romid_tables[device][current_identifier].switches
                        no_possible_entries = counter + 1

                        # Compare switches by address
                        for existing_label, existing_entry in existing_entries.items():
                            if existing_entry.addresses == new_entry.addresses and existing_entry.switches == new_entry.switches:
                                if existing_entry.label != new_entry.label:
                                    logger.warning(f"Switch entry with same addresses and switch definition but different label found for device {device.name}, RomID {current_romid:06X}: "
                                                   f"existing entry {existing_entry.label} with addresses {existing_entry.addresses} and switches {existing_entry.switches}, "
                                                   f"new entry {new_entry.label} with addresses {new_entry.addresses} and switches {new_entry.switches}. Keeping existing label.")
                                return True
                        
                        raise RomMismatchError(f"Conflict detected for device {device.name}, RomID {current_romid:06X}, entry {new_entry.label}")
        
    
    def __get_create_scaling(self, action_name: str, ecu_addresses: set[int], ssm_scaling: RomScalingDefinition) -> SimpleMeasurement:
        
        # Create a unique name
        counter = 1
        name = f"{action_name}_{counter}"
        while name in self.measurements:
            counter += 1
            name = f"{action_name}_{counter}"

        # TODO Prüfung, ob mehr als eine LUT vorhanden ist, dann dürfte man das substitute ohne Adressangabe nicht machen

        substituted_scaling = LookupTableHelper.substitute_lookup_tables(ssm_scaling.scaling, generalize_name=True)
        
        current_scaling = SimpleMeasurement(
            label=action_name,
            addresses=ecu_addresses,
            scaling_expr=str(substituted_scaling),
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
        

