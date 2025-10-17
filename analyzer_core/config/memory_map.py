# MemoryMap
# MemoryRegion-Objekte, Profile laden, Region-Lookup.

from enum import Enum, auto
from dataclasses import dataclass
from typing import List, Optional, Dict
import yaml
from pathlib import Path

class RegionKind(Enum):
    RAM = auto()
    ROM = auto()
    IO = auto()
    MAPPED_ROM = auto()

@dataclass
class MemoryRegion:
    kind: RegionKind
    start: int
    end: int
    name: str

    def contains(self, address: int) -> bool:
        return self.start <= address <= self.end

class MemoryMap:
    def __init__(self, regions: Optional[List[MemoryRegion]] = None):
        self.regions = regions if regions else self.get_default_ssm_values()
        self._by_kind: Dict[RegionKind, List[MemoryRegion]] = {}
        for region in self.regions:
            self._by_kind.setdefault(region.kind, []).append(region)
    
    # TODO in config?
    def get_default_ssm_values(self):
        return [
                MemoryRegion(start=0x0000, end=0x1FFF, kind=RegionKind.RAM, name="RAM"),               # 8 KB RAM
                MemoryRegion(start=0x2000, end=0x3FFF, kind=RegionKind.MAPPED_ROM, name="MAPPED_ROM"), # 8 KB Mapped ROM from 0x2000, needs to be attached first
                MemoryRegion(start=0x8000, end=0xFFFF, kind=RegionKind.ROM, name="ROM"),               # 32 KB ROM from 0x8000
                
                # Optional: IO, TODO
            ]

    @classmethod
    def from_profile_yaml(cls, yaml_path: Path, profile_name: str = "default") -> "MemoryMap":
        with open(yaml_path, "r", encoding="utf-8") as f:
            profiles = yaml.safe_load(f)
        if profile_name not in profiles:
            raise ValueError(f"Profil '{profile_name}' nicht gefunden in {yaml_path}")
        regions = []
        for kind_str, region in profiles[profile_name].items():
            kind = RegionKind[kind_str.upper()]
            regions.append(MemoryRegion(
                kind=kind,
                start=int(region["start"], 0),
                end=int(region["end"], 0),
                name=kind_str
            ))
        return cls(regions)

    def region_lookup(self, address: int) -> Optional[MemoryRegion]:
        for region in self.regions:
            if region.contains(address):
                return region
        return None

    def regions_by_kind(self, kind: RegionKind) -> List[MemoryRegion]:
        return self._by_kind.get(kind, [])

    def __repr__(self):
        return f"MemoryMap({len(self.regions)} Regions)"
