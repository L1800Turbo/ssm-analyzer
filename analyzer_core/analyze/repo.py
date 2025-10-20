# SignatureRepository
# Loads versioned pattern sets (e.g. signatures/v1/rom_signatures.json).

import json
from pathlib import Path
from typing import Any, Dict, List

class PatternRepository:
    def __init__(self, json_path: Path):
        self.json_path = json_path
        self.patterns: Dict[str, Any] = {}
        self.version: str = ""
        self._load()

    def _load(self):
        with open(self.json_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        self.version = self.data.get("version", "")
        #self.fn_patterns = data.get("functions", [])
        self.string_patterns = self.data.get("strings", {})

    def get_patterns(self, pattern_group:str) -> List[Dict[str, Any]]:
        return self.data.get(pattern_group)

    #def get_fn_patterns(self) -> List[Dict[str, Any]]:
    #    return self.fn_patterns

    def get_string_patterns(self) -> Dict[str, str]:
        return self.string_patterns

    def get_version(self) -> str:
        return self.version
