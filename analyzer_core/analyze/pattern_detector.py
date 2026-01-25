# SignatureEngine
# Window-based matcher: skip, capture VAR/FN/REF, min_skip, alternatives. Returns SignatureResult.

import ast
import logging
from pathlib import Path
import re
from typing import List, Dict, Any, Optional

from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import CurrentSelectedDevice
from analyzer_core.disasm.insn_model import Instruction


class SignatureError(Exception):
    pass

class SignatureNotFound(Exception):
    pass

class PatternDetector:
    def __init__(self, rom_cfg: RomConfig, current_device: Optional[CurrentSelectedDevice] = None) -> None:
        self.logger = logging.getLogger(__name__)

        self.repo = rom_cfg.pattern_repo
        #self.fn_patterns = repo.get_fn_patterns()
        self.rom_cfg = rom_cfg
        self.current_device = current_device

        self.found_signatures = set()

    def detect_patterns(self, instructions: dict[int, Instruction], pattern_group:str, no_warnings = False) -> dict[str, int]:
        signatures = self.repo.get_patterns(pattern_group)
        #self.fn_patterns

        # Get all patterns as missing to be detected one after another
        #missing = [step["name"] for step in signatures]

        # Get all patterns not existing in rom_cfg as missing to be detected one after another
        missing = [step["name"] for step in signatures if "name" in step and step["name"] not in self.rom_cfg.all_items()]


        this_found_signatures:dict[str, int] = {}

        # Loop while missing patterns exist
        while missing:
            for sig in signatures:
                name = sig["name"]

                #if self.rom_cfg.get_by_name(name) is not None:
                #    continue

                if name in self.found_signatures:
                    # Workaround when a second pattern with this name was already found
                    if name in missing:
                        missing.remove(name)
                    continue

                # If it's not missing any more
                if name not in missing:
                    continue

                # If none of the depends_on is not yet found, skip this step
                if "depends_on" in sig and not any(dep in self.found_signatures for dep in sig["depends_on"]):
                    # Check if they actually do exist
                    if not any(dep in signatures for dep in sig["depends_on"]):
                        raise SignatureError(f"Pattern {name} seems to depend on {sig["depends_on"]}, but none does exist.")
                    continue

                # TODO testen, ob überhaupt möglich mit depends_on: Mal was willkürliches ausprobieren

                if "pattern" not in sig:
                    raise SignatureError(f"Signature {name} doesn't contain a pattern")
                pattern = sig["pattern"]

                # Build an ordered list view from the instructions dict (do not modify original) 
                # TODO ist das so nicht ineffizient? Der sollte nicht jedes ml alle instructions geben und sortiern?
                ordered_device_addrs = sorted(instructions.keys())
                instr_list = [instructions[a] for a in ordered_device_addrs]

                # When using a start_address, we skip until that point
                start_address = sig.get("start_address", None)
                if start_address:
                    if type(start_address) == str:
                        if start_address.startswith("REF{"):
                            ref_name = start_address[4:-1]
                            ref_var = self.rom_cfg.get_by_name(ref_name)
                            
                            if ref_var is None or ref_var.rom_address is None:
                                raise SignatureError(f"Reference {ref_name} in Config for signature {name} not found")
                            
                            start_address = ref_var.rom_address
                        else:
                            start_address = int(start_address)
                    elif type(start_address) != int:
                        raise SignatureError(f"Unknown start_address for {name}")
                    
                    idx = 0
                    while idx < len(instr_list) and instr_list[idx].address < start_address:
                        idx += 1
                    if idx >= len(instr_list):
                        raise SignatureNotFound(f"Start address 0x{start_address:04X} for {name} is invalid.")
                else:
                    idx = 0

                # pass a sliced view to the matcher (simulates popped/skipped prefix)
                pattern_match = self.__detect_current_pattern(name, instr_list[idx:], pattern)

                if pattern_match:
                    self.logger.debug(f"Found {name} function at 0x{pattern_match['funcs'][name]:02X}")

                    # If we got mutual patterns, we remove the other ones, they don't need to be detected anymore
                    if "replaces" in sig:
                        for repl in sig["replaces"]: 
                            if repl in missing:
                                missing.remove(repl)

                    this_found_signatures[name] = pattern_match['funcs'][name]

                    for varname, addr in pattern_match.get("vars", {}).items():
                        self.rom_cfg.add_var_address(
                            name=varname, 
                            address=addr, 
                            current_device=self.current_device if self.current_device is not None else CurrentSelectedDevice.UNDEFINED)
                    for funcname, addr in pattern_match.get("funcs", {}).items():
                        # Pattern detector should be able to rename functions as they'd be named fn_xxxx by default
                        self.rom_cfg.add_refresh_function(
                            name=funcname, 
                            rom_address=addr, 
                            current_device=self.current_device if self.current_device is not None else CurrentSelectedDevice.UNDEFINED,
                            rename=True
                        )
                    
                    
                    # After setting the addresses
                    # Check for additional variable/function definition and add it
                    additional_vars_list = sig.get("additional_vars", None)
                    if additional_vars_list:
                        self._parse_additional_vars(additional_vars_list)


                    self.found_signatures.add(name)
                    if name in  missing:
                        missing.remove(name)
                    
                else:
                    # TODO Anpassen: Nciht pauschal abbrechen, sondern den problematischen raus nehmen
                    #raise SignatureNotFound(f"Pattern {name} not found")
                    missing.remove(name)
                    if not no_warnings:
                        self.logger.error(f"Pattern {name} not found")
        return this_found_signatures

    def __detect_current_pattern(self, name: str, instructions: List[Instruction], pattern: List[Dict[str, Any]]) -> Optional[Dict[str, Dict[str, int]]]:
        # Inspect current pattern

        vars_found: Dict[str, int] = {}
        funcs_found: Dict[str, int] = {}
        refs_found: Dict[str, int] = {}

        first_instr_addr = None
        pattern_idx, instr_idx = 0, 0

        while pattern_idx < len(pattern) and instr_idx < len(instructions):
            search_pattern: dict[str,str|int|list[int]] = pattern[pattern_idx]
            cur_instr = instructions[instr_idx]

            # For debugging
            # if cur_instr.address == 0xC15B:
            #     pass

            # TODO: Er muss noch die passende Startadresse einlesen können, um nicht bei 0 anzufangen!

            # 1. Skip
            if "max_skip" in search_pattern:
                if type(search_pattern["max_skip"]) is not int: raise SignatureError(f"Invalid skip values in pattern {name}")

                max_skip = int(search_pattern["max_skip"])
                min_skip_list = search_pattern.get("min_skip", [0])

                if type(min_skip_list) is not list: raise SignatureError(f"Invalid skip values in pattern {name}")

                
                found = False
                # Try all skip variants from min to max
                for skip in range(0, max_skip + 1):

                    # Erlaubt, wenn skip == min_skip_list[0] oder skip >= min_skip_list[1] usw.
                    # TODO ungetestet
                    if not any(skip == min_val or skip >= min_val for min_val in min_skip_list):
                        continue

                    test_idx = instr_idx + skip
                    if test_idx >= len(instructions):
                        break
                    
                    # Prüfe, ob nach dem Skip das nächste Pattern matcht
                    next_pattern_idx = pattern_idx + 1
                    if next_pattern_idx < len(pattern):
                        next_pattern = pattern[next_pattern_idx]
                        next_instr = instructions[test_idx]
                        if "mnemonic" in next_pattern:
                            findings = self.__analyze_mnemonic(name, next_instr, next_pattern)
                            if findings:
                                instr_idx = test_idx + 1
                                pattern_idx += 2
                                found = True

                                vars_found.update(findings.get("vars", {}))
                                funcs_found.update(findings.get("funcs", {}))
                                refs_found.update(findings.get("refs", {}))
                                break
                if not found:
                    # Kein gültiger Skip gefunden, Pattern abbrechen
                    first_instr_addr = None
                    instr_idx += 1
                    pattern_idx = 0
                continue
            # 2. Mnemonic
            elif "mnemonic" in search_pattern:
                findings = self.__analyze_mnemonic(name, cur_instr, search_pattern)
                if findings:
                    if first_instr_addr is None: first_instr_addr = cur_instr.address
                    instr_idx += 1
                    pattern_idx += 1

                    vars_found.update(findings.get("vars", {}))
                    funcs_found.update(findings.get("funcs", {}))
                    refs_found.update(findings.get("refs", {}))
                else:
                    if pattern_idx > 3:
                        self.logger.info(f"Didn't find pattern for {name} beyond {instructions[instr_idx].address:#04X} yet, but got {pattern_idx} matched lines. "
                                         f"Instruction: '{instructions[instr_idx].mnemonic} {instructions[instr_idx].op_str}'.")

                    # Keep instruction position, but restart with pattern
                    first_instr_addr = None
                    instr_idx += 1
                    pattern_idx = 0
                    continue
            
            else:
                raise SignatureError(f"Unknown pattern '{search_pattern}' in {name}")
            
            if pattern_idx == len(pattern):
                if first_instr_addr is None:
                    raise SignatureError(f"Seems like found the pattern for {name}, but no first instruction address was recorded.")
                funcs_found[name] = first_instr_addr
                return {
                    "vars": vars_found,
                    "funcs": funcs_found,
                    "refs": refs_found,
                }
        
        return None
            


    def __analyze_mnemonic(self, name:str, cur_instr:Instruction, search_pattern:dict) -> Optional[Dict[str, Dict[str, int]]]:

        vars_found: Dict[str, int] = {}
        funcs_found: Dict[str, int] = {}
        refs_found: Dict[str, int] = {}

        def get_target_rom_value(instr: Instruction) -> int:
            if cur_instr.target_value is None:
                    raise SignatureError(f"Function {fn_name} in signature {name} has no target value in assembly.")
            return self.rom_cfg.get_mapped_address(cur_instr.target_value, self.current_device if self.current_device is not None else CurrentSelectedDevice.UNDEFINED)
        
        def to_int(value):
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                value = value.strip().lower()
                if value.startswith("0x"):
                    return int(value, 16)
                elif value.startswith("#$"):
                    return int(value[2:], 16)
                else:
                    return int(value, 10)
            return None
        
        # Check if mnemonic matches, on multiple possibilities, they're bound in a list
        expected_mnemonic = search_pattern["mnemonic"]
        if isinstance(expected_mnemonic, list):
            if cur_instr.mnemonic not in expected_mnemonic:
                return None
        elif cur_instr.mnemonic != expected_mnemonic:
            return None
        # 3. VAR/FN/REF im op_str
        op_str = search_pattern.get("op_str", None) # Distinguish between None and "None" as value given by the json
        if op_str:
            if str(op_str).startswith("VAR{"):
                var_name = op_str[4:-1]
                #self.rom_cfg.add_var_address(var_name, get_target_value(cur_instr))
                vars_found[var_name] = get_target_rom_value(cur_instr)
            elif str(op_str).startswith("FN{"):
                fn_name = op_str[3:-1]
                #self.rom_cfg.add_function_address(fn_name, get_target_value(cur_instr))
                funcs_found[fn_name] = get_target_rom_value(cur_instr)
            elif str(op_str).startswith("REF{"):
                ref_name = op_str[4:-1]
                ref_var = self.rom_cfg.get_by_name(ref_name)
                if ref_var is None:
                    raise SignatureError(f"Reference {ref_name} in config for signature {name} not found")
                refs_found[ref_name] = get_target_rom_value(cur_instr)

                if not ref_var or ref_var.rom_address != get_target_rom_value(cur_instr):
                    return None  # Reference doesn't match
            elif to_int(op_str) == cur_instr.target_value:
                    pass
            else:
                return None

        return {
            "vars": vars_found,
            "funcs": funcs_found,
            "refs": refs_found,
        }
    
    def _parse_additional_vars(self, additional_vars:dict[str, str]) -> None:

        def replace_ref(match:re.Match) -> str:
            ref_name = match.group(1)
            ref_var = self.rom_cfg.get_by_name(ref_name)
            if not ref_var:
                raise SignatureError(f"Reference {ref_name} in Config not found")
            return str(ref_var.rom_address)

        for var_name_ref, var_address_ref in additional_vars.items():
            if str(var_name_ref).startswith("VAR{"):
                var_name = var_name_ref[4:-1]
                var_address_calc = re.sub(r"REF\{(.*?)\}", replace_ref, var_address_ref)

                # TODO für Eval auch später die Adressbereiche prüfen
                self.rom_cfg.add_var_address(var_name, eval(var_address_calc), current_device=self.current_device if self.current_device is not None else CurrentSelectedDevice.UNDEFINED)
                #vars_found[var_name] = eval(var_address_calc)
            else:
                raise NotImplementedError("Only VAR{...} is implemented so far...")
        

