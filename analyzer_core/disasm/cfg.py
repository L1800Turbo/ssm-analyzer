
# Funktions- und Caller-Erkennung für 630x-Disassembly
from typing import List, Dict, Set, Optional
from analyzer_core.config.rom_config import RomConfig, RomVarType
from analyzer_core.disasm.insn_model import Instruction
from dataclasses import dataclass

@dataclass
class FunctionInfo:
	start: int
	name: str
	callers: Set[int]

def extract_functions_and_callers(
	instructions: dict[int, Instruction],
	reset_addr: Optional[int] = None,
	config: Optional[RomConfig] = None
) -> Dict[int, FunctionInfo]:
	"""
	Extrahiert Funktionsstarts (JSR-Ziele, Reset) und Caller aus Instructions.
	Gibt Mapping start_addr -> FunctionInfo zurück.
	"""
	functions: Dict[int, FunctionInfo] = {}
	def ensure_fn(addr: int) -> FunctionInfo:
		fn_name = f"fn_{addr:04X}"
		if config is not None:
			fn = config.get_by_address(addr)
			if fn is not None and fn.type == RomVarType.FUNCTION:
				fn_name = fn.name
				
		if addr not in functions:
			functions[addr] = FunctionInfo(start=addr, name=fn_name, callers=set())
		return functions[addr]

	# TODO weg?
	if reset_addr is not None:
		fi = ensure_fn(reset_addr)
		fi.name = "fn_reset"

	# Caller detection (last function start <= instruction address)
	sorted_fn_starts = sorted(functions.keys())
	current_fn_start: Optional[int] = None
	fn_iter = iter(sorted_fn_starts)
	next_fn = next(fn_iter, None)


	# Function starts: Reset + all function call targets
	for addr, ins in instructions.items():
		if addr in functions:
			current_fn_start = ins.address
		if ins.is_function_call and ins.target_value is not None:
			callee = ensure_fn(ins.target_value & 0xFFFF)
			caller_id = current_fn_start if current_fn_start is not None else ins.address
			callee.callers.add(caller_id & 0xFFFF)

	return functions
