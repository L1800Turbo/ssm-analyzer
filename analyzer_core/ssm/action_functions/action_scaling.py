from dataclasses import dataclass
import logging
from analyzer_core.analyze.instruction_parser import InstructionParser
from analyzer_core.analyze.pattern_detector import PatternDetector
from analyzer_core.config.rom_config import RomConfig
from analyzer_core.config.ssm_model import CurrentSelectedDevice, MasterTableEntry, RomIdTableEntry_512kb
from analyzer_core.disasm.capstone_wrap import Disassembler630x, OperandType
from analyzer_core.disasm.insn_model import Instruction
from analyzer_core.emu.emulator_6303 import Emulator6303
from analyzer_core.emu.memory_manager import MemoryManager
from analyzer_core.emu.tracing import MemAccess
from analyzer_core.ssm.action_functions.action_helper import SsmActionHelper

logger = logging.getLogger(__name__)



class SsmActionScalingFunction(SsmActionHelper):

    def __init__(self, 
            rom_cfg: RomConfig, 
            emulator: Emulator6303, 
            current_device: CurrentSelectedDevice, 
            romid_entry:RomIdTableEntry_512kb, 
            mt_entry: MasterTableEntry) -> None:
        super().__init__(rom_cfg, emulator)
        self.current_device = current_device
        self.romid_entry = romid_entry
        self.mt_entry = mt_entry

        self.instr_parser = InstructionParser(rom_cfg, emulator, read_address=self.rom_cfg.address_by_name("ssm_rx_byte_2"))


        self.check_disasm_scaling()
        self.set_unit()

    # TODO als Alternative nur den INdex nehmen und direkt aqus der Tabelle die Adresse holen?
    # Aber was wäre mit BARO.P usw?

    def check_disasm_scaling(self):
        '''
        Do a disassembly of the scaling function table if not already done.
        '''
        if self.romid_entry.current_scale_fn_table_pointer is None:
            raise ValueError("No scaling function table pointer available in ROM ID entry.")

        scaling_fn_table_ptr = self.romid_entry.current_scale_fn_table_pointer + 2 * self.mt_entry.scaling_index
        self.scaling_fn_ptr = self.emulator.read16(scaling_fn_table_ptr)
        

        # TODO: Der muss das vom Memory lesen den Pointer, damit der Adressoffset passt!, aber nicht direkt, nur der Offset

        if self.scaling_fn_ptr not in self.rom_cfg.scaling_addresses:
            disasm = Disassembler630x(mem=self.emulator.mem) # TODO Besser raussuchen? self.emulator.mem.rom_image.rom)
            disasm.disassemble_reachable(self.scaling_fn_ptr, self.rom_cfg.instructions, self.rom_cfg.call_tree)

            pattern_detector = PatternDetector(self.rom_cfg)
            action_fn_patterns = pattern_detector.detect_patterns(self.rom_cfg.instructions, "scaling_function_pattern")
    
    def add_function_mocks(self):
        '''
        Add necessary function mocks for the scaling functions
        '''

        def mock_skip(em: Emulator6303):
            # Just return from the function
            em.mock_return()

        self.emulator.hooks.mock_function(self.rom_cfg.address_by_name("print_lower_value"), mock_skip)

        def hook_read_ssm_rx_bytes_in_scaling_fn(addr: int, value: int, mem: MemoryManager):
            logger.debug(f"hook_read_ssm_rx_bytes_in_scaling_fn at {addr:04X}")
            #self.emulator.add_logger("scaling_fn_ssm_rx_logger", lambda instr, access: logging.debug(f"[SCALING_FN] Read SSM RX Bytes: {instr.address:04X}"))
            self.emulator.add_logger("scaling_fn_ssm_rx_logger", self.trace_rx_value_calculation)

        def hook_pre_scaling_function(em: Emulator6303):
            logger.debug(f"hook_pre_scaling_function at {self.scaling_fn_ptr:04X}")
            self.emulator.hooks.add_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_2"), hook_read_ssm_rx_bytes_in_scaling_fn)
        
        def hook_post_scaling_function(em: Emulator6303, access):
            print(f"hook_post_scaling_function at {self.scaling_fn_ptr:04X}", flush=True)
            self.emulator.hooks.remove_read_hook(self.rom_cfg.address_by_name("ssm_rx_byte_2"), hook_read_ssm_rx_bytes_in_scaling_fn)
            self.emulator.remove_logger("scaling_fn_ssm_rx_logger")

        self.emulator.hooks.add_pre_hook(self.scaling_fn_ptr, hook_pre_scaling_function)
        self.emulator.hooks.add_post_hook(self.scaling_fn_ptr, hook_post_scaling_function)

        # TODO Noch mocken?
        # fn_fn_copy_to_lower_screen_buffer_unit -> wird ja eigentrlich schon manuell gemacht
    
    def run_post_actions(self):
        negative_sign = "-" if self.emulator.mem.read(self.rom_cfg.address_by_name('print_-_sign')) == 1 else ""
        positive_sign = "+" if self.emulator.mem.read(self.rom_cfg.address_by_name('print_+_sign')) == 1 else ""
        self.value_sign = f"{positive_sign}{negative_sign}"
        self.decimal_places = self.emulator.mem.read(self.rom_cfg.address_by_name('decimal_places'))
        #
        # if self.decimal_places > 0:
        #    self.calc_str += f" / ({10 ** self.decimal_places})"


    def set_unit(self):
        '''
        Set the unit for the scaling as done in IMPREZA96 @C15B: fn_set_lower_screen_buffer_unit
        '''
        if self.romid_entry.menuitems_lower_label_pointer is None:
            raise ValueError("No lower label pointer available in ROM ID entry.")
        
        lower_label_pointer = self.romid_entry.menuitems_lower_label_pointer + self.mt_entry.lower_label_index * 16

        lower_label_raw = self.emulator.mem.read_bytes(lower_label_pointer, 16)
        lower_label_str = self.rom_cfg.byte_interpreter.render(lower_label_raw)

        self.unit = lower_label_str.strip()

    def trace_rx_value_calculation(self, instr: Instruction, access: MemAccess):

        self.instr_parser.do_step(instr, access)

        return

        #logger.debug(f"[SCALING_FN] {Instr} {access}")

        # TODO Sicherstellen, dass wir vorne anfangen, also calc_address und register müssen schon null sein
        if instr.mnemonic == "ldaa":
            if self.new_calc_address is None and self.new_calc_register is None:
                self.new_calc_address = None
                self.new_calc_register = "A"
        elif instr.mnemonic == "ldab":
            if self.new_calc_address is None and self.new_calc_register is None:
                self.new_calc_address = None
                self.new_calc_register = "B"
        elif instr.mnemonic == "ldd":
            if self.new_calc_address is None and self.new_calc_register is None: # TODO dann nicht nur none, sondenr auch gucken, ob die "spannende variable" geladen wird
                self.new_calc_address = None
                self.new_calc_register = "D"
        elif instr.mnemonic == "ldx":
            if self.new_calc_address is None and self.new_calc_register is None:
                self.new_calc_address = None
                self.new_calc_register = "X"
        elif instr.mnemonic == "staa":
            if self.new_calc_register == "A":
                self.new_calc_address = instr.target_value
                self.new_calc_register = None
        elif instr.mnemonic == "stab":
            if self.new_calc_register == "B":
                self.new_calc_address = instr.target_value
                self.new_calc_register = None
        elif instr.mnemonic == "std":
            if self.new_calc_register == "D":
                self.new_calc_address = instr.target_value
                self.new_calc_register = None
        elif instr.mnemonic == "addd":
            if self.new_calc_register == "D":
                self.calc_str += f" + {instr.target_value}"
                # if instr.target_type == OperandType.DIRECT:
                #     self.new_calc_address = instr.target_value
                #     self.new_calc_register = None
        elif instr.mnemonic == "asl":
            if self.new_calc_address == instr.target_value:
                self.calc_str += " * 2"
        elif instr.mnemonic == "rol":
            if self.new_calc_address == instr.target_value:
                self.calc_str += " * 2"
        elif instr.mnemonic == "rola":
            if self.new_calc_register == "A":
                self.calc_str += " * 2"
        elif instr.mnemonic == "rolb":
            if self.new_calc_register == "B":
                self.calc_str += " * 2"
        elif instr.mnemonic.startswith("clr") or instr.is_function_call or instr.is_return:
            pass
        elif instr.mnemonic == "mul":
            if self.new_calc_register == "A":
                self.calc_str += f" * {self.saved_registers.B}"
                self.new_calc_register = "D" # A and B
            elif self.new_calc_register == "B": # TODO Mul überschreibt das B dann ja schon
                self.calc_str += f" * {self.saved_registers.A}"
                self.new_calc_register = "D" # A and B
        else:
            raise NotImplementedError(f"Tracing for instruction \"{instr.mnemonic}\" not implemented in scaling function.")
        
        print(f"[SCALING_FN] Current calculation: {self.calc_str}", flush=True)
        
        # Save current registers as they might get modified in the next step
        

        # TODO Mocker für divide und mul16bit schreiben? dann hier nach funktion gucken und den Rechenschritt einfügen