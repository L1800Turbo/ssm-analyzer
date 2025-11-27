from dataclasses import dataclass
from typing import Optional
from pyparsing import Callable
import sympy as sp 
from sympy.core.relational import Relational
from analyzer_core.config.byte_interpreter import ByteInterpreter
from analyzer_core.emu.emulator_6303 import Emulator6303


@dataclass
class LookupTableAccess:
    _lut_address: Optional[int] = None
    lut_expr: sp.Expr = sp.Expr()
    _lut_x_flag_modified_after_set: bool = False

    def address_defined(self) -> bool:
        return self._lut_address is not None #and self.lut_expr is not None
    
    def class_defined(self, lookup_tables: dict[str, Callable]) -> bool:
        # Find the lookup table with the given address in the list
        if self._lut_address is not None and LookupTableHelper.table_name(self._lut_address) in lookup_tables:
            return True
        return False

    def set_lut_address(self, address:int):
        self._lut_address = address
        self._lut_x_flag_modified_after_set = False
    
    def set_x_reg_modified(self):
        if self._lut_address is not None:
            self._lut_x_flag_modified_after_set = True

    def get_lut_ptr_modified(self) -> bool:
        '''
        If the X flag was changed after a LUT was loaded into X, we can assume that there were calculations with it
        '''
        return self._lut_x_flag_modified_after_set
    
    def get_lut_address(self) -> int:
        if self._lut_address is None:
            raise ValueError("LUT address is expected to be set.")
        return self._lut_address
    


class LookupTable(sp.Function):
    nargs = 1
    table_data: dict[int, int|str] = {}
    table_ptr = None
    #item_size = item_size
    name = "LUT"

    # For LUTs with Text (e.g. 4EAT: 1st, 2nd, 3rd, 4th)
    is_String = False

    @classmethod
    def eval(cls, *args): # type: ignore
        # Nur auswerten, wenn x eine konkrete Zahl ist
        if args[0].is_Integer:
            if cls.is_String:
                return None # Don't evaluate string LUTs
            
            idx = int(args[0])
            if 0 <= idx < len(cls.table_data):
                table_value = cls.table_data[idx]
                if isinstance(table_value, int):
                    return sp.Integer(cls._interpret_value(table_value))
                #elif isinstance(table_value, str):
                #    return table_value
                raise NotImplementedError("Unknown table_data value")
                #return sp.Integer(cls.table_data[idx])
            else:
                return sp.S.NaN
        return None  # sonst symbolisch lassen
    
    @staticmethod
    def _interpret_value(v):
        """LUT-Werte (16 Bit) als signed interpretieren."""
        v = int(v) & 0xFFFF
        if v & 0x8000:
            return v - 0x10000
        return v

    def _eval_rewrite_as_piecewise(self, x, **kwargs):
        """Erzeuge eine Piecewise-Darstellung LUT(symbol)."""
        pieces = [(sp.S(val), sp.Eq(x, iter)) for iter, val in enumerate(self.table_data)]
        pieces.append((sp.S.NaN, sp.S.true))  # Default-Fall
        return sp.Piecewise(*pieces)
    
    def _eval_is_real(self):
        return all(isinstance(val, int) and sp.S(val).is_real for val in self.table_data)
    
    @classmethod
    def preimage(cls, value):
        """Gibt alle Indizes i zurück, für die LUT(i) == value gilt."""
        value = sp.S(value)
        #indizes = [i for i, v in enumerate(cls.table_data) if sp.S(v) == value]
        indizes = [i for i, v in cls.table_data.items() if sp.S(v) == value]

        return sp.FiniteSet(*indizes)

    @classmethod
    def __repr__(cls):
        return f"<LookupTable {cls.name} at 0x{cls.table_ptr:04X}>"

class LookupTableHelper:

    @staticmethod
    def table_name(ptr:int):
        return f"LUT_{ptr:04X}"

    @classmethod
    def create_get_lookup_table(cls, emu: Emulator6303, ptr: int, item_size: int, possible_index_values: list[int]):
        """Erzeugt eine SymPy-Funktion für eine bestimmte Lookup-Tabelle."""

        byte_interpreter = ByteInterpreter()


        table_name = LookupTableHelper.table_name(ptr)

        items: dict[int, int|str] = {}

        for i in possible_index_values:
            if item_size == 1:
                items[i] = emu.read8(ptr + i)
            elif item_size == 2:
                items[i] = emu.read16(ptr + i * 2)
            elif item_size == 16:
                # Usually the display lenght, get 16 bytes
                item_bytes = emu.mem.read_bytes(ptr + i * 0x10, 0x10)
                items[i] = byte_interpreter.render(item_bytes).strip()
            else:
                raise ValueError("Unsupported item size for lookup table.")
        
        return type(table_name, (LookupTable,), {
            "table_data": items,
            "table_ptr": ptr,
            #"item_size": item_size,
            "name": table_name,
            "is_String": item_size == 16,
        })
    
    @classmethod
    def substitute_lookup_tables(cls, expr: sp.Expr | Relational) -> sp.Expr:
        """
        Ersetzt alle LookupTable-Funktionen im Ausdruck durch ein Symbol mit dem Namen LUT_xxxx(nn).
        """
        def lut_to_symbol(lut):
            # Name wie LUT_310B(x1)
            lut_name = lut.func.name if hasattr(lut.func, "name") else lut.func.__name__
            arg_str = str(lut.args[0])
            return sp.Symbol(f"{lut_name}({arg_str})")
                
        # Ersetze rekursiv alle LookupTable-Instanzen
        return expr.replace(
            lambda e: isinstance(e, sp.Function) and issubclass(e.func, LookupTable),
            lut_to_symbol
        )
    
    @classmethod
    def reverse_substitute_lookup_tables(cls, luts: dict[str, Callable], expr: sp.Expr) -> sp.Expr:
        """
        Ersetzt alle Symbole wie LUT_xxxx(nn) wieder durch die entsprechende LookupTable-Funktion.
        """
        def symbol_to_lut(sym):
            # Name wie LUT_310B(x1)
            name = str(sym)
            if name.startswith("LUT_") and "(" in name and name.endswith(")"):
                lut_name, arg_str = name.split("(", 1)
                arg_str = arg_str[:-1]  # Remove ")"
                arg = sp.sympify(arg_str)

                # Finde die LookupTable-Klasse mit passendem Namen

                return luts[lut_name](arg)
                for lut_cls in luts:
                    if getattr(lut_cls, "name", None) == lut_name:
                        # Argument als Symbol oder Zahl
                        #try:
                        arg = sp.sympify(arg_str)
                        #except Exception:
                        #    arg = sp.Symbol(arg_str)
                        return lut_cls(arg)
            return sym

        # Ersetze rekursiv alle passenden Symbole
        return expr.replace(
            lambda e: isinstance(e, sp.Symbol) and str(e).startswith("LUT_"),
            symbol_to_lut
        )
    
    @classmethod
    def get_lookup_table_values(cls, expr: sp.Expr) -> Optional[dict[int, int|str]]:

        # TODO Prüfen, ob mehr als nur x1 drin ist?

        # Prüfe, ob überhaupt ein LookupTable-Child im Ausdruck vorhanden ist
        lut_indexes = None
        for node in expr.atoms(sp.Function):
            if isinstance(node, sp.Function) and issubclass(node.func, LookupTable):
                lut = node.func

                # If the LUT consists of string values, skip sympy evaluation
                # TODO er nimmt dann auch nur x1 als Wert und setzt einfach i ein -> evtl. reicht das nicht für alle Fälle
                if lut.is_String:
                    return lut.table_data

                _lut_indexes = lut.table_data.keys()
                if lut_indexes is not None and lut_indexes != _lut_indexes:
                    raise NotImplementedError("Range of valid lookup tables changed, behaviour not implemented.")
                else:
                    lut_indexes = _lut_indexes

        # If there are no values for a lookup table, we don't have one
        if lut_indexes is None:
            return None

        lut_values = {}

        for i in lut_indexes: #range(0, 255):
            substituted = expr.subs(sp.Symbol("x1"), sp.Integer(i))
            evaluated = sp.simplify(substituted)
            lut_values[i] = int(evaluated)
        
        return lut_values