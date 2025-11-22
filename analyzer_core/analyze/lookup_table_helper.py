from typing import Optional
from pyparsing import Callable
import sympy as sp 
from sympy.core.relational import Relational
from analyzer_core.emu.emulator_6303 import Emulator6303


class LookupTable(sp.Function):
    nargs = 1
    table_data = ()
    table_ptr = None
    #item_size = item_size
    name = "LUT"

    @classmethod
    def eval(cls, *args): # type: ignore
        # Nur auswerten, wenn x eine konkrete Zahl ist
        if args[0].is_Integer:
            idx = int(args[0])
            if 0 <= idx < len(cls.table_data):
                return sp.Integer(cls._interpret_value(cls.table_data[idx]))
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
    
    # @classmethod
    # def value(cls, idx):
    #     return cls._interpret_value(cls.table_data[idx])

    # @classmethod
    # def valid_indices(cls, predicate):
    #     """
    #     Liefert alle i (0..255), für die predicate(value) True ist.
    #     predicate: Funktion v -> bool
    #     """
    #     out = []
    #     for i, raw in enumerate(cls.table_data):
    #         v = cls._interpret_value(raw)
    #         if predicate(v):
    #             out.append(i)
    #     return out

    def _eval_rewrite_as_piecewise(self, x, **kwargs):
        """Erzeuge eine Piecewise-Darstellung LUT(symbol)."""
        pieces = [(sp.S(val), sp.Eq(x, iter)) for iter, val in enumerate(self.table_data)]
        pieces.append((sp.S.NaN, sp.S.true))  # Default-Fall
        return sp.Piecewise(*pieces)
    
    def _eval_is_real(self):
        return all(sp.S(val).is_real for val in self.table_data)
    
    @classmethod
    def preimage(cls, value):
        """Gibt alle Indizes i zurück, für die LUT(i) == value gilt."""
        value = sp.S(value)
        indizes = [i for i, v in enumerate(cls.table_data) if sp.S(v) == value]
        return sp.FiniteSet(*indizes)

    @classmethod
    def __repr__(cls):
        return f"<LookupTable {cls.name} at 0x{cls.table_ptr:04X}>"

class LookupTableHelper:

    @classmethod
    def create_get_lookup_table(cls, emu: Emulator6303, ptr: int, item_size: int):
        """Erzeugt eine SymPy-Funktion für eine bestimmte Lookup-Tabelle."""

        table_name = f"LUT_{ptr:04X}"

        items = []
        for i in range(256):
            if item_size == 1:
                items.append(emu.read8(ptr + i))
            elif item_size == 2:
                items.append(emu.read16(ptr + i * 2))
            else:
                raise ValueError("Unsupported item size for lookup table.")
        
        return type(table_name, (LookupTable,), {
            "table_data": tuple(items),
            "table_ptr": ptr,
            #"item_size": item_size,
            "name": table_name
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
    def reverse_substitute_lookup_tables(cls, luts: list[Callable], expr: sp.Expr) -> sp.Expr:
        """
        Ersetzt alle Symbole wie LUT_xxxx(nn) wieder durch die entsprechende LookupTable-Funktion.
        """
        def symbol_to_lut(sym):
            # Name wie LUT_310B(x1)
            name = str(sym)
            if name.startswith("LUT_") and "(" in name and name.endswith(")"):
                lut_name, arg_str = name.split("(", 1)
                lut_name = lut_name
                arg_str = arg_str[:-1]  # Klammer entfernen
                # Finde die LookupTable-Klasse mit passendem Namen
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
    def get_lookup_table_values(cls, expr: sp.Expr) -> Optional[dict[int, int]]:

        # TODO Prüfen, ob mehr als nur x1 drin ist?

        # Prüfe, ob überhaupt ein LookupTable-Child im Ausdruck vorhanden ist
        has_lut = any(
            isinstance(node, sp.Function) and issubclass(node.func, LookupTable)
            for node in expr.atoms(sp.Function)
        )
        if not has_lut:
            return None

        lut_values = {}

        for i in range(0, 255):
            substituted = expr.subs(sp.Symbol("x1"), sp.Integer(i))
            evaluated = sp.simplify(substituted)
            lut_values[i] = int(evaluated)
        
        return lut_values