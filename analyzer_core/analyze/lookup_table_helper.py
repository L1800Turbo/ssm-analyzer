from dataclasses import dataclass, field
from typing import Any, Optional
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
    _lut_x_d_flag_mixed: bool = False

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
    
    def set_x_reg_modified(self, d_and_x_mixed: bool = False):
        if self._lut_address is not None:
            self._lut_x_flag_modified_after_set = True

            if d_and_x_mixed:
                # If both D and X were modified, we cannot be sure about the LUT index
                self._lut_x_d_flag_mixed = True

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
    '''
    Base class for Lookup Tables in SymPy.
    Subclasses should define `table_data` as a dictionary mapping indices to values.
    '''
    nargs = 1
    table_ptr: Optional[int] = None
    item_size = 1
    #item_size = item_size
    name = "LUT_undefined"
    table_data: dict[int, int|str] = {}

    # For LUTs with Text (e.g. 4EAT: 1st, 2nd, 3rd, 4th)
    is_String = False

    @classmethod
    def eval(cls, *args): # type: ignore
        # Only evaluate as sympy expression if the argument is an integer, others throw errors
        if args[0].is_Integer:
            if cls.is_String:
                return None # Don't evaluate string LUTs
            
            idx = int(args[0])
            if 0 <= idx < len(cls.table_data):
                table_value = cls.table_data[idx]
                if isinstance(table_value, int):
                    return sp.Integer(cls._interpret_value(table_value))

                raise NotImplementedError("Unknown table_data value")
            else:
                return sp.S.NaN
        return None  # otherwise keep as is for symbolic evaluation
    
    @staticmethod
    def _interpret_value(v):
        """Interpret LUT values (16-bit) as signed."""
        v = int(v) & 0xFFFF
        if v & 0x8000:
            return v - 0x10000
        return v

    def _eval_rewrite_as_piecewise(self, x, **kwargs):
        """Generate a Piecewise representation LUT(symbol)."""
        pieces = [(sp.S(val), sp.Eq(x, iter)) for iter, val in enumerate(self.table_data)]
        pieces.append((sp.S.NaN, sp.S.true))  # Default case
        return sp.Piecewise(*pieces)
    
    def _eval_is_real(self):
        return all(isinstance(val, int) and sp.S(val).is_real for val in self.table_data)
    
    @classmethod
    def preimage(cls, value):
        """Returns all indices i for which LUT(i) == value."""
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
    
    @staticmethod
    def is_lut(expr: Any) -> bool:
        """Checks if a given SymPy function is a LookupTable."""
        return isinstance(expr, sp.Function) and issubclass(expr.func, LookupTable)

    @classmethod
    def create_get_lookup_table(cls, emu: Emulator6303, ptr: int, item_size: int, possible_index_values: list[int]):
        """Creates a SymPy function for a specific lookup table."""

        table_name = LookupTableHelper.table_name(ptr)

        lut_class = type(table_name, (LookupTable,), {
            "table_ptr": ptr,
            #"item_size": item_size,
            "name": table_name,
            "item_size": item_size,
            "is_String": item_size >= 16,
        })

        cls.add_index_values(lut_class, possible_index_values, emu)

        return lut_class
    
    @staticmethod
    def add_index_values(lut_class: type[LookupTable], new_indexes: list[int], emu: Emulator6303):
        """Adds new index values to an existing lookup table."""
        if lut_class.table_ptr is None:
            raise ValueError("LookupTable must have a defined table_ptr to add index values.")
        
        if not lut_class.table_data:
            lut_class.table_data = {}

        byte_interpreter = ByteInterpreter()

        for i in new_indexes:
            if i not in lut_class.table_data:
                if lut_class.item_size == 1:
                    lut_class.table_data[i] = emu.read8(lut_class.table_ptr + i)
                elif lut_class.item_size == 2:
                    lut_class.table_data[i] = emu.read16(lut_class.table_ptr + i * 2)
                elif lut_class.item_size == 16:
                    item_bytes = emu.mem.read_bytes(lut_class.table_ptr + i * 0x10, 0x10)
                    lut_class.table_data[i] = byte_interpreter.render(item_bytes).strip()
                elif lut_class.item_size == 18:
                    # SVX96 AC 0x291D: Quasi switch with 16byte for string and 2 byte for upper SSM lights
                    # TODO Die LED-Werte werden fürs erste ignoriert
                    item_bytes = emu.mem.read_bytes(lut_class.table_ptr + i * 0x12, 0x10)
                    lut_class.table_data[i] = byte_interpreter.render(item_bytes).strip()
                else:
                    raise ValueError("Unsupported item size for lookup table.")
                
    @staticmethod
    def extract_factor_and_index(symbol: sp.Symbol, current_expr, lut_access: LookupTableAccess, factor: Optional[int] = None) -> tuple[int, sp.Basic]:

        lut_expr = lut_access.lut_expr

        # If we got a factor delivered and there is no symbol, we use a fixed index, broken down by the factor
        if factor is not None and not (symbol in current_expr.free_symbols):

            # If the starting LUT pointer has already been copied onto X (by xgdx), we need to substract it first
            # e.g.: IMPREZA96: TCS 0x37C0 scaling for D-NEW
            if lut_access._lut_x_d_flag_mixed:
                lut_expr = lut_expr - sp.Integer(lut_access.get_lut_address())

            index_var = lut_expr / sp.Integer(factor) # type: ignore
            return factor, index_var

        if isinstance(lut_expr, sp.Mul):
            factor = None
            index_var = None
            for arg in lut_expr.args:
                if arg.is_Number:
                    factor = int(arg)
                else:
                    index_var = arg
            if factor is not None and index_var is not None:
                return factor, index_var
        if isinstance(lut_expr, sp.Mod):
            return 1, lut_expr
        # Fallback für x1
        vars = list(lut_expr.free_symbols)
        if len(vars) == 1 and lut_expr.is_Symbol:
            return 1, lut_expr
        raise NotImplementedError("Could not extract item size and index variable from LUT expression.")
    
    @staticmethod
    def substitute_lookup_tables(expr: sp.Expr | Relational): # -> tuple[sp.Expr | None, dict[Any, Any]]
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
    
    @staticmethod
    def reverse_substitute_lookup_tables(luts: dict[str, Callable], expr: sp.Expr, symbol_map: dict[str, sp.Symbol]) -> tuple[Any, dict[Any, Any]]:
        """
        Ersetzt alle Symbole wie LUT_xxxx(nn) wieder durch die entsprechende LookupTable-Funktion.
        """
        def symbol_to_lut(sym):
            # Name wie LUT_310B(x1)
            name = str(sym)
            if name.startswith("LUT_") and "(" in name and name.endswith(")"):
                lut_name, arg_str = name.split("(", 1)
                arg_str = arg_str[:-1]  # Remove ")"

                # locals_dict = {k: v for k, v in symbol_map.items()}

                # # Finde the previously used argument symbol from the string
                # for sym_name, sym_obj in symbol_map.items():
                #     if arg_str == sym_name:
                #         arg = sym_obj
                #         break
                # else:
                #     arg = sp.sympify(arg_str)

                arg = sp.sympify(arg_str, locals=symbol_map)

                # Finde die LookupTable-Klasse mit passendem Namen

                return luts[lut_name](arg)
            return sym

        # Ersetze rekursiv alle passenden Symbole
        return expr.replace(
            lambda e: isinstance(e, sp.Symbol) and str(e).startswith("LUT_"),
            symbol_to_lut
        )

    
    @staticmethod
    def get_lookup_table_values(expr: sp.Expr, symbol: sp.Symbol) -> Optional[dict[int|str, int|str]]:

        # TODO Prüfen, ob mehr als nur x1 drin ist?
        # TODO bei mehreren LUTs muss man das hier auc mehrmals durchgehen oder so und dann auch die letztliche Berechnung machen, auch bei string LUTs

        def eval_expression(expr: sp.Expr) -> int|str:
            #if isinstance(expr, sp.Function) and issubclass(expr.func, LookupTable):
            if LookupTableHelper.is_lut(expr):
                lut_func = expr.func
                lut_index = expr.args[0]
                #lut_index = lut_index.doit()
                #lut_index = sp.Integer(expr.args[0])

                if lut_func.is_String:
                    value = lut_func.table_data[int(lut_index)]
                    return value
                else:
                    value_proto = lut_func.eval()
                    if isinstance(value_proto, sp.Integer):
                       return int(value_proto)
                    else:
                        raise NotImplementedError("LUT value evaluation did not return an integer.")
            else:
                return str(expr)

        # Store values for all possible values
        lut_values: dict[int|str, int|str] = {}

        # TODO Vorher noch wegen LUT prüfen? oder wird das dann gar nicht aufgerufen??

        if isinstance(expr, sp.Piecewise):
            arms:tuple[tuple[sp.Expr, sp.Basic]] = expr.args # type: ignore
        else:
            arms = ((expr, sp.Basic(True)),)

        # TODO Hier fehlt, wenn auch noch x1 rein kommt und die LUT noch gar nicht mit fixer Nummer aufgerufen wuird
        for curr_expr, cond in arms:
            if isinstance(cond, sp.Equality):
                # Try to solve to get a possible index value
                sol = sp.solve(cond, symbol)
                for s in sol:
                    # Evaluate expression for each solution
                    if s.is_Integer:
                        expr_eval: sp.Expr = expr.subs({symbol: s}) # type: ignore
                        lut_values[s] = eval_expression(expr_eval)
                        #possible_index_values.append(int(s))
                    else:
                        raise NotImplementedError("Non-integer solutions for LUT index not implemented.")
            elif cond == sp.Basic(True) or cond == sp.S.true:
                # does this expression still contain the symbol?
                if len(curr_expr.free_symbols) > 0 and LookupTableHelper.is_lut(curr_expr): # curr_expr.has(symbol):
                    #for idx in range(0, 256):
                    for idx in curr_expr.func.table_data.keys():
                        expr_eval: sp.Expr = curr_expr.subs({symbol: idx}) # tkype: ignore
                        lut_values[idx] = eval_expression(expr_eval)
                        #possible_index_values.append(idx)
                else:
                    lut_values['default'] = eval_expression(curr_expr)
            elif isinstance(cond, (sp.Gt, sp.Lt, sp.Ge, sp.Le)):
                if len(curr_expr.free_symbols) > 0 and LookupTableHelper.is_lut(curr_expr):
                    for idx in curr_expr.func.table_data.keys():
                        # Check if idx satisfies the condition
                        if cond.subs({symbol: idx}): # type: ignore
                            expr_eval: sp.Expr = curr_expr.subs({symbol: idx}) # type: ignore
                            lut_values[idx] = eval_expression(expr_eval)
                        else:
                            raise NotImplementedError("Got LUT index with non matching condition.")

            else:
                raise NotImplementedError("Current condition for LUT index not implemented.")                    

        return lut_values if len(lut_values) > 0 else None
