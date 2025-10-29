from __future__ import annotations
from pathlib import Path
from datetime import datetime
import html
import os
from typing import Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from analyzer_core.emu.tracing import MemAccess

class AsmHtmlLogger:
    """
    Compact HTML table logger for MemAccess entries.
    - Writes one <tr> per MemAccess (single-line, compact).
    - Rotates files when size exceeds max_size_bytes.
    - Keeps header/footer management simple to allow appending.
    """

    DEFAULT_MAX_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(
        self,
        path: Path | str = "logs/asm_trace.html",
        append: bool = True,
        max_size_bytes: int | None = DEFAULT_MAX_SIZE,
        rotate_count: int = 3,
    ):
        self.path = Path(path)
        os.makedirs(self.path.parent, exist_ok=True)
        self.append = append
        self.max_size = max_size_bytes
        self.rotate_count = max(1, int(rotate_count))
        self._initialized = False

        # create/overwrite file with header unless appending to an existing file
        if not self.path.exists() or not append:
            with open(self.path, "w", encoding="utf-8") as f:
                f.write(self._html_header())
            self._initialized = True
        else:
            # if file exists, assume header present
            self._initialized = True

    def _html_header(self) -> str:
        return """<!doctype html><html><head><meta charset="utf-8"><title>ASM Trace</title>
<style>
body{font-family:system-ui,Arial,Helvetica,sans-serif;margin:8px}
table{border-collapse:collapse;width:100%;font-family:monospace;font-size:12px}
th,td{border-bottom:1px solid #eee;padding:6px 8px;text-align:left;white-space:nowrap}
thead th{background:#fafafa;font-weight:600;font-size:12px}
tr:nth-child(odd){background:#fff} tr:nth-child(even){background:#fbfbfb}
</style></head><body>
<table>
<thead><tr>
<th>ts</th><th>pc</th><th>instr</th><th>target</th><th>var</th><th>val</th><th>rw</th><th>next</th>
</tr></thead>
<tbody>
"""

    def _html_footer(self) -> str:
        return "</tbody></table></body></html>\n"

    def _rotate_if_needed(self) -> None:
        if self.max_size is None:
            return
        try:
            if self.path.exists() and self.path.stat().st_size > self.max_size:
                # close current by writing footer
                try:
                    with open(self.path, "a", encoding="utf-8") as f:
                        f.write(self._html_footer())
                except Exception:
                    pass
                # rotate files: .1, .2, ... up to rotate_count
                for i in range(self.rotate_count - 1, 0, -1):
                    src = self.path.with_suffix(self.path.suffix + f".{i}")
                    dst = self.path.with_suffix(self.path.suffix + f".{i+1}")
                    if src.exists():
                        try:
                            src.replace(dst)
                        except Exception:
                            pass
                # move base to .1
                try:
                    self.path.replace(self.path.with_suffix(self.path.suffix + ".1"))
                except Exception:
                    # fallback: copy & truncate
                    try:
                        import shutil
                        shutil.copy2(self.path, self.path.with_suffix(self.path.suffix + ".1"))
                        with open(self.path, "w", encoding="utf-8") as f:
                            f.write(self._html_header())
                    except Exception:
                        pass
                # create new file header
                if not self.path.exists():
                    with open(self.path, "w", encoding="utf-8") as f:
                        f.write(self._html_header())
                else:
                    # ensure new file has header if truncated
                    with open(self.path, "r+", encoding="utf-8") as f:
                        if f.read(16) == "":
                            f.seek(0)
                            f.write(self._html_header())
                self._initialized = True
        except Exception:
            # never raise from rotation
            pass

    def log(self, ma: "MemAccess") -> None:
        """
        Append a single compact table row for the MemAccess.
        Keep each row short to avoid huge HTML size.
        """
        try:
            # rotate before writing if needed
            self._rotate_if_needed()

            ts = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
            instr = getattr(ma, "instr", None)
            if instr is not None:
                mnem = html.escape(str(getattr(instr, "mnemonic", "") or ""))
                iaddr = f"0x{getattr(instr, 'address', 0):04X}"
                op = html.escape((getattr(instr, "op_str", "") or "").strip())
                instr_col = f"{mnem} {op}".strip()
            else:
                instr_col = "None"

            target = f"{getattr(ma,'target_addr',None) and (f'0x{ma.target_addr:04X}') or 'None'}"
            varname = getattr(getattr(ma, "var", None), "name", None)
            varcol = html.escape(str(varname)) if varname is not None else "None"
            val = getattr(ma, "value", None)
            valcol = f"{val:#04x}" if isinstance(val, int) else html.escape(repr(val))
            rw = html.escape(str(getattr(ma, "rw", "") or ""))
            by = getattr(ma, "by", None)
            bycol = f"0x{by:04X}" if isinstance(by, int) else "None"
            next_addr = getattr(ma, "next_instr_addr", None)
            nextcol = f"0x{next_addr:04X}" if isinstance(next_addr, int) else "None"

            row = "<tr>" + "".join([
                f"<td>{html.escape(ts)}</td>",
                f"<td>{html.escape(bycol)}</td>",
                f"<td>{html.escape(instr_col)}</td>",
                f"<td>{html.escape(target)}</td>",
                f"<td>{varcol}</td>",
                f"<td>{html.escape(valcol)}</td>",
                f"<td>{rw}</td>",
                f"<td>{html.escape(nextcol)}</td>",
            ]) + "</tr>\n"

            with open(self.path, "a", encoding="utf-8") as f:
                f.write(row)
        except Exception:
            try:
                import logging
                logging.getLogger(__name__).exception("AsmHtmlLogger.log failed")
            except Exception:
                pass

    def close(self) -> None:
        try:
            # append footer to properly close HTML
            if self.path.exists():
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(self._html_footer())
        except Exception:
            pass
        