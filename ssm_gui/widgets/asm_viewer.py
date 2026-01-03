# -*- coding: utf-8 -*-
"""
ASM/ROM Viewer Widget (extended)
- No nested classes.
- Uses external services/classes:
    analyzer_core.service.RomService
    analyzer_core.data.rom_image.RomImage
    analyzer_core.disasm.insn_model.Instruction

New features:
1) Search & "Go to address..."
2) Breakpoints & PC marker (•/▶), Step, GoTo-PC, PC=Selection, "Follow PC"
3) Function table incl. callers (double-click to jump)

Note:
- ROM tooltips (Name/Type) can be attached to ROMTableModel via optional resolver
    (e.g. from your config), default is None.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
import logging
from pathlib import Path
from typing import Optional, List, Dict, Set, Tuple

from PyQt6.QtCore import Qt, QModelIndex, QPoint, pyqtSignal
from PyQt6.QtGui import QFontDatabase, QKeySequence, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QListWidget, QLabel,
    QPushButton, QComboBox, QTableView, QAbstractItemView, QInputDialog,
    QMessageBox, QMenu, QListWidgetItem, QHeaderView, QCheckBox, QStyle,
    QTabWidget, QTreeView
)

# Externe Abhängigkeiten (beibehalten)
from analyzer_core.config.rom_config import RomVarType
from analyzer_core.config.ssm_model import CurrentSelectedDevice
from analyzer_core.service import RomService                      # noqa
from analyzer_core.data.rom_image import RomImage                 # noqa

from analyzer_core.disasm.insn_model import Instruction           # noqa
from ssm_gui.models.function_call_tree import FunctionCallTreeModel
from ssm_gui.models.function_table_model import FunctionTableModel
from ssm_gui.models.rom_table_model import ROMTableModel
from ssm_gui.models.variables_table_model import VariableTableModel

from analyzer_core.emu.memory_manager import MemoryManager

# ---------- Daten- & Hilfsklassen (Top-Level) ----------

class ItemType(Enum):
    CODE = auto()
    DATA = auto()
    FUNC_LABEL = auto()


@dataclass
class DisplayItem:
    type: ItemType
    orig_addr: int
    address: int
    size: int
    text: str
    bytes_: bytes
    instr: Optional[Instruction] = None  # nur bei CODE




# ---------- Haupt-Widget ----------

class AsmViewerWidget(QWidget):
    """
    ASM/ROM Viewer Widget with:
        - Disassembly & ROM via RomService (external)
        - Hex/ASCII view with highlights (yellow) & focus (orange)
        - ASM<->ROM synchronization
        - Function table incl. callers
        - Search, go to address
        - Breakpoints, PC control (GoTo-PC/Step/PC=Selection, follow PC)
    """
    roms_updated = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()


        #self.rom_services = rom_services
        self.rom_service = None

        self.logger = logging.getLogger(__name__)

        # Zustand/Modelle
        self.rom_paths: List[Path] = []
        self.current_rom_path: Optional[Path] = None

        self.display_items: List[DisplayItem] = []
        self.byteaddr_to_display_row: Dict[int, int] = {}
        self.code_addr_to_display_row: Dict[int, int] = {}

        self.hex_model: Optional[ROMTableModel] = None
        self.fn_model: Optional[FunctionTableModel] = None

        self.instructions: dict[tuple[CurrentSelectedDevice, int, int], Instruction] = {}
        self.addr_to_instr_index: Dict[int, int] = {}
        self.code_bytes: Set[int] = set()

        #self.functions: Dict[tuple[CurrentSelectedDevice, int, int], FunctionInfo] = {}  # start -> FunctionInfo

        self.highlight_addrs: Set[int] = set()

        self.breakpoints: Set[int] = set()
        self.current_pc: Optional[int] = None
        self.prev_pc: Optional[int] = None
        self.follow_pc: bool = True

        self._last_find_text: Optional[str] = None

        self._init_ui()
    
    def _init_ui(self) -> None:
        
        # --- UI ---
        layout = QVBoxLayout(self)
        widget_style = self.style()

        # # Top bar: ROM selection TODO ist jetzt in main window
        # top_bar = QHBoxLayout()
        # self.rom_select = QComboBox()
        # self.rom_select.setMinimumWidth(220)
        # top_bar.addWidget(QLabel("Select ROM image:"))
        # top_bar.addWidget(self.rom_select)

        # self.load_button = QPushButton("Load current ROM file") # Todo später analyze oder load nennen, je nachdem ob schon analysiert
        # self.load_button.clicked.connect(self.on_load_rom_file)
        # top_bar.addWidget(self.load_button)
        # top_bar.addStretch(1)
        # layout.addLayout(top_bar)

        # Action bar
        action_bar = QHBoxLayout()
        self.btn_find = QPushButton("Search…")
        self.btn_find.clicked.connect(self.action_find)
        if widget_style is not None:
            icon = widget_style.standardIcon(QStyle.StandardPixmap.SP_FileDialogContentsView)
            self.btn_find.setIcon(icon)
        action_bar.addWidget(self.btn_find)

        self.btn_find_next = QPushButton("Find next")
        self.btn_find_next.setToolTip("F3")
        self.btn_find_next.clicked.connect(self.action_find_next)
        action_bar.addWidget(self.btn_find_next)

        self.btn_goto = QPushButton("Go to address…")
        self.btn_goto.clicked.connect(self.action_goto_address)
        if widget_style is not None:
            icon = widget_style.standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon)
            self.btn_goto.setIcon(icon)
        action_bar.addWidget(self.btn_goto)

        action_bar.addSpacing(20)

        # self.btn_emu = QPushButton("Init Emulator")
        # self.btn_emu.clicked.connect(self.action_init_emulator)
        # if widget_style is not None:
        #     icon = widget_style.standardIcon(QStyle.StandardPixmap.SP_DesktopIcon)
        #     self.btn_emu.setIcon(icon)
        # action_bar.addWidget(self.btn_emu)

        # self.btn_pc_from_sel = QPushButton("PC to selection")
        # self.btn_pc_from_sel.clicked.connect(self.action_pc_from_selection)
        # if widget_style is not None:
        #     icon = widget_style.standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton)
        #     self.btn_pc_from_sel.setIcon(icon)
        # action_bar.addWidget(self.btn_pc_from_sel)

        # self.btn_step = QPushButton("Step (F10)")
        # self.btn_step.clicked.connect(self.action_step)
        # if widget_style is not None:
        #     icon = widget_style.standardIcon(QStyle.StandardPixmap.SP_CommandLink)
        #     self.btn_step.setIcon(icon)
        # action_bar.addWidget(self.btn_step)

        # self.btn_fn_end = QPushButton("Run to fn end")
        # self.btn_fn_end.clicked.connect(self.action_fn_end)
        # if widget_style is not None:
        #     icon = widget_style.standardIcon(QStyle.StandardPixmap.SP_CommandLink)
        #     self.btn_fn_end.setIcon(icon)
        # action_bar.addWidget(self.btn_fn_end)

        # self.btn_bp = QPushButton("Breakpoint (F9)")
        # self.btn_bp.clicked.connect(self.action_toggle_breakpoint)
        # self.btn_bp.setEnabled(False) # TODO nocht nicht da
        # action_bar.addWidget(self.btn_bp)

        # self.btn_goto_pc = QPushButton("Go to PC")
        # self.btn_goto_pc.clicked.connect(self.action_goto_pc)
        # if widget_style is not None:
        #     icon = widget_style.standardIcon(QStyle.StandardPixmap.SP_ArrowUp)
        #     self.btn_goto_pc.setIcon(icon)
        # action_bar.addWidget(self.btn_goto_pc)

        # self.chk_follow_pc = QCheckBox("Follow PC")
        # self.chk_follow_pc.setChecked(True)
        # self.chk_follow_pc.stateChanged.connect(self._on_follow_pc_changed)
        # action_bar.addWidget(self.chk_follow_pc)

        action_bar.addStretch(1)
        layout.addLayout(action_bar)



        # Splitter: links ASM, rechts ROM + Funktionen
        splitter = QSplitter()
        monospace_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)

        # ASM Liste
        self.asm_list = QListWidget()
        self.asm_list.setFont(monospace_font)
        self.asm_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.asm_list.customContextMenuRequested.connect(self._asm_context_menu)
        self.asm_list.itemDoubleClicked.connect(self._asm_item_double_clicked)
        self.asm_list.currentRowChanged.connect(self._on_asm_row_changed)
        splitter.addWidget(self.asm_list)

        # Rechte Seite (Hex + Funktionen-Tabelle)
        # Splitter für Hex-View und Function-Table
        right_splitter = QSplitter()
        right_splitter.setOrientation(Qt.Orientation.Vertical)

        # Hex-View Panel
        hex_panel = QWidget()
        hex_layout = QVBoxLayout(hex_panel)
        hex_layout.setContentsMargins(0, 0, 0, 0)
        hex_layout.addWidget(QLabel("ROM Hex view:"))
        self.hex_view = self._create_hex_table_view()
        hex_layout.addWidget(self.hex_view)
        right_splitter.addWidget(hex_panel)

        # Function table and tree
        function_tabs = QTabWidget()
        right_splitter.addWidget(function_tabs)
        
        # Function-Table Panel
        self.fn_table = QTableView()
        self.fn_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.fn_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.fn_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        fn_header = self.fn_table.horizontalHeader()
        if fn_header is not None:
            fn_header.setStretchLastSection(True)
            fn_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.fn_table.doubleClicked.connect(self.on_function_row_activated)
        self.fn_table.setFont(monospace_font)
        function_tabs.addTab(self.fn_table, "Function table")

        # Function-Tree Panel
        self.fn_tree_view = QTreeView()
        function_tabs.addTab(self.fn_tree_view, "Function call tree")

        # Variables
        self.var_view = QTableView()
        function_tabs.addTab(self.var_view, "Variables")

        splitter.addWidget(right_splitter)
        # Splitter-Position: ASM breiter als rechts
        splitter.setSizes([260, 400])
        layout.addWidget(splitter)
        self.setLayout(layout)

        # Events Hex-View
        self.hex_view.clicked.connect(self._on_hex_table_clicked)

        # ROM Auswahl
        #self.rom_select.currentIndexChanged.connect(self.on_rom_selected)

        # Tastenkürzel (Widget-weit)
        self._install_shortcuts()

    def set_rom_service(self, rom_service: RomService) -> None:
        """Sets the current ROM service."""
        self.rom_service = rom_service

    # ---- UI helpers ----
    def _create_hex_table_view(self) -> QTableView:
        view = QTableView()
        view.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        view.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        return view

    def configure_hex_table_columns(self, view: QTableView):
        hex_w, ascii_w = 28, 140
        h_header = view.horizontalHeader()
        v_header = view.verticalHeader()

        if h_header is not None:
            for c in range(ROMTableModel.BYTES_PER_ROW + 1):
                h_header.setSectionResizeMode(c, QHeaderView.ResizeMode.Fixed)
                view.setColumnWidth(c, hex_w if c < ROMTableModel.BYTES_PER_ROW else ascii_w)
        
        if v_header is not None:
            v_header.setDefaultAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

    def _install_shortcuts(self):
        # F9: Breakpoint
        # act_bp = QPushButton()  # Dummy, wir nutzen nur Shortcut via QWidget.addAction nicht zwingend nötig
        # act_bp_shortcut = QKeySequence(Qt.Key.Key_F9)
        # self.addAction(self._mk_action_with_shortcut(act_bp_shortcut, self.action_toggle_breakpoint))
        # # F10: Step
        # act_step_shortcut = QKeySequence(Qt.Key.Key_F10)
        # self.addAction(self._mk_action_with_shortcut(act_step_shortcut, self.action_step))
        # F3: Find Next
        act_find_next_shortcut = QKeySequence(QKeySequence.StandardKey.FindNext)
        self.addAction(self._mk_action_with_shortcut(act_find_next_shortcut, self.action_find_next))
        # Ctrl+G: Goto
        act_goto_shortcut = QKeySequence("Ctrl+G")
        self.addAction(self._mk_action_with_shortcut(act_goto_shortcut, self.action_goto_address))
        # Ctrl+F: Find
        act_find_shortcut = QKeySequence(QKeySequence.StandardKey.Find)
        self.addAction(self._mk_action_with_shortcut(act_find_shortcut, self.action_find))

    def _mk_action_with_shortcut(self, ks: QKeySequence, handler):
        from PyQt6.QtGui import QAction
        act = QAction(self)
        act.setShortcut(ks)
        act.triggered.connect(handler)
        return act

    # ---- Public API ----
    # def set_rom_list(self, rom_paths: List[Path]) -> None:
    #     """Sets the ROM list and updates the dropdown."""
    #     self.rom_paths = rom_paths or []
    #     self.rom_select.clear()
    #     for p in self.rom_paths:
    #         self.rom_select.addItem(str(p), p)

    # ---- Load/Disassembly ----
      


    # TODO Entfall, sollte einfach als Objekt extern hier hin gegeben werden?
    # def __on_load_rom_file(self) -> None:
    # # analyzes the currently selected file
    #     index = self.rom_select.currentIndex()
    #     self.handle_rom_selection(index)

    def handle_rom_selection__blablaweg(self, index: int) -> None:
        if index < 0 or index >= len(self.rom_paths):
            return
        rom_path: Path = self.rom_paths[index]
        #self.current_rom_path = rom_path

        # New ROMs to be added to the services dict
        if rom_path not in self.rom_services:
            self.rom_services[rom_path] = RomService()

        
        #self.curr_rom_service = self.rom_services[rom_path]


        # Load ROM + and let the analyzer do its job
        # TODO Oben in die IF einbauen, dann wird das einmalig neu gemacht, verhindert auch warnungen


        # TODO Nochmal überdenken die UI:
        '''
        - ROMs aus Ordner auflisten und in RomServices laden, noch nicht analysieren
        - wenn eine Rom geladen wird, soll zunächst der Hex-Code angezeigt werden
        - Dann disassembly ohne alles anzeigen
        - dann die analysen laufen lassen
        - dann asm wieder aktualisieren und function table und son zeug
        - wenn Fehler auftauchen: zwischenstand anzeigen mit Fehlermeldung
        - später: Reactive?

        - bei mehreren Dateien dann: analyse druchführen und angeben, dass analyse abgeschlossen ist. 
          für die reine Anzeige ist dann keine analyzse mehr nötgi
        - auch eine Möglichkeit für "alles analyiseren"

        
        '''

        try:
            self.rom_image_nein: RomImage = self.curr_rom_service.load_rom_image(rom_path)

            self.curr_rom_service.analyze(self.rom_image)
            self.roms_updated.emit()

            self.instructions = self.curr_rom_service.rom_cfg.instructions

            self.build_current_rom_ui(curr_rom_service=self.curr_rom_service)

            # TODO: Instructions dann letztlich aus dem Objekt oholen
            #instructions: List[Instruction] = self.rom_service.disassemble_from_reset(self.rom_image)

            # Create display objects + functions/callers
            display_items, functions_map, highlight_addrs, code_bytes = \
                self._build_display_items(self.rom_image, self.instructions)

            #self.code_bytes = code_bytes
            self.display_items = display_items
            self.functions = functions_map

            # Fill ASM list
            #self._populate_asm_list()

            # Set/update hex model
            # if self.hex_model is None:
            #     self.hex_model = ROMTableModel(
            #         rom=self.rom_image.rom, # TODO Direkt auf RomImage setzen, keine Kopie mit load?
            #         base_addr=0x0000,
            #         name_resolver=None,       # Optional: via RomService/Config einhängbar
            #         mem_type_resolver=None,   # Optional
            #     )
            #     self.hex_view.setModel(self.hex_model)
            # else:
            #     self.hex_model.set_rom(self.rom_image.rom, base_addr=0x0000)

            # self.configure_hex_table_columns(self.hex_view)
            # self.hex_model.set_highlight(highlight_addrs, None)
        except Exception as e:
            self.logger.error(f"Failed to update hex model: {e}")

        # Function table
        self._refresh_tables()

        # Load breakpoints (optional; per-ROM file)
        #self._load_breakpoints()

        # Reset selection (if available)
        reset_addr = self.rom_image.reset_vector()
        if reset_addr is not None:
            self._select_address(reset_addr, prefer_start=True)

    # ---- Build display ----

    def build_current_rom_ui(self) -> None:
        """Builds the UI for the currently selected ROM (disassembly, hex view, functions)."""

        self._print_rom_code()

        # Create the assembly view and show it
        self._build_assembly_ui()
        self._populate_asm_list()

        self._refresh_tables()


        # dann obige schritte -> assembly, analysieren, ....
        
    
    # TODO Damit das funktioniert: Hughlight addrs einbauen
    def _print_rom_code(self) -> None:
        """Debug helper: prints disassembled code to logger."""

        if self.rom_service is None:
            self.logger.warning("No ROM service set, cannot print ROM code.")
            return

        if self.hex_model is None:
            self.hex_model = ROMTableModel(
                rom=self.rom_service.rom_image.contents(),
                base_addr=0x0000,
                name_resolver=None,       # Optional: via RomService/Config einhängbar
                mem_type_resolver=None,   # Optional
            )
            self.hex_view.setModel(self.hex_model)
        else:
            self.hex_model.set_rom(self.rom_service.rom_image.contents(), base_addr=0x0000)

        self.configure_hex_table_columns(self.hex_view)
        #self.hex_model.set_highlight(self.highlight_addrs, None)
    
    def _build_assembly_ui(self) -> None:

        if self.rom_service is None:
            self.logger.warning("No ROM service set, cannot print ROM code.")
            return

        # Create display elements
        display_items: List[DisplayItem] = []
        self.byteaddr_to_display_row.clear()
        self.code_addr_to_display_row.clear()

        self.highlight_addrs.clear()

        instructions = self.rom_service.rom_cfg.instructions
        rom_image = self.rom_service.rom_image
        
        # Loop over the whole ROM and show analyzed code if available
        rom_addr = 0x0000
        end_addr = len(self.rom_service.rom_image.contents())
        while rom_addr < end_addr:
           
            # Function label
            fn_info = self.rom_service.rom_cfg.get_by_address(rom_addr)
            if fn_info is not None and fn_info.type == RomVarType.FUNCTION:
                display_items.append(DisplayItem(ItemType.FUNC_LABEL, rom_addr, rom_addr, 0, f"{fn_info.name}:", b""))

            # Does this address have an instruction?
            if rom_addr in instructions:
                ins = instructions[rom_addr]
                text = self._render_code_line(rom_addr, ins)
                
                row = len(display_items)
                display_items.append(DisplayItem(ItemType.CODE, rom_addr, ins.address, ins.size, text, ins.bytes, instr=ins))

                self.code_addr_to_display_row[rom_addr] = row
                for off in range(ins.size):
                    ba = (rom_addr + off)
                    self.byteaddr_to_display_row[ba] = row
                    self.highlight_addrs.add(ba)
                rom_addr += ins.size
                continue

            # Data (.db) – up to 16 bytes, but stop before next label/code
            # TODO muss das hier hin?
            start = rom_addr
            max_len = 16
            length = 0
            while length < max_len:
                cur = start + length
                if cur in instructions or cur >= end_addr:
                    break
                length += 1

            # No code follows between the instructions
            if length == 0:
                rom_addr += 1
                continue

            b = rom_image.rom[start:start + length]
            bytes_str = " ".join(f"{x:02X}" for x in b)
            ascii_str = "".join(chr(v) if 32 <= v < 127 else "." for v in b)
            text = f" {start:04X}: .db {bytes_str:<47} ; {ascii_str}"
            row = len(display_items)
            display_items.append(DisplayItem(ItemType.DATA, start, start, length, text, b))
            for i in range(length):
                ba = (start + i) & 0xFFFF
                self.byteaddr_to_display_row[ba] = row
                self.highlight_addrs.add(ba)
            rom_addr += length

        # Hand over results
        self.display_items = display_items

    

    # ---- Rendering ----
    def _render_code_line(self, rom_addr: int, ins: Instruction) -> str:
        """Format: •/▶, address, hex, mnemonic, op_str, optional target (→ label/$addr)."""

        if self.rom_service is None:
            raise LookupError("Can't render code line, current ROM service isn't selected, yet")
        
        bytes_str = " ".join(f"{b:02X}" for b in ins.bytes)
        mnem = ins.mnemonic
        op = getattr(ins, "op_str", "")
        target = ""
        ref_var = None

        if ins.target_value is not None:
            ref_var = self.rom_service.rom_cfg.get_by_address(ins.target_value)
        

        # For 16-bit operands it's possible that we have a direct mapping of the variable
        if ins.is_operand_16bit:
            #ref_var = self.rom_service.rom_cfg.get_by_address(ins.target_value)
            if ref_var is not None and ref_var.rom_address is not None:
                if ref_var.type == RomVarType.STRING and ref_var.size is not None:
                    target = f" \"{self.rom_service.rom_image.rom[ref_var.rom_address:ref_var.rom_address + ref_var.size].decode('utf-8', errors='ignore')}\""
                elif ref_var.type == RomVarType.VARIABLE or ref_var.type == RomVarType.PORT:
                    current_var = self.rom_service.rom_cfg.get_by_address(ref_var.rom_address)
                    if current_var is not None:
                        target = f" ({current_var.name})"

        # Target display for jump/function call
        if (ins.is_function_call or ins.is_jump):
            tgt = ins.target_value
            if tgt is not None:
                tgt = tgt & 0xFFFF

                if ref_var is not None:
                    target = f" → {ref_var.name}"
                else:
                    target = ""

        #bp = "● " if (ins.address in self.breakpoints) else "  "
        #pcmark = "▶ " if (self.current_pc is not None and ins.address == self.current_pc) else "  "
        addr = f"{ins.address:04X}" if ins.address == rom_addr else f"{rom_addr:04X} -> {ins.address:04X}"
        return f"{addr}: {bytes_str:<16} {mnem} {op}{target}".rstrip()

    def _populate_asm_list(self) -> None:
        self.asm_list.clear()
        for di in self.display_items:
            # TODO Text ist irgendwie doppelt, wenn das oben schon gerendert werden soll...
            text = di.text
            #if di.type is ItemType.CODE and di.instr is not None:
            #    text = self._render_code_line(di.orig_addr, di.instr, self.functions)
            self.asm_list.addItem(text)

    def _refresh_code_row(self, addr: int) -> None:
        row = self.code_addr_to_display_row.get(addr & 0xFFFF)
        if row is None:
            return
        di = self.display_items[row]
        if di.type is ItemType.CODE and di.instr is not None:
            item = self.asm_list.item(row)
            if item is not None:
                item.setText(self._render_code_line(di.orig_addr, di.instr))

    def _refresh_all_code_rows(self) -> None:
        for row, di in enumerate(self.display_items):
            if di.type is ItemType.CODE and di.instr is not None:
                item = self.asm_list.item(row)
                if item is not None:
                    item.setText(self._render_code_line(di.orig_addr, di.instr))

    def _refresh_tables(self) -> None:
        if not self.rom_service:
            raise LookupError("Can't build display items, current ROM service isn't selected, yet")
        
        # Define function table model
        self.fn_model = FunctionTableModel(self.rom_service.rom_cfg.all_functions(), self)
        self.fn_table.setModel(self.fn_model)
        self.fn_table.setColumnWidth(0, 160)  # Name
        self.fn_table.setColumnWidth(1, 80)   # Address

        # TODO reparieren und wieder einbauen
        # Refresh call tree
        #self.fn_tree_model = FunctionCallTreeModel(self.rom_service.rom_cfg.call_tree, self.functions)
        #self.fn_tree_view.setModel(self.fn_tree_model)
        #self.fn_tree_view.setColumnWidth(0, 160)
        #self.fn_tree_view.setColumnWidth(1, 80)   # Address

        # Refresh variables
        self.var_view_model = VariableTableModel(self.rom_service.rom_cfg.all_vars(), self)
        self.var_view.setModel(self.var_view_model)
        self.var_view.setColumnWidth(0, 160)
        self.var_view.setColumnWidth(1, 80)   # Address

    # ---- ASM <-> ROM interaction ----
    def _on_asm_row_changed(self, row: int) -> None:
        """ASM line selected → highlight corresponding bytes in hex view (yellow)."""
        if self.hex_model is None:
            return
        if not (0 <= row < len(self.display_items)):
            self.hex_model.set_highlight(set(), None)
            return
        di = self.display_items[row]
        addrs = set()
        if di.type != ItemType.FUNC_LABEL:
            for off in range(max(di.size, 1)):
                addrs.add((di.address + off) & 0xFFFF)
        self.hex_model.set_highlight(addrs, None)
    # Scroll hex view to start of line
        if addrs:
            first = min(addrs)
            rc = self.hex_model.row_col_of_address(first)
            if rc:
                r, c = rc
                self.hex_view.scrollTo(self.hex_model.index(r, c))

    def _on_hex_table_clicked(self, index: QModelIndex) -> None:
        """Click in hex view → select matching ASM line + set focus (orange)."""
        if self.hex_model is None:
            return
        r, c = index.row(), index.column()
        if c >= ROMTableModel.BYTES_PER_ROW:  # ASCII-Spalte ignorieren
            return
        addr = self.hex_model.address_of(r, c)
        if addr is None:
            return
        self._highlight_asm_for_byte(addr)

    def _highlight_asm_for_byte(self, addr: int) -> None:
        """Select ASM row for given byte address and highlight in hex view."""
        for row, di in enumerate(self.display_items):
            if di.type is ItemType.FUNC_LABEL:
                continue
            if di.address <= addr < di.address + max(di.size, 1):
                self.asm_list.setCurrentRow(row)
                if self.hex_model:
                    addrs = {(di.address + off) & 0xFFFF for off in range(max(di.size, 1))}
                    self.hex_model.set_highlight(addrs, focus_addr=addr)
                return

    def on_function_row_activated(self, index: QModelIndex):
        addr = self.fn_model.functions_rom_address(index.row()) if self.fn_model else None
        if addr is not None:
            self._select_address(addr, prefer_start=True)

    # ---- ASM context menu ----
    def _asm_context_menu(self, pos: QPoint) -> None:
        itemw = self.asm_list.itemAt(pos)
        if not itemw:
            return
        row = self.asm_list.row(itemw)
        di = self.display_items[row]

        menu = QMenu(self)
        if di.type is ItemType.CODE and di.instr is not None:
            act_bp = menu.addAction("Toggle breakpoint (F9)")
            if act_bp is not None:
                act_bp.triggered.connect(self.action_toggle_breakpoint)
            menu.addSeparator()
            if di.instr is not None:
                act_pc = menu.addAction(f"Set PC here (${getattr(di.instr, 'address', 0):04X})")
                if act_pc is not None:
                    act_pc.triggered.connect(lambda: self.set_pc(getattr(di.instr, 'address', 0)))

            # Target navigation for branch/JSR/JMP
            name = ""
            tgt_addr = None
            if (di.instr.is_function_call or di.instr.is_jump) and di.instr.target_value is not None:
                tgt_addr = di.instr.target_value & 0xFFFF
                fninfo = self.functions.get(tgt_addr)
                name = fninfo.name if fninfo is not None else f"${tgt_addr:04X}"
                act_goto = menu.addAction(f"Go to {name}")
                if act_goto is not None:
                    act_goto.triggered.connect(lambda: self._select_address(tgt_addr, prefer_start=True))
        else:
            act_goto = menu.addAction(f"Go to address ${di.address:04X}")
            if act_goto is not None:
                act_goto.triggered.connect(lambda: self._select_address(di.address, prefer_start=False))

        menu.exec(self.asm_list.mapToGlobal(pos))

    def _asm_item_double_clicked(self, item: QListWidgetItem) -> None:
        row = self.asm_list.row(item)
        di = self.display_items[row]
        if di.type is ItemType.CODE and di.instr is not None:
            if (di.instr.is_function_call or di.instr.is_jump or di.instr.is_branch_rel8 or di.instr.is_branch_rel16) and di.instr.target_value is not None:
                tgt = di.instr.target_value & 0xFFFF
                self._select_address(tgt, prefer_start=True)

    # ---- Breakpoints / PC ----
    def action_toggle_breakpoint(self) -> None:
        row = self.asm_list.currentRow()
        if not (0 <= row < len(self.display_items)):
            return
        di = self.display_items[row]
        if di.type is not ItemType.CODE or di.instr is None:
            return
        addr = di.instr.address & 0xFFFF
        if addr in self.breakpoints:
            self.breakpoints.remove(addr)
        else:
            self.breakpoints.add(addr)
        self._refresh_code_row(addr)
        #self._save_breakpoints()

    # def action_init_emulator(self) -> None:
    #     if not self.curr_rom_service:
    #         raise LookupError("Can't build display items, current ROM service isn't selected, yet")
        
    #     self.curr_rom_service.init_emulator(self.rom_image)

    # def action_step(self) -> None:
    #     if not self.curr_rom_service:
    #         raise LookupError("Can't build display items, current ROM service isn't selected, yet")
    #     # TODO diese not irgendwie vielleicht als @ oben drüber?
        
    #     if not self.instructions:
    #         return
    #     if self.current_pc is None:
    #         self.logger.error("No PC set, cannot step.")
    #         return
        
    #     try:
    #         mem_access = self.curr_rom_service.step_from_address(self.current_pc)
    #     except Exception as e:
    #         self.logger.error(f"Error running instruction at PC=0x{self.current_pc:04X}: {e}")
    #         return

    #     if mem_access and mem_access.next_instr_addr:
    #         self.set_pc(mem_access.next_instr_addr)
    #     else:
    #         self.logger.error("No next instruction address found.")

    # def action_fn_end(self) -> None:
    #     if not self.curr_rom_service:
    #         raise LookupError("Can't build display items, current ROM service isn't selected, yet")
        
    #     if self.current_pc is None:
    #         self.logger.error("No PC set, cannot run to function end.")
    #         return

    #     try:
    #         mem_access = self.curr_rom_service.run_to_function_end(self.current_pc)
    #         if mem_access and mem_access.next_instr_addr:
    #             self.set_pc(mem_access.next_instr_addr)
    #     except Exception as e:
    #         self.logger.error(f"Error running function beginning at PC=0x{self.current_pc:04X}: {e}")

    # def action_goto_pc(self) -> None:
    #     if self.current_pc is None:
    #         QMessageBox.information(self, "Info", "No PC set.")
    #         return
    #     self._select_address(self.current_pc, prefer_start=True)

    # def action_pc_from_selection(self) -> None:
    #     row = self.asm_list.currentRow()
    #     if 0 <= row < len(self.display_items):
    #         di = self.display_items[row]
    #         if di.type is ItemType.CODE and di.instr is not None:
    #             self.set_pc(di.instr.address)

    def _on_follow_pc_changed(self, state):
        self.follow_pc = (state == Qt.CheckState.Checked)
        # TODO hier noch was 

    def set_pc(self, addr: int) -> None:

        def set_pc_background(addr: int, color: Qt.GlobalColor|QBrush):
            row = self.code_addr_to_display_row.get(addr)
            if row is not None:
                item = self.asm_list.item(row)
                if item is not None:
                    item.setBackground(color)


        self.prev_pc, self.current_pc = self.current_pc, addr

        if self.prev_pc is not None:
            set_pc_background(self.prev_pc, QBrush())
        set_pc_background(self.current_pc, Qt.GlobalColor.yellow)

        # Zeile in ASM-Liste suchen und gelb markieren
        # row = self.code_addr_to_display_row.get(addr)
        # if row is not None:
        #     #self.asm_list.setCurrentRow(row)
        #     item = self.asm_list.item(row)
        #     if item is not None:
        #         item.setBackground(Qt.GlobalColor.yellow)
                
        # Anzeige aktualisieren (optional)
        #self._refresh_all_code_rows()

    # ---- Search / Go to ----
    def action_find(self) -> None:
        text, ok = QInputDialog.getText(self, "Search", "Find text in assembler (case-insensitive):")
        if ok and text:
            self._last_find_text = text
            self._find_next_internal(start_after_current=True)

    def action_find_next(self) -> None:
        if not self._last_find_text:
            self.action_find()
        else:
            self._find_next_internal(start_after_current=True)

    def _find_next_internal(self, start_after_current: bool = True) -> None:
        if not self._last_find_text or self.asm_list.count() == 0:
            return
        query = self._last_find_text.lower()
        start = self.asm_list.currentRow()
        n = self.asm_list.count()
        i = (start + (1 if start_after_current else 0)) % n
        for _ in range(n):
            item = self.asm_list.item(i)
            if item is not None and query in item.text().lower():
                self.asm_list.setCurrentRow(i)
                return
            i = (i + 1) % n
        QMessageBox.information(self, "Search", f"'{self._last_find_text}' not found.")

    def action_goto_address(self) -> None:
        s, ok = QInputDialog.getText(self, "Go to address", "Address ($1234, 0x1234 or decimal):")
        if not ok or not s:
            return
        try:
            addr = self._parse_address(s)
            self._select_address(addr, prefer_start=True)
        except ValueError as ex:
            QMessageBox.warning(self, "Invalid address", str(ex))

    @staticmethod
    def _parse_address(s: str) -> int:
        t = s.strip().lower()
        if t.startswith('$'):
            v = int(t[1:], 16)
        elif t.startswith('0x'):
            v = int(t, 16)
        else:
            v = int(t)
        if not (0 <= v <= 0xFFFF):
            raise ValueError("Adresse muss im Bereich 0x0000..0xFFFF liegen.")
        return v

    # ---- Select address ----
    def _select_address(self, addr: int, prefer_start: bool = True) -> None:
        addr &= 0xFFFF
        row = self.code_addr_to_display_row.get(addr) if prefer_start else None
        if row is not None:
            self.asm_list.setCurrentRow(row)
            self._on_asm_row_changed(row)
            return
        row = self.byteaddr_to_display_row.get(addr)
        if row is not None:
            self.asm_list.setCurrentRow(row)
            self._on_asm_row_changed(row)
            return
        # fallback: first row >= addr
        for i, di in enumerate(self.display_items):
            if di.address >= addr:
                self.asm_list.setCurrentRow(i)
                self._on_asm_row_changed(i)
                return
        self.logger.warning(f"Address ${addr:04X} was not found in the current view.")
