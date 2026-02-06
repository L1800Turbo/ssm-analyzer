# HookManager
# Read/write hooks, mock functions, lifecycle management.

from typing import Callable, Dict, List, Optional, TYPE_CHECKING, Any
import logging

if TYPE_CHECKING:
    from analyzer_core.emu.memory_manager import MemoryManager


class HookManager:
    def __init__(self): # type: ignore
        self._read_hooks: Dict[int, List[Callable[[int, Any, "MemoryManager"], None]]] = {}
        self._write_hooks: Dict[int, List[Callable[[int, Any, "MemoryManager"], None]]] = {}
        self._pre_hooks: Dict[int, List[Callable]] = {}
        self._post_hooks: Dict[int, List[Callable]] = {}
        self._mocked_functions: Dict[int, Callable] = {}

        # Helper to track if we are waiting for post hooks at function beginnings
        self.waiting_for_post_hook: Dict[int, int] = {}

        self.logger = logging.getLogger(f"{__name__}.HookManager")

    def add_read_hook(self, addr: int, callback: Callable[[int, Any, "MemoryManager"], None]):
        """Register a callback for read access at a specific address."""
        self._read_hooks.setdefault(addr & 0xFFFF, []).append(callback)
    
    def remove_write_hook(self, addr: int, callback: Callable[[int, Any, "MemoryManager"], None]):
        """Remove a specific write hook for an address."""
        if addr & 0xFFFF in self._write_hooks:
            if callback in self._write_hooks[addr & 0xFFFF]:
                self._write_hooks[addr & 0xFFFF].remove(callback)
                if not self._write_hooks[addr & 0xFFFF]:
                    del self._write_hooks[addr & 0xFFFF]
            # TODO bei nicht angeben von callback -> alle entfernen!
            

    def add_write_hook(self, addr: int, callback: Callable[[int, Any, "MemoryManager"], None]):
        """Register a callback for write access at a specific address."""
        self._write_hooks.setdefault(addr & 0xFFFF, []).append(callback)
    
    def remove_read_hook(self, addr: int, callback: Callable[[int, Any, "MemoryManager"], None]):
        """Remove a specific read hook for an address."""
        if addr & 0xFFFF in self._read_hooks:
            if callback in self._read_hooks[addr & 0xFFFF]:
                self._read_hooks[addr & 0xFFFF].remove(callback)
                if not self._read_hooks[addr & 0xFFFF]:
                    del self._read_hooks[addr & 0xFFFF]
    
    # pre / post hook API
    def add_pre_hook(self, addr: int, fn: Callable) -> None:
        self._pre_hooks.setdefault(addr & 0xFFFF, []).append(fn)

    def add_post_hook(self, addr: int, fn: Callable) -> None:
        self._post_hooks.setdefault(addr & 0xFFFF, []).append(fn)
    
    def run_pre_hooks(self, addr: int, emulator) -> None:
        for fn in self._pre_hooks.get(addr & 0xFFFF, []):
            fn(emulator)

    def get_post_hooks(self, addr: int) -> List[Callable]:
        return self._post_hooks.get(addr & 0xFFFF, [])

    def run_post_hooks(self, addr: int, emulator, mem_access) -> None:
        for fn in self.get_post_hooks(addr):
            fn(emulator, mem_access)

    def run_read_hooks(self, addr: int, value: int|None, mem_mgr: "MemoryManager") -> bool:
        """Run all read hooks for the given address and value. Returns True if any hook was called."""
        at_least_one_hook = False
        for cb in self._read_hooks.get(addr & 0xFFFF, []):
            try:
                cb(addr & 0xFFFF, value, mem_mgr)
                at_least_one_hook = True
            except Exception as e:
                self.logger.exception("read_hook error")
        return at_least_one_hook

    def run_write_hooks(self, addr: int, value: int|None, mem_mgr: "MemoryManager"):
        """Run all write hooks for the given address and value."""
        for cb in self._write_hooks.get(addr & 0xFFFF, []):
            try:
                # NOTE: When we pass value, we only get 8bit, even if it's a 16bit write command
                cb(addr & 0xFFFF, value, mem_mgr)
            except Exception as e:
                self.logger.exception("write_hook error")

    def mock_function(self, fn_addr: int, stub: Callable):
        """Register a mock function for a given function address."""
        self._mocked_functions[fn_addr & 0xFFFF] = stub

    def get_mock(self, fn_addr: int) -> Optional[Callable]:
        """Get the mock function for a given address, if any."""
        return self._mocked_functions.get(fn_addr & 0xFFFF)

    def clear_hooks_and_mocks(self):
        """Remove all registered mock functions and hooks (read/write)."""
        self._mocked_functions.clear()
        self._write_hooks.clear()
        self._read_hooks.clear()
        self._pre_hooks.clear()
        self._post_hooks.clear()
