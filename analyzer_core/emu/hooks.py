# HookManager
# Read/write hooks, mock functions, lifecycle management.

from typing import Callable, Dict, List, Optional
import logging

class HookManager:
    def __init__(self):
        self._read_hooks: Dict[int, List[Callable[[int, int], None]]] = {}
        self._write_hooks: Dict[int, List[Callable[[int, int], None]]] = {}
        self._mocked_functions: Dict[int, Callable] = {}
        self.logger = logging.getLogger(f"{__name__}.HookManager")

    def add_read_hook(self, addr: int, callback: Callable[[int, int], None]):
        """Register a callback for read access at a specific address."""
        self._read_hooks.setdefault(addr & 0xFFFF, []).append(callback)

    def add_write_hook(self, addr: int, callback: Callable[[int, int], None]):
        """Register a callback for write access at a specific address."""
        self._write_hooks.setdefault(addr & 0xFFFF, []).append(callback)

    def run_read_hooks(self, addr: int, value: int) -> bool:
        """Run all read hooks for the given address and value. Returns True if any hook was called."""
        at_least_one_hook = False
        for cb in self._read_hooks.get(addr & 0xFFFF, []):
            try:
                cb(addr & 0xFFFF, value & 0xFF)
                at_least_one_hook = True
            except Exception as e:
                self.logger.exception("read_hook error")
        return at_least_one_hook

    def run_write_hooks(self, addr: int, value: int):
        """Run all write hooks for the given address and value."""
        for cb in self._write_hooks.get(addr & 0xFFFF, []):
            try:
                cb(addr & 0xFFFF, value & 0xFF)
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
