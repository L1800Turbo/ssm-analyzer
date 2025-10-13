from PyQt6.QtGui import QStandardItemModel, QStandardItem

class FunctionCallTreeModel(QStandardItemModel):
    def __init__(self, call_tree: dict, functions: dict, parent=None):
        super().__init__(parent)
        self.setHorizontalHeaderLabels(["Function", "Address"])
        self._populate(call_tree, self.invisibleRootItem(), functions)

    def _populate(self, tree, parent_item, functions):
        for addr, subtree in tree.items():
            fn_name = functions.get(addr).name if addr in functions else f"${addr:04X}"
            item = QStandardItem(fn_name)
            addr_item = QStandardItem(f"${addr:04X}")
            parent_item.appendRow([item, addr_item])
            if subtree:
                self._populate(subtree, item, functions)