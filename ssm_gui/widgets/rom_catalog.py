# ROM-Information Viewer
# Zeigt ROM-Metadaten, Funktionen, Strings, Exportoptionen.

# ROM Catalog Widget
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel

class RomCatalogWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("ROM Catalog (Meta, Functions, Strings, Export/CSV)"))
        self.setLayout(layout)
