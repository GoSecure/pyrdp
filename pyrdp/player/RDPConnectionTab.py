from PyQt4.QtCore import Qt
from PyQt4.QtGui import QWidget, QTextEdit, QScrollArea, QVBoxLayout

from pyrdp.core.helpers import getLoggerPassFilters
from pyrdp.logging import LOGGER_NAMES


class RDPConnectionTab(QWidget):
    """
    Class that encapsulates logic for a tab that displays an RDP connection, regardless of its origin
    (network or file)
    """

    def __init__(self, viewer):
        """
        :type viewer: QWidget
        """
        QWidget.__init__(self, None, Qt.WindowFlags())
        self.widget = viewer

        self.writeInCaps = False
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setMinimumHeight(150)
        self.log = getLoggerPassFilters(LOGGER_NAMES.LIVEPLAYER)

        scrollViewer = QScrollArea()
        scrollViewer.setWidget(self.widget)
        layout = QVBoxLayout()
        layout.addWidget(scrollViewer, 8)
        layout.addWidget(self.text, 2)

        self.setLayout(layout)
