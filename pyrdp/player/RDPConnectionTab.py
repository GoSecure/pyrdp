#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import logging

from PyQt4.QtCore import Qt
from PyQt4.QtGui import QScrollArea, QTextEdit, QVBoxLayout, QWidget

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
        self.log = logging.getLogger(LOGGER_NAMES.PLAYER)

        scrollViewer = QScrollArea()
        scrollViewer.setWidget(self.widget)
        layout = QVBoxLayout()
        layout.addWidget(scrollViewer, 8)
        layout.addWidget(self.text, 2)

        self.setLayout(layout)
