#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QScrollArea, QTextEdit, QVBoxLayout, QWidget

from pyrdp.logging import LOGGER_NAMES
from pyrdp.ui import QRemoteDesktop


class BaseTab(QWidget):
    """
    Class that encapsulates logic for a tab that displays an RDP connection, regardless of its origin
    (network or file).
    """

    def __init__(self, viewer: QRemoteDesktop, parent: QWidget = None):
        """
        :param viewer: the RDP viewer widget
        :param parent: the parent widget
        """
        super().__init__(parent, Qt.WindowFlags())
        self.widget = viewer

        self.writeInCaps = False
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setMinimumHeight(150)
        self.log = logging.getLogger(LOGGER_NAMES.PLAYER)

        scrollViewer = QScrollArea()
        scrollViewer.setWidget(self.widget)

        self.tabLayout = QVBoxLayout()
        self.tabLayout.addWidget(scrollViewer, 8)
        self.tabLayout.addWidget(self.text, 2)

        self.setLayout(self.tabLayout)
