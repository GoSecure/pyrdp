#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QWidget, QSpacerItem, QSizePolicy

from pyrdp.logging import LOGGER_NAMES
from pyrdp.ui import PlayPauseButton


class AttackerBar(QWidget):
    """
    Bar that contains widgets for live session actions.
    """

    controlTaken = Signal()
    controlReleased = Signal()

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)

        self.log = logging.getLogger(LOGGER_NAMES.PLAYER)

        self.attackButton = PlayPauseButton(playText = "Take control", pauseText = "Release control")
        self.attackButton.clicked.connect(self.onAttackButtonClicked)

        horizontal = QHBoxLayout()
        horizontal.addWidget(self.attackButton)
        horizontal.addItem(QSpacerItem(1, 1, QSizePolicy.Expanding, QSizePolicy.Minimum))

        self.setLayout(horizontal)

    def onAttackButtonClicked(self):
        if self.attackButton.playing:
            self.log.debug("Attacker has taken control")
            self.controlTaken.emit()
        else:
            self.log.debug("Attacker has released control")
            self.controlReleased.emit()
