#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2023 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QSizePolicy, QSlider, QSpacerItem, \
    QVBoxLayout, QWidget

from pyrdp.logging import LOGGER_NAMES
from pyrdp.player.SeekBar import SeekBar
from pyrdp.ui import PlayPauseButton


class ReplayBar(QWidget):
    """
    Widget that contains the play/pause button, the seek bar and the speed slider.
    """
    play = Signal()
    pause = Signal()
    seek = Signal(float)
    speedChanged = Signal(int)

    def __init__(self, duration: float, parent: QWidget = None):
        super().__init__(parent)

        self.log = logging.getLogger(LOGGER_NAMES.PLAYER)

        self.button = PlayPauseButton()
        self.button.setMaximumWidth(100)
        self.button.clicked.connect(self.onButtonClicked)

        self.scaleCheckbox = QCheckBox("Scale to window")

        self.timeSlider = SeekBar()
        self.timeSlider.setMinimum(0)
        self.timeSlider.setMaximum(int(duration * 1000))
        self.timeSlider.valueChanged.connect(self.onSeek)

        self.speedLabel = QLabel("Speed: 1x")

        self.speedSlider = QSlider(Qt.Horizontal)
        self.speedSlider.setMaximumWidth(300)
        self.speedSlider.setMinimum(1)
        self.speedSlider.setMaximum(10)
        self.speedSlider.valueChanged.connect(self.onSpeedChanged)

        vertical = QVBoxLayout()

        horizontal = QHBoxLayout()
        horizontal.addWidget(self.speedLabel)
        horizontal.addWidget(self.speedSlider)
        horizontal.addWidget(self.scaleCheckbox)
        horizontal.addItem(QSpacerItem(20, 40, QSizePolicy.Expanding, QSizePolicy.Expanding))
        vertical.addLayout(horizontal)

        horizontal = QHBoxLayout()
        horizontal.addWidget(self.button)
        horizontal.addWidget(self.timeSlider)
        vertical.addLayout(horizontal)

        self.setLayout(vertical)
        self.setGeometry(0, 0, 80, 60)

    def onButtonClicked(self):
        if self.button.playing:
            self.log.debug("Play clicked")
            self.play.emit()
        else:
            self.log.debug("Pause clicked")
            self.pause.emit()

    def onSeek(self):
        time = self.timeSlider.value() / 1000.0
        self.log.debug("Seek to %(arg1)d seconds", {"arg1": time})
        self.seek.emit(time)

    def onSpeedChanged(self):
        speed = self.speedSlider.value()
        self.log.debug("Slider changed value: %(arg1)d", {"arg1": speed})
        self.speedLabel.setText("Speed: {}x".format(speed))
        self.speedChanged.emit(speed)
