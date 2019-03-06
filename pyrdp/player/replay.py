#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import logging

from PySide2.QtCore import Qt, Signal
from PySide2.QtWidgets import QApplication, QHBoxLayout, QLabel, QSizePolicy, QSlider, QSpacerItem, QVBoxLayout, QWidget

from pyrdp.layer import PlayerMessageLayer, TPKTLayer
from pyrdp.logging import LOGGER_NAMES
from pyrdp.player.BasePlayerWindow import BasePlayerWindow
from pyrdp.player.ClickableProgressBar import ClickableProgressBar
from pyrdp.player.event import PlayerMessageHandler
from pyrdp.player.RDPConnectionTab import RDPConnectionTab
from pyrdp.player.ReplayThread import ReplayThread
from pyrdp.ui import PlayPauseButton, QRemoteDesktop


class ReplayWindow(BasePlayerWindow):
    """
    Class for managing replay tabs.
    """

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)

    def openFile(self, fileName: str):
        """
        Open a replay file and open a new tab.
        :param fileName: replay path.
        """
        tab = ReplayTab(fileName)
        self.addTab(tab, fileName)
        self.log.debug("Loading replay file %(arg1)s", {"arg1": fileName})


class ReplayTab(RDPConnectionTab):
    """
    Tab that displays a RDP Connection that is being replayed from a file.
    """

    def __init__(self, fileName: str, parent: QWidget = None):
        """
        :param fileName: name of the file to read.
        :param parent: parent widget.
        """
        self.viewer = QRemoteDesktop(800, 600)
        super().__init__(self.viewer, parent)
        QApplication.instance().aboutToQuit.connect(self.onClose)

        self.fileName = fileName
        self.file = open(self.fileName, "rb")
        self.eventHandler = PlayerMessageHandler(self.widget, self.text)

        self.thread = ReplayThread(self.file)
        self.thread.eventReached.connect(self.readEvent)
        self.thread.timeUpdated.connect(self.onTimeUpdated)
        self.thread.clearNeeded.connect(self.clear)
        self.thread.start()

        self.controlBar = ControlBar(self.thread.getDuration())
        self.controlBar.play.connect(self.thread.play)
        self.controlBar.pause.connect(self.thread.pause)
        self.controlBar.seek.connect(self.thread.seek)
        self.controlBar.speedChanged.connect(self.thread.setSpeed)

        self.layout().insertWidget(0, self.controlBar)

        self.tpkt = TPKTLayer()
        self.message = PlayerMessageLayer()

        self.tpkt.setNext(self.message)
        self.message.addObserver(self.eventHandler)

    def readEvent(self, position: int):
        """
        Read an event from the file at the given position.
        :param position: the position of the event in the file.
        """
        self.file.seek(position)

        data = self.file.read(4)
        self.tpkt.recv(data)

        length = self.tpkt.getDataLengthRequired()
        data = self.file.read(length)
        self.tpkt.recv(data)

    def onTimeUpdated(self, currentTime: float):
        """
        Called everytime the thread ticks.
        :param currentTime: the current time.
        """
        self.controlBar.timeSlider.blockSignals(True)
        self.controlBar.timeSlider.setValue(int(currentTime * 1000))
        self.controlBar.timeSlider.blockSignals(False)

    def clear(self):
        """
        Clear the UI.
        """
        self.viewer.clear()
        self.text.setText("")

    def onClose(self):
        self.thread.close()
        self.thread.wait()


class ControlBar(QWidget):
    """
    Widget that contains the play/pause button, the progress bar and the speed slider.
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

        self.timeSlider = ClickableProgressBar()
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
