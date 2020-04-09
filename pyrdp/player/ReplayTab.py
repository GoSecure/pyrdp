#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from PySide2.QtGui import QResizeEvent
from PySide2.QtWidgets import QApplication, QWidget

from pyrdp.layer import PlayerLayer
from pyrdp.player.BaseTab import BaseTab
from pyrdp.player.PlayerEventHandler import PlayerEventHandler
from pyrdp.player.Replay import Replay
from pyrdp.player.ReplayBar import ReplayBar
from pyrdp.player.ReplayThread import ReplayThread
from pyrdp.ui import QRemoteDesktop


class ReplayTab(BaseTab):
    """
    Tab that displays a RDP Connection that is being replayed from a file.
    """

    def __init__(self, fileName: str, parent: QWidget):
        """
        :param fileName: name of the file to read.
        :param parent: parent widget.
        """
        self.viewer = QRemoteDesktop(800, 600, parent)
        super().__init__(self.viewer, parent)
        QApplication.instance().aboutToQuit.connect(self.onClose)

        self.fileName = fileName
        self.file = open(self.fileName, "rb")
        self.eventHandler = PlayerEventHandler(self.widget, self.text)

        replay = Replay(self.file)
        self.thread = ReplayThread(replay)
        self.thread.eventReached.connect(self.readEvent)
        self.thread.timeUpdated.connect(self.onTimeUpdated)
        self.thread.clearNeeded.connect(self.clear)
        self.thread.start()

        self.controlBar = ReplayBar(replay.duration)
        self.controlBar.play.connect(self.thread.play)
        self.controlBar.pause.connect(self.thread.pause)
        self.controlBar.seek.connect(self.thread.seek)
        self.controlBar.speedChanged.connect(self.thread.setSpeed)
        self.controlBar.scaleCheckbox.stateChanged.connect(self.setScaleToWindow)
        self.controlBar.button.setDefault(True)

        self.tabLayout.insertWidget(0, self.controlBar)

        self.player = PlayerLayer()
        self.player.addObserver(self.eventHandler)

    def play(self):
        self.controlBar.play.emit()

    def readEvent(self, position: int):
        """
        Read an event from the file at the given position.
        :param position: the position of the event in the file.
        """
        self.file.seek(position)

        data = self.file.read(8)
        self.player.recv(data)

        length = self.player.getDataLengthRequired()
        data = self.file.read(length)
        self.player.recv(data)

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

    def setScaleToWindow(self, status: int):
        """
        Called when the scale to window checkbox is checked or unchecked, refresh
        the scaling calculation.
        :param status: state of the checkbox
        """
        self.parentResized(None)
        self.widget.setScaleToWindow(status)

    def parentResized(self, event: QResizeEvent):
        """
        Called when the main PyRDP window is resized to allow to scale the current
        RDP session being displayed.
        :param event: The event of the parent that has been resized
        """
        newScale = (self.scrollViewer.height() - self.scrollViewer.horizontalScrollBar().height()) / self.widget.sessionHeight
        self.widget.scale(newScale)
