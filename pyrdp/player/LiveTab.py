#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio

from PySide2.QtCore import Qt, Signal
from PySide2.QtWidgets import QWidget

from pyrdp.player.AttackerBar import AttackerBar
from pyrdp.player.BaseTab import BaseTab
from pyrdp.player.PlayerEventHandler import PlayerEventHandler
from pyrdp.player.PlayerLayerSet import AsyncIOPlayerLayerSet
from pyrdp.player.RDPMITMWidget import RDPMITMWidget


class LiveTab(BaseTab):
    """
    Tab playing a live RDP connection as data is being received over the network.
    """

    connectionClosed = Signal(object)

    def __init__(self, parent: QWidget = None):
        layers = AsyncIOPlayerLayerSet()
        rdpWidget = RDPMITMWidget(1024, 768, layers.player)

        super().__init__(rdpWidget, parent)
        self.layers = layers
        self.rdpWidget = rdpWidget
        self.eventHandler = PlayerEventHandler(self.widget, self.text)
        self.attackerBar = AttackerBar()

        self.attackerBar.controlTaken.connect(lambda: self.rdpWidget.setControlState(True))
        self.attackerBar.controlReleased.connect(lambda: self.rdpWidget.setControlState(False))

        self.tabLayout.insertWidget(0, self.attackerBar)
        self.layers.player.addObserver(self.eventHandler)

    def getProtocol(self) -> asyncio.Protocol:
        return self.layers.tcp

    def onDisconnection(self):
        self.connectionClosed.emit()

    def onClose(self):
        self.layers.tcp.disconnect(True)

    def sendKeySequence(self, keys: [Qt.Key]):
        self.rdpWidget.sendKeySequence(keys)

    def sendText(self, text: str):
        self.rdpWidget.sendText(text)