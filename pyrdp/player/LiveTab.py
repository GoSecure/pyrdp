#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import asyncio

from PySide2.QtCore import Signal
from PySide2.QtWidgets import QWidget

from pyrdp.player.BaseTab import BaseTab
from pyrdp.player.PlayerHandler import PlayerHandler
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
        self.eventHandler = PlayerHandler(self.widget, self.text)

        self.layers.player.addObserver(self.eventHandler)
        self.rdpWidget.handleEvents = True

    def getProtocol(self) -> asyncio.Protocol:
        return self.layers.tcp

    def onDisconnection(self):
        self.connectionClosed.emit()

    def onClose(self):
        self.layers.tcp.disconnect(True)
