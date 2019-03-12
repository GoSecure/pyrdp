#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from PySide2.QtCore import Signal
from PySide2.QtWidgets import QWidget

from pyrdp.layer import AsyncIOTCPLayer, LayerChainItem, PlayerMessageLayer
from pyrdp.player.PlayerMessageHandler import PlayerMessageHandler
from pyrdp.player.BaseTab import BaseTab
from pyrdp.ui import QRemoteDesktop


class LiveTab(BaseTab):
    """
    Tab playing a live RDP connection as data is being received over the network.
    """

    connectionClosed = Signal(object)

    def __init__(self, parent: QWidget = None):
        super().__init__(QRemoteDesktop(1024, 768), parent)
        self.tcp = AsyncIOTCPLayer()
        self.player = PlayerMessageLayer()
        self.eventHandler = PlayerMessageHandler(self.widget, self.text)

        LayerChainItem.chain(self.tcp, self.player)
        self.player.addObserver(self.eventHandler)

    def getProtocol(self):
        return self.tcp

    def onDisconnection(self):
        self.connectionClosed.emit()

    def onClose(self):
        self.tcp.disconnect(True)
