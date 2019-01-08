#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from queue import Queue

from PyQt4.QtCore import pyqtSignal
from PyQt4.QtGui import qApp

from pyrdp.layer import AsyncIOTCPLayer, PlayerMessageLayer, TPKTLayer, Layer, IntermediateLayer
from pyrdp.layer.layer import LayerChainItem
from pyrdp.player.BasePlayerWindow import BasePlayerWindow
from pyrdp.player.event import PlayerMessageHandler
from pyrdp.player.RDPConnectionTab import RDPConnectionTab
from pyrdp.player.ServerThread import ServerThread
from pyrdp.ui import QRemoteDesktop


class LivePlayerWindow(BasePlayerWindow):
    """
    Class that holds logic for live player (network RDP connections as they happen) tabs.
    """
    connectionReceived = pyqtSignal(name="Connection received")

    def __init__(self, address, port):
        BasePlayerWindow.__init__(self)
        qApp.aboutToQuit.connect(self.onClose)

        self.server = ServerThread(address, port, self.onConnection)
        self.server.start()
        self.connectionReceived.connect(self.createLivePlayerTab)
        self.queue = Queue()

    def onConnection(self):
        self.connectionReceived.emit()
        tab = self.queue.get()
        return tab.getProtocol()

    def createLivePlayerTab(self):
        tab = LivePlayerTab()
        tab.connectionClosed.connect(self.onConnectionClosed)
        self.addTab(tab, "New connection")
        self.setCurrentIndex(self.count() - 1)
        self.queue.put(tab)

    def onConnectionClosed(self, tab):
        index = self.indexOf(tab)
        text = self.tabText(index)
        self.setTabText(index, text + " - Closed")

    def onClose(self):
        self.server.stop()


class LivePlayerTab(RDPConnectionTab):
    """
    Tab playing a live RDP connection as data is being received over the network.
    """

    connectionClosed = pyqtSignal(object, name="Close")

    def __init__(self):
        RDPConnectionTab.__init__(self, QRemoteDesktop(1024, 768))
        self.tcp = AsyncIOTCPLayer()
        self.tpkt = TPKTLayer()
        self.message = PlayerMessageLayer()
        self.eventHandler = PlayerMessageHandler(self.widget, self.text)

        LayerChainItem.chain(self.tcp, self.tpkt, self.message)
        self.message.addObserver(self.eventHandler)

    def getProtocol(self):
        return self.tcp

    def onDisconnection(self):
        self.connectionClosed.emit()

    def onClose(self):
        self.tcp.disconnect()
