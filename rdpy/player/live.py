from queue import Queue

from PyQt4.QtCore import pyqtSignal
from PyQt4.QtGui import qApp

from rdpy.core.rss import RssAdaptor
from rdpy.layer.recording import RDPPlayerMessageLayer
from rdpy.layer.tcp import AsyncIOTCPLayer
from rdpy.layer.tpkt import TPKTLayer
from rdpy.player.BasePlayerWindow import BasePlayerWindow
from rdpy.player.RDPConnectionTab import RDPConnectionTab
from rdpy.player.ServerThread import ServerThread
from rdpy.ui.event import RSSEventHandler
from rdpy.ui.qt4 import QRemoteDesktop


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
        RDPConnectionTab.__init__(self, QRemoteDesktop(1024, 768, RssAdaptor()))
        self.tcp = AsyncIOTCPLayer()
        self.tpkt = TPKTLayer()
        self.message = RDPPlayerMessageLayer()
        self.eventHandler = RSSEventHandler(self.widget, self.text)

        self.tcp.setNext(self.tpkt)
        self.tpkt.setNext(self.message)
        self.message.addObserver(self.eventHandler)

    def getProtocol(self):
        return self.tcp

    def onDisconnection(self):
        self.connectionClosed.emit()