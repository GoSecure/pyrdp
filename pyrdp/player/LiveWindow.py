#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
from queue import Queue

from PySide2.QtCore import Signal, Qt
from PySide2.QtWidgets import QApplication, QWidget

from pyrdp.player.BaseWindow import BaseWindow
from pyrdp.player.LiveTab import LiveTab
from pyrdp.player.LiveThread import LiveThread


class LiveWindow(BaseWindow):
    """
    Class that holds logic for live player (network RDP connections as they happen) tabs.
    """
    connectionReceived = Signal()

    def __init__(self, address: str, port: int, parent: QWidget = None):
        super().__init__(parent)
        QApplication.instance().aboutToQuit.connect(self.onClose)

        self.server = LiveThread(address, port, self.onConnection)
        self.server.start()
        self.connectionReceived.connect(self.createLivePlayerTab)
        self.queue = Queue()

    def onConnection(self) -> asyncio.Protocol:
        self.connectionReceived.emit()
        tab = self.queue.get()
        return tab.getProtocol()

    def createLivePlayerTab(self):
        tab = LiveTab()
        tab.connectionClosed.connect(self.onConnectionClosed)
        self.addTab(tab, "New connection")
        self.setCurrentIndex(self.count() - 1)
        self.queue.put(tab)

    def onConnectionClosed(self, tab: LiveTab):
        index = self.indexOf(tab)
        text = self.tabText(index)
        self.setTabText(index, text + " - Closed")

    def onClose(self):
        self.server.stop()

    def sendKeySequence(self, keys: [Qt.Key]):
        tab: LiveTab = self.currentWidget()

        if tab is not None:
            tab.sendKeySequence(keys)

    def sendText(self, text: str):
        tab: LiveTab = self.currentWidget()

        if tab is not None:
            tab.sendText(text)