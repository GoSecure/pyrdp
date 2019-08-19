#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
from queue import Queue
from typing import Dict

from PySide2.QtCore import Qt, Signal
from PySide2.QtWidgets import QApplication, QMessageBox, QWidget

from pyrdp.player.BaseWindow import BaseWindow
from pyrdp.player.LiveTab import LiveTab
from pyrdp.player.LiveThread import LiveThread


class LiveWindow(BaseWindow):
    """
    Class that holds logic for live player (network RDP connections as they happen) tabs.
    """

    connectionReceived = Signal()
    closedTabText = " - Closed"

    def __init__(self, address: str, port: int, updateCountSignal: Signal, options: Dict[str, object], parent: QWidget = None):
        super().__init__(options, parent)

        QApplication.instance().aboutToQuit.connect(self.onClose)

        self.server = LiveThread(address, port, self.onConnection)
        self.server.start()
        self.connectionReceived.connect(self.createLivePlayerTab)
        self.queue = Queue()
        self.updateCountSignal = updateCountSignal

    def onConnection(self) -> asyncio.Protocol:
        self.connectionReceived.emit()
        tab = self.queue.get()
        return tab.getProtocol()

    def createLivePlayerTab(self):
        tab = LiveTab()
        tab.renameTab.connect(self.renameLivePlayerTab)
        tab.connectionClosed.connect(self.onConnectionClosed)
        self.addTab(tab, "New connection")

        if self.options.get("focusNewTab"):
            self.setCurrentIndex(self.count() - 1)

        self.updateCountSignal.emit()
        self.queue.put(tab)

    def renameLivePlayerTab(self, tab: LiveTab, name: str):
        index = self.indexOf(tab)
        self.setTabText(index, name)

    def onClose(self):
        self.server.stop()

    def onConnectionClosed(self, tab: LiveTab):
        index = self.indexOf(tab)
        text = self.tabText(index)
        name = text + self.closedTabText
        self.setTabText(index, name)

    def sendKeySequence(self, keys: [Qt.Key]):
        tab: LiveTab = self.currentWidget()

        if tab is not None:
            tab.sendKeySequence(keys)

    def sendText(self, text: str):
        tab: LiveTab = self.currentWidget()

        if tab is not None:
            tab.sendText(text)

    def onTabClosed(self, index: int):
        """
        Gracefully closes the tab by calling the onClose method
        :param index: Index of the closed tab
        """
        super().onTabClosed(index)
        self.updateCountSignal.emit()

    def onTabCloseRequest(self, index: int):
        """
        Prompt the user for validation when the connection is live, then forward call to the parent.
        """
        text = self.tabText(index)

        if not text.endswith(self.closedTabText):
            reply = QMessageBox.question(self, "Confirm close", "Are you sure you want to close a tab with an active connection?", QMessageBox.Yes|QMessageBox.No)
            if reply == QMessageBox.No:
                return

        super().onTabCloseRequest(index)
