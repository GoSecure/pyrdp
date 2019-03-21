#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from PySide2.QtWidgets import QAction, QFileDialog, QMainWindow, QTabWidget

from pyrdp.player.LiveWindow import LiveWindow
from pyrdp.player.ReplayWindow import ReplayWindow


class MainWindow(QMainWindow):
    """
    Main window for the player application.
    """

    def __init__(self, bind_address: str, port: int, filesToRead: [str]):
        """
        :param bind_address: address to bind to when listening for live connections.
        :param port: port to bind to when listening for live connections.
        :param filesToRead: replay files to open.
        """
        super().__init__()

        self.liveWindow = LiveWindow(bind_address, port)
        self.replayWindow = ReplayWindow()

        self.tabManager = QTabWidget()
        self.tabManager.addTab(self.liveWindow, "Live connections")
        self.tabManager.addTab(self.replayWindow, "Replays")
        self.setCentralWidget(self.tabManager)

        openAction = QAction("Open...", self)
        openAction.setShortcut("Ctrl+O")
        openAction.setStatusTip("Open a replay file")
        openAction.triggered.connect(self.onOpenFile)

        menuBar = self.menuBar()
        fileMenu = menuBar.addMenu("File")
        fileMenu.addAction(openAction)

        for fileName in filesToRead:
            self.replayWindow.openFile(fileName)

    def onOpenFile(self):
        fileName, _ = QFileDialog.getOpenFileName(self, "Open File")

        if fileName:
            self.tabManager.setCurrentWidget(self.replayWindow)
            self.replayWindow.openFile(fileName)
