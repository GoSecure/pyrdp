#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QAction, QFileDialog, QMainWindow, QTabWidget, QInputDialog

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

        windowsRAction = QAction("Windows+R", self)
        windowsRAction.setShortcut("Ctrl+Alt+R")
        windowsRAction.setStatusTip("Send a Windows+R key sequence")
        windowsRAction.triggered.connect(lambda: self.sendKeySequence([Qt.Key.Key_Meta, Qt.Key.Key_R]))

        windowsLAction = QAction("Windows+L", self)
        windowsLAction.setShortcut("Ctrl+Alt+L")
        windowsLAction.setStatusTip("Send a Windows+L key sequence")
        windowsLAction.triggered.connect(lambda: self.sendKeySequence([Qt.Key.Key_Meta, Qt.Key.Key_L]))

        windowsEAction = QAction("Windows+E", self)
        windowsEAction.setShortcut("Ctrl+Alt+E")
        windowsEAction.setStatusTip("Send a Windows+E key sequence")
        windowsEAction.triggered.connect(lambda: self.sendKeySequence([Qt.Key.Key_Meta, Qt.Key.Key_E]))

        typeTextAction = QAction("Type text...", self)
        typeTextAction.setShortcut("Ctrl+Alt+T")
        typeTextAction.setStatusTip("Simulate typing on the keyboard")
        typeTextAction.triggered.connect(self.sendText)

        menuBar = self.menuBar()

        fileMenu = menuBar.addMenu("File")
        fileMenu.addAction(openAction)

        commandMenu = menuBar.addMenu("Command")
        commandMenu.addAction(windowsRAction)
        commandMenu.addAction(windowsLAction)
        commandMenu.addAction(windowsEAction)
        commandMenu.addAction(typeTextAction)

        for fileName in filesToRead:
            self.replayWindow.openFile(fileName)

    def onOpenFile(self):
        fileNames, _ = QFileDialog.getOpenFileNames(self, "Open File(s)")

        if fileNames:
            self.tabManager.setCurrentWidget(self.replayWindow)
            for fileName in fileNames:
                self.replayWindow.openFile(fileName)


    def sendKeySequence(self, keys: [Qt.Key]):
        if self.tabManager.currentWidget() is self.liveWindow:
            self.liveWindow.sendKeySequence(keys)

    def sendText(self):
        if self.tabManager.currentWidget() is not self.liveWindow:
            return

        text, success = QInputDialog.getMultiLineText(self, "Type text...", "Text to type:")

        if not success:
            return

        self.liveWindow.sendText(text)