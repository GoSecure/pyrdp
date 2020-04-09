#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Dict

from PySide2.QtWidgets import QWidget

from pyrdp.player import MainWindow
from pyrdp.player.BaseWindow import BaseWindow
from pyrdp.player.ReplayTab import ReplayTab


class ReplayWindow(BaseWindow):
    """
    Class for managing replay tabs.
    """

    def __init__(self, options: Dict[str, object], mainWindow: MainWindow, parent: QWidget = None):
        super().__init__(options, parent=parent)
        self.mainWindow = mainWindow

    def openFile(self, fileName: str, autoplay: bool = False):
        """
        Open a replay file and open a new tab.
        :param fileName: replay path.
        """
        tab = ReplayTab(fileName)
        self.mainWindow.addObserver(tab)
        self.addTab(tab, fileName)
        self.log.debug("Loading replay file %(arg1)s", {"arg1": fileName})
        if autoplay:
            tab.play()
