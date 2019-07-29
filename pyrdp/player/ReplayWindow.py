#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Dict

from PySide2.QtWidgets import QWidget

from pyrdp.player.BaseWindow import BaseWindow
from pyrdp.player.ReplayTab import ReplayTab


class ReplayWindow(BaseWindow):
    """
    Class for managing replay tabs.
    """

    def __init__(self, options: Dict[str, object], parent: QWidget = None):
        super().__init__(options, parent)

    def openFile(self, fileName: str):
        """
        Open a replay file and open a new tab.
        :param fileName: replay path.
        """
        tab = ReplayTab(fileName)
        self.addTab(tab, fileName)
        self.log.debug("Loading replay file %(arg1)s", {"arg1": fileName})
