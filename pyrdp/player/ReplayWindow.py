from PySide2.QtWidgets import QWidget

from pyrdp.player import BasePlayerWindow
from pyrdp.player.ReplayTab import ReplayTab


class ReplayWindow(BasePlayerWindow):
    """
    Class for managing replay tabs.
    """

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)

    def openFile(self, fileName: str):
        """
        Open a replay file and open a new tab.
        :param fileName: replay path.
        """
        tab = ReplayTab(fileName)
        self.addTab(tab, fileName)
        self.log.debug("Loading replay file %(arg1)s", {"arg1": fileName})