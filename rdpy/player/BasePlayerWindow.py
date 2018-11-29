import logging

from PyQt4.QtGui import QTabWidget, QShortcut, QKeySequence


class BasePlayerWindow(QTabWidget):
    """
    Class that encapsulates the common logic to manage a QtTabWidget to display RDP connections,
    regardless of their origin (network or file).
    """

    def __init__(self, maxTabCount=250):
        QTabWidget.__init__(self)
        self.closeTabShortcut = QShortcut(QKeySequence("Ctrl+W"), self, self.closeCurrentTab)
        self.maxTabCount = maxTabCount
        self.setTabsClosable(True)
        self.tabCloseRequested.connect(self.onTabClosed)
        self.log = logging.getLogger("liveplayer")

    def closeCurrentTab(self):
        if self.count() > 0:
            self.onTabClosed(self.currentIndex())

    def onTabClosed(self, index):
        """
        Gracefully closes the tab by calling the onClose method
        :param index: Index of the closed tab
        """
        tab = self.widget(index)
        tab.onClose()
        self.removeTab(index)
