from PyQt4.QtGui import QMainWindow, QTabWidget, QAction, QFileDialog

from pyrdp.player.live import LivePlayerWindow
from pyrdp.player.replay import ReplayWindow


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
        QMainWindow.__init__(self)

        self.liveWindow = LivePlayerWindow(bind_address, port)
        self.replayWindow = ReplayWindow()

        self.tabManager = QTabWidget()
        self.tabManager.addTab(self.replayWindow, "Replays")
        self.tabManager.addTab(self.liveWindow, "Live connections")
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
        fileName = QFileDialog.getOpenFileName(self, "Open File")

        if fileName:
            self.replayWindow.openFile(fileName)
