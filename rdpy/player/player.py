import logging

from PyQt4.QtCore import Qt, pyqtSignal
from PyQt4.QtGui import QMainWindow, QTabWidget, QVBoxLayout, QWidget, QAction, QFileDialog, QPushButton, QLabel, \
    QSlider, QHBoxLayout, QSpacerItem, QSizePolicy

from rdpy.player.live import LivePlayerWindow
from rdpy.player.replay import ReplayWindow


class MainWindow(QMainWindow):
    """
    Main window that contains every other QWidgets.
    """

    def __init__(self, bind_address, port, filesToRead):
        QMainWindow.__init__(self)

        self.liveWindow = LivePlayerWindow(bind_address, port)
        self.replayWindow = ReplayWindow()

        self.controlBar = ControlBar()
        self.controlBar.play.connect(self.replayWindow.onPlay)
        self.controlBar.stop.connect(self.replayWindow.onStop)
        self.controlBar.restart.connect(self.replayWindow.onRestart)
        self.controlBar.speedChanged.connect(self.replayWindow.onSpeedChanged)

        self.tabManager = QTabWidget()
        self.tabManager.addTab(self.replayWindow, "Replays")
        self.tabManager.addTab(self.liveWindow, "Live connections")

        layout = QVBoxLayout()
        layout.addWidget(self.tabManager, 500)
        layout.addWidget(self.controlBar, 5, alignment=Qt.AlignBottom)

        mainWidget = QWidget()
        mainWidget.setLayout(layout)
        self.setCentralWidget(mainWidget)

        openAction = QAction("Open...", self)
        openAction.setShortcut("Ctrl+O")
        openAction.setStatusTip("Open a replay file")
        openAction.triggered.connect(self.onOpenFile)

        menuBar = self.menuBar()
        fileMenu = menuBar.addMenu("File")
        fileMenu.addAction(openAction)

        for fileName in filesToRead:
            self.tabManager.openFile(fileName)

    def onOpenFile(self):
        fileName = QFileDialog.getOpenFileName(self, "Open File")
        self.replayWindow.openFile(fileName)


class ControlBar(QWidget):
    """
    Control bar displayed at the bottom of the GUI that gives access
    to buttons such as Play, stop and rewind.
    """
    play = pyqtSignal(name="Play")
    stop = pyqtSignal(name="Stop")
    restart = pyqtSignal(name="Restart")
    speedChanged = pyqtSignal(int, name="Speed")

    def __init__(self, parent = None):
        QWidget.__init__(self, parent)

        self.log = logging.getLogger("liveplayer")

        self.playButton = QPushButton("Play")
        self.playButton.setMaximumWidth(100)
        self.playButton.clicked.connect(self.onPlayClicked)

        self.stopButton = QPushButton("Pause")
        self.stopButton.setMaximumWidth(100)
        self.stopButton.clicked.connect(self.onStopClicked)

        self.restartButton = QPushButton("Restart")
        self.restartButton.setMaximumWidth(100)
        self.restartButton.clicked.connect(self.onRestartClicked)

        self.speedLabel = QLabel("Speed: 1x")

        self.speedSlider = QSlider(Qt.Horizontal)
        self.speedSlider.setMaximumWidth(300)
        self.speedSlider.setMinimum(1)
        self.speedSlider.setMaximum(10)
        self.speedSlider.valueChanged.connect(self.onSpeedChanged)

        vertical = QVBoxLayout()
        horizontal = QHBoxLayout()
        horizontal.addWidget(self.playButton)
        horizontal.addWidget(self.stopButton)
        horizontal.addWidget(self.restartButton)
        horizontal.addItem(QSpacerItem(20, 40, QSizePolicy.Expanding, QSizePolicy.Expanding))
        vertical.addLayout(horizontal)

        horizontal = QHBoxLayout()
        horizontal.addWidget(self.speedLabel)
        horizontal.addWidget(self.speedSlider)
        horizontal.addItem(QSpacerItem(20, 40, QSizePolicy.Expanding, QSizePolicy.Expanding))
        vertical.addLayout(horizontal)

        self.setLayout(vertical)
        self.setGeometry(0, 0, 80, 60)

    def onPlayClicked(self):
        self.log.debug("Play clicked")
        self.speedChanged.emit(self.speedSlider.value())
        self.play.emit()

    def onStopClicked(self):
        self.log.debug("Stop clicked")
        self.stop.emit()

    def onRestartClicked(self):
        self.log.debug("Restart clicked")
        self.restart.emit()

    def onSpeedChanged(self):
        speed = self.speedSlider.value()
        self.log.debug("Slider changed value: {}".format(speed))
        self.speedLabel.setText("Speed: {}x".format(speed))
        self.speedChanged.emit(speed)