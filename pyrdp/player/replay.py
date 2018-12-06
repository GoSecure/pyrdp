from PyQt4.QtCore import pyqtSignal, Qt
from PyQt4.QtGui import QHBoxLayout, QLabel, QSizePolicy, QSlider, QSpacerItem, QVBoxLayout, QWidget

from pyrdp.core.helper_methods import getLoggerPassFilters
from pyrdp.layer import PlayerMessageLayer, TPKTLayer
from pyrdp.logging.log import LOGGER_NAMES
from pyrdp.player.BasePlayerWindow import BasePlayerWindow
from pyrdp.player.ClickableProgressBar import ClickableProgressBar
from pyrdp.player.RDPConnectionTab import RDPConnectionTab
from pyrdp.player.ReplayThread import ReplayThread
from pyrdp.ui.event import RSSEventHandler
from pyrdp.ui.PlayPauseButton import PlayPauseButton
from pyrdp.ui.qt4 import QRemoteDesktop
from pyrdp.ui.rss import RSSAdaptor


class ReplayWindow(BasePlayerWindow):
    """
    Class for managing replay tabs.
    """

    def __init__(self):
        BasePlayerWindow.__init__(self)

    def openFile(self, fileName: str):
        """
        Open a replay file and open a new tab.
        :param fileName: replay path.
        """
        tab = ReplayTab(fileName)
        self.addTab(tab, fileName)
        self.log.debug("Loading replay file {}".format(fileName))


class ReplayTab(RDPConnectionTab):
    """
    Tab that displays a RDP Connection that is being replayed from a file.
    """

    def __init__(self, fileName: str):
        """
        :param fileName: name of the file to read.
        """
        self.viewer = QRemoteDesktop(800, 600, RSSAdaptor())
        RDPConnectionTab.__init__(self, self.viewer)

        self.fileName = fileName
        self.file = open(self.fileName, "rb")
        self.eventHandler = RSSEventHandler(self.widget, self.text)
        self.thread = ReplayThread(self.file)
        self.thread.eventReached.connect(self.readEvent)
        self.thread.timeUpdated.connect(self.onTimeUpdated)
        self.thread.clearNeeded.connect(self.clear)
        self.thread.start()

        self.controlBar = ControlBar(self.thread.getDuration())
        self.controlBar.play.connect(self.thread.play)
        self.controlBar.pause.connect(self.thread.pause)
        self.controlBar.seek.connect(self.thread.seek)
        self.controlBar.speedChanged.connect(self.thread.setSpeed)

        self.layout().insertWidget(0, self.controlBar)

        self.tpkt = TPKTLayer()
        self.message = PlayerMessageLayer()

        self.tpkt.setNext(self.message)
        self.message.addObserver(self.eventHandler)

    def readEvent(self, position: int):
        """
        Read an event from the file at the given position.
        :param position: the position of the event in the file.
        """
        self.file.seek(position)

        data = self.file.read(4)
        self.tpkt.recv(data)

        length = self.tpkt.getDataLengthRequired()
        data = self.file.read(length)
        self.tpkt.recv(data)

    def onTimeUpdated(self, currentTime: float):
        """
        Called everytime the thread ticks.
        :param currentTime: the current time.
        """
        self.controlBar.timeSlider.blockSignals(True)
        self.controlBar.timeSlider.setValue(int(currentTime * 1000))
        self.controlBar.timeSlider.blockSignals(False)

    def clear(self):
        """
        Clear the UI.
        """
        self.viewer.clear()
        self.text.setText("")

    def onClose(self):
        self.thread.close()


class ControlBar(QWidget):
    """
    Widget that contains the play/pause button, the progress bar and the speed slider.
    """
    play = pyqtSignal(name="Play")
    pause = pyqtSignal(name="Pause")
    seek = pyqtSignal(float, name="Time changed")
    speedChanged = pyqtSignal(int, name="Speed changed")

    def __init__(self, duration: float, parent: QWidget = None):
        QWidget.__init__(self, parent)

        self.log = getLoggerPassFilters(LOGGER_NAMES.LIVEPLAYER)

        self.button = PlayPauseButton()
        self.button.setMaximumWidth(100)
        self.button.clicked.connect(self.onButtonClicked)

        self.timeSlider = ClickableProgressBar()
        self.timeSlider.setMinimum(0)
        self.timeSlider.setMaximum(int(duration * 1000))
        self.timeSlider.valueChanged.connect(self.onSeek)

        self.speedLabel = QLabel("Speed: 1x")

        self.speedSlider = QSlider(Qt.Horizontal)
        self.speedSlider.setMaximumWidth(300)
        self.speedSlider.setMinimum(1)
        self.speedSlider.setMaximum(10)
        self.speedSlider.valueChanged.connect(self.onSpeedChanged)

        vertical = QVBoxLayout()

        horizontal = QHBoxLayout()
        horizontal.addWidget(self.speedLabel)
        horizontal.addWidget(self.speedSlider)
        horizontal.addItem(QSpacerItem(20, 40, QSizePolicy.Expanding, QSizePolicy.Expanding))
        vertical.addLayout(horizontal)

        horizontal = QHBoxLayout()
        horizontal.addWidget(self.button)
        horizontal.addWidget(self.timeSlider)
        vertical.addLayout(horizontal)

        self.setLayout(vertical)
        self.setGeometry(0, 0, 80, 60)

    def onButtonClicked(self):
        if self.button.playing:
            self.log.debug("Play clicked")
            self.play.emit()
        else:
            self.log.debug("Pause clicked")
            self.pause.emit()

    def onSeek(self):
        time = self.timeSlider.value() / 1000.0
        self.log.debug("Seek to {} seconds".format(time))
        self.seek.emit(time)

    def onSpeedChanged(self):
        speed = self.speedSlider.value()
        self.log.debug("Slider changed value: {}".format(speed))
        self.speedLabel.setText("Speed: {}x".format(speed))
        self.speedChanged.emit(speed)