import logging

from PyQt4.QtCore import QTimer

from rdpy.core.observer import Observer
from rdpy.core.rss import RssAdaptor
from rdpy.core.subject import Subject, ObservedBy
from rdpy.layer.recording import RDPPlayerMessageLayer
from rdpy.layer.tpkt import TPKTLayer
from rdpy.player.BasePlayerWindow import BasePlayerWindow
from rdpy.player.RDPConnectionTab import RDPConnectionTab
from rdpy.ui.event import RSSEventHandler
from rdpy.ui.qt4 import QRemoteDesktop


class ReplayWindow(BasePlayerWindow):
    """
    Class for managing replay tabs.
    """

    def __init__(self):
        BasePlayerWindow.__init__(self)

    def openFile(self, fileName):
        tab = ReplayTab(fileName)
        self.addTab(tab, fileName)
        self.log.debug("Loading replay file {}".format(fileName))

    def onPlay(self):
        self.log.debug("Start replay file")
        self.currentWidget().start()

    def onStop(self):
        self.log.debug("Stop replay file")
        self.currentWidget().stop()

    def onRestart(self):
        self.log.debug("Rewind replay file")
        self.currentWidget().restart()

    def onSpeedChanged(self, newSpeed):
        self.log.debug("Change replay speed to {}".format(newSpeed))
        self.currentWidget().setSpeedMultiplier(newSpeed)



class RSSTimedEventHandlerObserver(Observer):
    def onEventHandled(self):
        pass

@ObservedBy(RSSTimedEventHandlerObserver)
class RSSTimedEventHandler(RSSEventHandler, Subject):
    def __init__(self, viewer, text):
        RSSEventHandler.__init__(self, viewer, text)
        Subject.__init__(self)
        self.lastTimestamp = None
        self.speedMultiplier = 1
        self.timer = None

    def setSpeedMultiplier(self, speed):
        self.speedMultiplier = speed

    def onPDUReceived(self, pdu):
        logging.getLogger("liveplayer").debug(pdu.timestamp)
        if self.lastTimestamp is None:
            self.dispatchPDU(pdu)
        else:
            interval = (pdu.timestamp - self.lastTimestamp) / self.speedMultiplier

            self.timer = QTimer()
            self.timer.timeout.connect(lambda: self.dispatchPDU(pdu))
            self.timer.setSingleShot(True)
            self.timer.start(interval)

    def dispatchPDU(self, pdu):
        self.timer = None
        self.lastTimestamp = pdu.timestamp
        RSSEventHandler.onPDUReceived(self, pdu)
        self.observer.onEventHandled()

    def start(self):
        if self.timer and not self.timer.isActive():
            self.timer.start()

    def stop(self):
        if self.timer:
            self.timer.stop()

    def restart(self):
        if self.timer:
            self.timer.stop()
            self.timer = None
            self.lastTimestamp = None

    def hasQueuedEvent(self):
        return self.timer is not None



class ReplayTab(RDPConnectionTab):
    """
    Tab that displays a RDP Connection that is being replayed from a file.
    """

    def __init__(self, fileName):
        """
        :type reader: rdpy.core.rss.FileReader
        """
        self.viewer = QRemoteDesktop(800, 600, RssAdaptor())
        RDPConnectionTab.__init__(self, self.viewer)
        self.fileName = fileName
        self.file = open(self.fileName, "rb")
        self.eventHandler = RSSTimedEventHandler(self.widget, self.text)
        self.eventHandler.createObserver(onEventHandled=self.readEvent)

        self.tpkt = TPKTLayer()
        self.message = RDPPlayerMessageLayer()

        self.tpkt.setNext(self.message)
        self.message.addObserver(self.eventHandler)

    def readEvent(self):
        data = self.file.read(4)
        self.tpkt.recv(data)

        length = self.tpkt.getDataLengthRequired()
        data = self.file.read(length)
        self.tpkt.recv(data)

    def start(self):
        """
        Start the RDP Connection replay
        """
        if self.eventHandler.hasQueuedEvent():
            self.eventHandler.start()
        else:
            self.readEvent()

    def stop(self):
        """
        Sets a flag to stop the replay on the next event.
        """
        self.eventHandler.stop()

    def restart(self):
        """
        Resets the replay to start it over.
        """
        self.log.debug("Resetting current replay {}".format(self))
        self.eventHandler.restart()
        self.viewer.clear()
        self.text.setText("")
        self.file.seek(0)

    def onConnectionClosed(self):
        self.text.append("<Connection closed>")
        self.log.debug("Replay file ended, replay done.")

    def setSpeedMultiplier(self, speed):
        self.eventHandler.setSpeedMultiplier(speed)

    def onClose(self):
        pass
