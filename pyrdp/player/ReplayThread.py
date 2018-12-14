import os
import queue
from collections import defaultdict
from enum import IntEnum
from multiprocessing import Queue
from time import sleep
from typing import BinaryIO

from PyQt4.QtCore import pyqtSignal, QThread

from pyrdp.core import Timer
from pyrdp.layer import PlayerMessageLayer, TPKTLayer
from pyrdp.pdu import PlayerMessagePDU


class ReplayThreadEvent(IntEnum):
    """
    Types of messages that can be sent to the replay thread.
    """
    PLAY = 0
    PAUSE = 1
    SEEK = 2
    SPEED = 3
    EXIT = 4


class ReplayThread(QThread):
    """
    Thread that runs in the background for every replay. Constantly checks time to see which events should be played.
    """

    timeUpdated = pyqtSignal(float, name="Time changed")

    # We use the object type instead of int for this signal to prevent Python integers from being converted to 32-bit integers
    eventReached = pyqtSignal(object, name="Event reached")
    clearNeeded = pyqtSignal()

    def __init__(self, file: BinaryIO):
        super().__init__(None)

        self.queue = Queue()
        self.lastSeekTime = 0
        self.requestedSpeed = 1

        events = defaultdict(list)
        startingPosition = file.tell()

        file.seek(0, os.SEEK_END)
        size = file.tell()

        # Take note of the position of each event and its timestamp
        file.seek(0)
        currentMessagePosition = 0

        tpkt = TPKTLayer()
        player = PlayerMessageLayer()
        tpkt.setNext(player)

        def registerEvent(pdu: PlayerMessagePDU):
            events[pdu.timestamp].append(currentMessagePosition)

        player.createObserver(onPDUReceived = registerEvent)

        while file.tell() < size:
            data = file.read(4)
            tpkt.recv(data)

            data = file.read(tpkt.getDataLengthRequired())
            tpkt.recv(data)
            currentMessagePosition = file.tell()

        file.seek(startingPosition)

        # Use relative timestamps to simplify things
        self.events = {}

        if len(events) == 0:
            self.duration = 0
        else:
            timestamps = sorted(events.keys())
            startingTime = timestamps[0]

            for timestamp in timestamps:
                relative = timestamp - startingTime
                self.events[relative] = events[timestamp]

            self.duration = (timestamps[-1] - startingTime) / 1000.0

    def getDuration(self):
        return self.duration

    def run(self):
        step = 16 / 1000
        currentIndex = 0
        runThread = True
        timestamps = sorted(self.events.keys())
        timer = Timer()

        while runThread:
            timer.update()

            try:
                while True:
                    event = self.queue.get_nowait()

                    if event == ReplayThreadEvent.PLAY:
                        timer.start()
                    elif event == ReplayThreadEvent.PAUSE:
                        timer.stop()
                    elif event == ReplayThreadEvent.SEEK:
                        if self.lastSeekTime < timer.getElapsedTime():
                            currentIndex = 0
                            self.clearNeeded.emit()

                        timer.setTime(self.lastSeekTime)
                    elif event == ReplayThreadEvent.SPEED:
                        timer.setSpeed(self.requestedSpeed)
                    elif event == ReplayThreadEvent.EXIT:
                        runThread = False

            except queue.Empty:
                pass

            if timer.isRunning():
                currentTime = timer.getElapsedTime()
                self.timeUpdated.emit(currentTime)

                while currentIndex < len(timestamps) and timestamps[currentIndex] / 1000.0 <= currentTime:
                    positions = self.events[timestamps[currentIndex]]

                    for position in positions:
                        self.eventReached.emit(position)

                    currentIndex += 1

            sleep(step)

    def play(self):
        self.queue.put(ReplayThreadEvent.PLAY)

    def pause(self):
        self.queue.put(ReplayThreadEvent.PAUSE)

    def seek(self, time: float):
        self.lastSeekTime = time
        self.queue.put(ReplayThreadEvent.SEEK)

    def setSpeed(self, speed: float):
        self.requestedSpeed = speed
        self.queue.put(ReplayThreadEvent.SPEED)

    def close(self):
        self.queue.put(ReplayThreadEvent.EXIT)