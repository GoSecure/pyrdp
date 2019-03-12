#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import queue
from enum import IntEnum
from multiprocessing import Queue
from time import sleep

from PySide2.QtCore import Signal, QThread

from pyrdp.core import Timer
from pyrdp.player.Replay import Replay


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

    timeUpdated = Signal(float)

    # We use the object type instead of int for this signal to prevent Python integers from being converted to 32-bit integers
    eventReached = Signal(object)
    clearNeeded = Signal()

    def __init__(self, replay: Replay):
        super().__init__()

        self.queue = Queue()
        self.lastSeekTime = 0
        self.requestedSpeed = 1
        self.replay = replay

    def run(self):
        step = 16 / 1000
        currentIndex = 0
        runThread = True
        timestamps = sorted(self.replay.events.keys())
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
                    nextTimestamp = timestamps[currentIndex]
                    positions = self.replay.events[nextTimestamp]

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