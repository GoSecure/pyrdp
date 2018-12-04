import time
from typing import Callable


class Timer:
    """
    Simple timer class for counting elapsed time. The timer needs to be manually updated before calling getElapsedTime.
    """

    def __init__(self, timeFunc: Callable[[], float] = time.time):
        """
        :param timeFunc: the function to be used for getting the current time. Default: time.time
        """
        self.previousTime: float = None
        self.savedTime = 0.0
        self.timeFunc = timeFunc
        self.speed = 1.0

    def getElapsedTime(self) -> float:
        """
        Get the elapsed time.
        """
        return self.savedTime

    def update(self):
        """
        Update the timer. Does nothing if the timer is not running.
        """
        if self.previousTime is not None:
            currentTime = self.timeFunc()
            self.savedTime += self.speed * (currentTime - self.previousTime)
            self.previousTime = currentTime

    def start(self):
        """
        Start or resume the timer.
        """
        self.previousTime = self.timeFunc()

    def stop(self):
        """
        Stop the timer. It can still be resumed by calling start.
        """
        self.previousTime = None

    def reset(self, start = False):
        """
        Reset the timer and, if start is True, start it again.
        :param start: True if the timer should be started after resetting. Default: False
        """
        self.previousTime = None
        self.savedTime = 0.0

        if start:
            self.start()

    def setTime(self, currentTime: float):
        """
        Set the current time on the timer.
        :param currentTime: the elapsed time.
        """
        self.savedTime = currentTime

        if self.previousTime is not None:
            self.previousTime = self.timeFunc()

    def setSpeed(self, speed: float):
        """
        Set the speed of the timer.
        :param speed: speed of the timer (time multiplier).
        """
        if speed == 0.0:
            raise ValueError("Timer speed cannot be 0")

        self.speed = speed

    def isRunning(self) -> bool:
        """
        Returns True if the timer is currently running.
        """
        return self.previousTime is not None