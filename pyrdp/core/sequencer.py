#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
from abc import ABCMeta, abstractmethod
from typing import Callable, List, Optional

from pyrdp.core.defer import defer


class Sequencer(metaclass = ABCMeta):
    """
    Class used for spreading function calls across time.
    """

    def __init__(self, functions: List[Callable[[], Optional[int]]]):
        """
        :param functions: list of functions to be called, each one optionally returning an amount of time to wait for.
        """
        self.functions = functions

    def run(self):
        """
        Run all remaining functions.
        """

        while len(self.functions) > 0:
            wait = self.functions.pop(0)()

            if wait is not None and wait > 0:
                self.wait(wait)

    @abstractmethod
    def wait(self, waitTime: int):
        """
        Call self.run after waitTime milliseconds.
        :param waitTime: milliseconds to wait for.
        """
        pass


class AsyncIOSequencer(Sequencer):
    """
    Sequencer that uses asyncio.sleep to wait between calls.
    """

    def wait(self, waitTime: int):
        async def waitFunction():
            await asyncio.sleep(waitTime / 1000.0)
            self.run()

        defer(waitFunction())