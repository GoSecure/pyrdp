#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import List, Callable, Optional

from PySide2.QtCore import QTimer


class Sequencer:
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
                QTimer.singleShot(wait, self.run)