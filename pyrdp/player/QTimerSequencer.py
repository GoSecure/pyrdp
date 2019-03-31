#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from PySide2.QtCore import QTimer

from pyrdp.core import Sequencer


class QTimerSequencer(Sequencer):
    """
    Sequencer that uses QTimer to wait between calls.
    """

    def wait(self, waitTime: int):
        QTimer.singleShot(waitTime, self.run)