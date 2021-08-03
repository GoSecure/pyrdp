#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import time

from pyrdp.core import ObservedBy
from pyrdp.enum import PlayerPDUType
from pyrdp.layer import BufferedLayer, LayerRoutedObserver
from pyrdp.parser import PlayerParser
from pyrdp.pdu import PlayerPDU

class PlayerLayer(BufferedLayer):
    """
    Layer to manage the encapsulation of Player metadata such as event timestamp and
    event type/origin (input, output).
    """

    def __init__(self, parser: PlayerParser = PlayerParser()):
        super().__init__(parser)

    def sendMessage(self, data: bytes, messageType: PlayerPDUType, timeStamp: int):
        pdu = PlayerPDU(messageType, timeStamp, data)
        self.sendPDU(pdu)

    @staticmethod
    def timeStampFunction() -> int:
        return int(time.time() * 1000)

    def getCurrentTimeStamp(self) -> int:
        return PlayerLayer.timeStampFunction()