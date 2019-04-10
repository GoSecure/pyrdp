#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import time

from pyrdp.core import ObservedBy
from pyrdp.enum import PlayerPDUType
from pyrdp.layer import BufferedLayer, LayerRoutedObserver
from pyrdp.parser import PlayerParser
from pyrdp.pdu import PlayerPDU


class PlayerObserver(LayerRoutedObserver):
    def __init__(self, **kwargs):
        LayerRoutedObserver.__init__(self, {
            PlayerPDUType.CONNECTION_CLOSE: "onConnectionClose",
            PlayerPDUType.CLIENT_INFO: "onClientInfo",
            PlayerPDUType.SLOW_PATH_PDU: "onSlowPathPDU",
            PlayerPDUType.FAST_PATH_INPUT: "onInput",
            PlayerPDUType.FAST_PATH_OUTPUT: "onOutput",
            PlayerPDUType.CLIPBOARD_DATA: "onClipboardData",
            PlayerPDUType.CLIENT_DATA: "onClientData"
        }, **kwargs)

    def onConnectionClose(self, pdu: PlayerPDU):
        raise NotImplementedError()

    def onClientInfo(self, pdu: PlayerPDU):
        raise NotImplementedError()

    def onSlowPathPDU(self, pdu: PlayerPDU):
        raise NotImplementedError()

    def onInput(self, pdu: PlayerPDU):
        raise NotImplementedError()

    def onOutput(self, pdu: PlayerPDU):
        raise NotImplementedError()

    def onClipboardData(self, pdu: PlayerPDU):
        raise NotImplementedError()

    def onClientData(self, pdu: PlayerPDU):
        raise NotImplementedError()


@ObservedBy(PlayerObserver)
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

    def getCurrentTimeStamp(self) -> int:
        return int(time.time() * 1000)