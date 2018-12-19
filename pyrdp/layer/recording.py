#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import ObservedBy, Uint64LE, Uint8
from pyrdp.enum import PlayerMessageType
from pyrdp.layer.layer import Layer, LayerRoutedObserver
from pyrdp.pdu import PlayerMessagePDU


class PlayerMessageObserver(LayerRoutedObserver):
    def __init__(self, **kwargs):
        LayerRoutedObserver.__init__(self, {
            PlayerMessageType.CONNECTION_CLOSE: "onConnectionClose",
            PlayerMessageType.CLIENT_INFO: "onClientInfo",
            PlayerMessageType.SLOW_PATH_PDU: "onSlowPathPDU",
            PlayerMessageType.FAST_PATH_INPUT: "onInput",
            PlayerMessageType.FAST_PATH_OUTPUT: "onOutput",
            PlayerMessageType.CLIPBOARD_DATA: "onClipboardData",
            PlayerMessageType.CLIENT_DATA: "onClientData"
        }, **kwargs)

    def onConnectionClose(self, pdu: PlayerMessagePDU):
        raise NotImplementedError()

    def onClientInfo(self, pdu: PlayerMessagePDU):
        raise NotImplementedError()

    def onSlowPathPDU(self, pdu: PlayerMessagePDU):
        raise NotImplementedError()

    def onInput(self, pdu: PlayerMessagePDU):
        raise NotImplementedError()

    def onOutput(self, pdu: PlayerMessagePDU):
        raise NotImplementedError()

    def onClipboardData(self, pdu: PlayerMessagePDU):
        raise NotImplementedError()

    def onClientData(self, pdu: PlayerMessagePDU):
        raise NotImplementedError()


@ObservedBy(PlayerMessageObserver)
class PlayerMessageLayer(Layer):
    """
    Layer to manage the encapsulation of Player metadata such as event timestamp and
    event type/origin (input, output).
    """

    def __init__(self):
        Layer.__init__(self)

    def recv(self, data: bytes):
        """
        Parses data to make a RDPPlayerMessagePDU and calls the observer with it.
        """
        stream = BytesIO(data)
        type = PlayerMessageType(Uint8.unpack(stream))
        timestamp = Uint64LE.unpack(stream)
        payload = stream.read()
        pdu = PlayerMessagePDU(type, timestamp, payload)
        self.pduReceived(pdu, forward=False)

    def sendMessage(self, data: bytes, messageType: PlayerMessageType, timeStamp: int):
        stream = BytesIO()
        Uint8.pack(messageType, stream)
        Uint64LE.pack(timeStamp, stream)
        stream.write(data)
        self.previous.send(stream.getvalue())

