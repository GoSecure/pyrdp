#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import time
from pathlib import Path
from typing import Dict, List, Optional, Union

from pyrdp.enum import ParserMode, PlayerMessageType
from pyrdp.layer import PlayerMessageLayer, TPKTLayer
from pyrdp.layer.layer import LayerChainItem
from pyrdp.logging import log
from pyrdp.parser import BasicFastPathParser, ClientInfoParser, ClipboardParser, Parser, SlowPathParser
from pyrdp.parser.rdp.connection import ClientConnectionParser
from pyrdp.pdu import PDU


class Recorder:
    """
    Class that manages recording of RDP events using the provided
    transport layers. Those transport layers are the ones that will
    receive binary data and handle them as they wish. They perform the actual recording.
    """

    def __init__(self, transports: List[LayerChainItem]):
        self.parsers: Dict[PlayerMessageType, Parser] = {
            PlayerMessageType.FAST_PATH_INPUT: BasicFastPathParser(ParserMode.CLIENT),
            PlayerMessageType.FAST_PATH_OUTPUT: BasicFastPathParser(ParserMode.SERVER),
            PlayerMessageType.CLIENT_INFO: ClientInfoParser(),
            PlayerMessageType.SLOW_PATH_PDU: SlowPathParser(),
            PlayerMessageType.CLIPBOARD_DATA: ClipboardParser(),
            PlayerMessageType.CLIENT_DATA: ClientConnectionParser(),
        }

        self.topLayers = []

        for transport in transports:
            self.addTransport(transport)

    def addTransport(self, transportLayer: LayerChainItem):
        player = PlayerMessageLayer()

        LayerChainItem.chain(transportLayer, player)
        self.topLayers.append(player)

    def setParser(self, messageType: PlayerMessageType, parser: Parser):
        """
        Set the parser to use for a given message type.
        """
        self.parsers[messageType] = parser


    def record(self, pdu: Optional[PDU], messageType: PlayerMessageType):
        """
        Encapsulate the pdu properly, then record the data
        """
        if pdu:
            data = self.parsers[messageType].write(pdu)
        else:
            data = b""

        timeStamp = int(round(self.getCurrentTimeStamp() * 1000))

        for layer in self.topLayers:
            layer.sendMessage(data, messageType, timeStamp)

    def getCurrentTimeStamp(self) -> float:
        return time.time()


class FileLayer(LayerChainItem):
    """
    Layer that saves RDP events to a file for later replay.
    """

    def __init__(self, fileName: Union[str, Path]):
        super().__init__()
        self.file_descriptor = open(str(fileName), "wb")

    def sendBytes(self, data: bytes):
        """
        Save data to the file.
        :param data: data to write.
        """

        if not self.file_descriptor.closed:
            self.file_descriptor.write(data)
        else:
            log.error("Recording file handle closed, cannot write message: %(message)s", {"message": data})