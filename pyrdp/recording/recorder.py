#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pathlib import Path
from typing import Dict, List, Optional, Union

from pyrdp.enum import ParserMode, PlayerPDUType
from pyrdp.layer import LayerChainItem, PlayerLayer
from pyrdp.logging import log
from pyrdp.parser import BasicFastPathParser, ClientConnectionParser, ClientInfoParser, ClipboardParser, Parser, \
    SlowPathParser
from pyrdp.pdu import PDU


class Recorder:
    """
    Class that manages recording of RDP events using the provided
    transport layers. Those transport layers are the ones that will
    receive binary data and handle them as they wish. They perform the actual recording.
    """

    def __init__(self, transports: List[LayerChainItem]):
        self.parsers: Dict[PlayerPDUType, Parser] = {
            PlayerPDUType.FAST_PATH_INPUT: BasicFastPathParser(ParserMode.CLIENT),
            PlayerPDUType.FAST_PATH_OUTPUT: BasicFastPathParser(ParserMode.SERVER),
            PlayerPDUType.CLIENT_INFO: ClientInfoParser(),
            PlayerPDUType.SLOW_PATH_PDU: SlowPathParser(),
            PlayerPDUType.CLIPBOARD_DATA: ClipboardParser(),
            PlayerPDUType.CLIENT_DATA: ClientConnectionParser(),
        }

        self.topLayers = []
        self.recordFilename = None

        for transport in transports:
            self.addTransport(transport)

    def setRecordFilename(self, filename: str):
        """
        Sets the filename used for the session recording.
        :param filename: the filename
        """
        self.recordFilename = filename

    def addTransport(self, transportLayer: LayerChainItem):
        player = PlayerLayer()
        player.setPrevious(transportLayer)
        self.topLayers.append(player)

    def setParser(self, messageType: PlayerPDUType, parser: Parser):
        """
        Set the parser to use for a given message type.
        """
        self.parsers[messageType] = parser


    def record(self, pdu: Optional[PDU], messageType: PlayerPDUType):
        """
        Encapsulate the pdu properly, then record the data
        """
        if messageType not in self.parsers:
            for layer in self.topLayers:
                layer.sendPDU(pdu)

            return

        if pdu:
            data = self.parsers[messageType].write(pdu)
        else:
            data = b""

        timeStamp = self.getCurrentTimeStamp()

        for layer in self.topLayers:
            layer.sendMessage(data, messageType, timeStamp)

    def getCurrentTimeStamp(self) -> int:
        return PlayerLayer().getCurrentTimeStamp()


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