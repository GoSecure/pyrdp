import time
from typing import BinaryIO, Dict, List, Optional

from pyrdp.enum import ParserMode, PlayerMessageType
from pyrdp.layer import Layer, PlayerMessageLayer, TPKTLayer
from pyrdp.logging import log
from pyrdp.parser import ClipboardParser, Parser, RDPBasicFastPathParser, RDPClientInfoParser, RDPDataParser
from pyrdp.parser.rdp.connection import RDPClientConnectionParser
from pyrdp.pdu import PDU


class Recorder:
    """
    Class that manages recording of RDP events using the provided
    transport layers. Those transport layers are the ones that will
    receive binary data and handle them as they wish. They perform the actual recording.
    """

    def __init__(self, transportLayers: List[Layer]):
        self.parsers: Dict[PlayerMessageType, Parser] = {
            PlayerMessageType.FAST_PATH_INPUT: RDPBasicFastPathParser(ParserMode.CLIENT),
            PlayerMessageType.FAST_PATH_OUTPUT: RDPBasicFastPathParser(ParserMode.SERVER),
            PlayerMessageType.CLIENT_INFO: RDPClientInfoParser(),
            PlayerMessageType.SLOW_PATH_PDU: RDPDataParser(),
            PlayerMessageType.CLIPBOARD_DATA: ClipboardParser(),
            PlayerMessageType.CLIENT_DATA: RDPClientConnectionParser(),
        }

        self.topLayers = []

        for transportLayer in transportLayers:
            tpktLayer = TPKTLayer()
            messageLayer = PlayerMessageLayer()

            transportLayer.setNext(tpktLayer)
            tpktLayer.setNext(messageLayer)
            self.topLayers.append(messageLayer)

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


class FileLayer(Layer):
    """
    Layer that saves RDP events to a file for later replay.
    """

    def __init__(self, fileHandle):
        """
        :type fileHandle: BinaryIO
        """
        Layer.__init__(self)
        self.file_descriptor: BinaryIO = fileHandle

    def send(self, data: bytes):
        """
        Save data to the file.
        """

        if not self.file_descriptor.closed:
            self.file_descriptor.write(data)
        else:
            log.error("Recording file handle closed, cannot write message: %(message)s", {"message": data})


class SocketLayer(Layer):
    """
    Layer that sends RDP events to a network socket for live play.
    """

    def __init__(self, socket):
        """
        :type socket: socket.socket
        """
        Layer.__init__(self)
        self.socket = socket
        self.isConnected = True

    def send(self, data):
        """
        Send data through the socket
        :type data: bytes
        """
        if self.isConnected:
            try:
                log.debug("sending %(arg1)s to %(arg2)s", {"arg1": data, "arg2": self.socket.getpeername()})
                self.socket.send(data)
            except Exception as e:
                log.error("Cant send data over the network socket: %(data)s", {"data": e})
                self.isConnected = False
