from rdpy.core import log
from rdpy.core.layer import Layer
from rdpy.enum.core import ParserMode
from rdpy.enum.rdp import RDPPlayerMessageType
from rdpy.layer.recording import RDPPlayerMessageTypeLayer
from rdpy.layer.tpkt import TPKTLayer
from rdpy.parser.parser import Parser
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.data import RDPDataParser
from rdpy.parser.rdp.fastpath import RDPBasicFastPathParser
from rdpy.parser.rdp.virtual_channel.clipboard import ClipboardParser


class Recorder:
    """
    Class that manages recording of RDP events using the provided
    transport layers. Those transport layers are the ones that will
    receive binary data and handle them as they wish. They perform the actual recording.
    """

    def __init__(self, transportLayers):
        """
        :type transportLayers: list
        """
        self.parsers = {
            RDPPlayerMessageType.INPUT: RDPBasicFastPathParser(ParserMode.CLIENT),
            RDPPlayerMessageType.OUTPUT: RDPBasicFastPathParser(ParserMode.SERVER),
            RDPPlayerMessageType.CLIENT_INFO: RDPClientInfoParser(),
            RDPPlayerMessageType.CONFIRM_ACTIVE: RDPDataParser(),
            RDPPlayerMessageType.CLIPBOARD_DATA: ClipboardParser(),
        }

        self.topLayers = []

        for transportLayer in transportLayers:
            tpktLayer = TPKTLayer()
            messageLayer = RDPPlayerMessageTypeLayer()

            transportLayer.setNext(tpktLayer)
            tpktLayer.setNext(messageLayer)
            self.topLayers.append(messageLayer)

    def setParser(self, messageType, parser):
        """
        Set the parser to use for a given message type.
        :type messageType: rdpy.enum.rdp.RDPPlayerMessageType
        :type parser: Parser
        """
        self.parsers[messageType] = parser

    def record(self, pdu, messageType):
        """
        Encapsulate the pdu properly, then record the data
        :type pdu: rdpy.pdu.base_pdu.PDU | None
        :type messageType: rdpy.enum.rdp.RDPPlayerMessageType
        """
        if pdu:
            data = self.parsers[messageType].write(pdu)
        else:
            data = b""

        for layer in self.topLayers:
            layer.sendMessage(data, messageType)


class FileLayer(Layer):
    """
    Layer that saves RDP events to a file for later replay.
    """

    def __init__(self, fileHandle):
        """
        :type fileHandle: BinaryIO
        """
        Layer.__init__(self)
        self.file_descriptor = fileHandle

    def send(self, data):
        """
        Save data to the file.
        :type data: str
        """
        log.debug("writing {} to {}".format(data, self.file_descriptor))
        self.file_descriptor.write(data)


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
        :type data: str
        """
        if self.isConnected:
            try:
                log.debug("sending {} to {}".format(data, self.socket.getpeername()))
                self.socket.send(data)
            except Exception as e:
                log.error("Cant send data over the network socket: {}".format(e.message))
                self.isConnected = False
