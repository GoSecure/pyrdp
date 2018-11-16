from rdpy.core.newlayer import Layer, LayerObserver
from rdpy.core.packing import Uint8
from rdpy.core.subject import ObservedBy
from rdpy.enum.segmentation import SegmentationPDUType
from rdpy.parser.segmentation import SegmentationParser
from rdpy.pdu.segmentation import SegmentationPDU


class SegmentationObserver(LayerObserver):
    """
    Observer class for the segmentation layer.
    """
    def __init__(self, **kwargs):
        LayerObserver.__init__(self, **kwargs)
        self.handlers = {}

    def onPDUReceived(self, pdu):
        """
        Called when a PDU is received.
        :type pdu: SegmentationPDU
        """
        type = pdu.getSegmentationType()
        if type in self.handlers:
            self.handlers[type](pdu)

    def setHandler(self, type, handler):
        """
        Add a handler for a given PDU type.
        :param type: the PDU type.
        :type type: int
        :param handler: callable object
        """
        self.handlers[type] = handler

    def onUnknownHeader(self, header):
        pass



@ObservedBy(SegmentationObserver)
class SegmentationLayer(Layer):
    """
    Layer to handle segmentation PDUs (e.g: TPKT and fast-path).
    Handles buffering data until there is enough to parse a full PDU.
    PDUs are not forwarded. Use the observer to receive the individual PDUs for each type.
    """

    def __init__(self):
        Layer.__init__(self)
        self.buffer = ""
        self.fastPathLayer = None
        self.parsers = {}

    def setParser(self, type, parser):
        """
        Set the parser used for a given PDU type.
        :type type: int
        :type parser: SegmentationParser
        """
        self.parsers[type] = parser

    def recv(self, data):
        """
        All the data received is buffered until there is enough to parse a complete PDU.
        :type data: str
        """
        data = self.buffer + data

        while len(data) > 0:
            header = Uint8.unpack(data[0]) & SegmentationPDUType.MASK

            try:
                parser = self.parsers[header]
            except KeyError:
                if self.observer:
                    self.observer.onUnknownHeader(header)
                    return
                else:
                    raise

            if not parser.isCompletePDU(data):
                self.buffer = data
                data = ""
            else:
                pduLength = parser.getPDULength(data)
                pduData = data[: pduLength]

                pdu = parser.parse(pduData)
                self.pduReceived(pdu, False)

                data = data[pduLength :]
                self.buffer = ""

    def recvWithSocket(self, socket):
        """
        Same as recv, but using a socket.
        :type socket: socket.socket
        """
        data = socket.recv(1)
        header = Uint8.unpack(data) & 0b00000011
        parser = self.parsers[header]
        data2, pduLength = parser.getPDULengthWithSocket(socket)
        data += data2
        pduData = data + socket.recv(pduLength - 4)

        pdu = parser.parse(pduData)
        self.pduReceived(pdu, header == 3)

    def sendPDU(self, pdu):
        """
        Send a PDU for one of the registered classes.
        :type pdu: SegmentationPDU
        """
        type = pdu.getSegmentationType()
        parser = self.parsers[type]
        data = parser.write(pdu)
        self.previous.send(data)
