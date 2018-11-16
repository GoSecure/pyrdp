from rdpy.core.newlayer import Layer, LayerObserver
from rdpy.core.packing import Uint8
from rdpy.core.subject import ObservedBy
from rdpy.enum.segmentation import SegmentationPDUType
from rdpy.parser.segmentation import SegmentationParser
from rdpy.parser.tpkt import TPKTParser
from rdpy.pdu.segmentation import TPKTPDU


class SegmentationObserver(LayerObserver):
    """
    Observer class for the segmentation layer.
    """

    def onUnknownHeader(self, header):
        pass

@ObservedBy(SegmentationObserver)
class SegmentationLayer(Layer):
    """
    Layer to handle segmentation PDUs (e.g: TPKT and fast-path).
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
        Since there can be more than one TPKT message per TCP packet, parse
        a TPKT message, handle the packet then check if we have more messages left.
        :param data: The TCP packet's payload
        :type data: str
        """
        data = self.buffer + data

        while len(data) > 0:
            header = Uint8.unpack(data[0]) & 0b00000011

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
        :param pdu: the pdu.
        :type pdu: TPKTPDU
        :return:
        """
        type = pdu.getType()
        parser = self.parsers[type]
        data = parser.write(pdu)
        self.previous.send(data)

class TPKTLayer(SegmentationLayer):
    def __init__(self):
        SegmentationLayer.__init__(self)
        self.setParser(SegmentationPDUType.TPKT, TPKTParser())

    def pduReceived(self, pdu, forward):
        SegmentationLayer.pduReceived(self, pdu, pdu.getType() & SegmentationPDUType.TPKT)

    def send(self, data):
        self.sendPDU(TPKTPDU(data))

class TPKTProxyLayer(Layer):
    def __init__(self, segmentation):
        """
        :type segmentation: SegmentationLayer
        """
        Layer.__init__(self)
        self.segmentation = segmentation
        self.parser = TPKTParser()

    def recv(self, data):
        raise NotImplementedError("recv is not supported for TPKTProxyLayer")

    def send(self, data):
        self.segmentation.sendPDU(TPKTPDU(data))