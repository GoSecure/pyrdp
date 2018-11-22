from rdpy.core.layer import Layer
from rdpy.parser.segmentation import SegmentationParser


class BufferedLayer(Layer):
    def __init__(self, parser):
        """
        :type parser: SegmentationParser
        """
        Layer.__init__(self)
        self.parser = parser
        self.buffer = b""

    def getDataLengthRequired(self):
        """
        Get the minimum amount that must be read next.
        This does not have to be the actual size of the PDU: if you return 1 twice in a row, you will read 1 byte twice
        in a row.
        This should always return 0 if the buffer is empty.
        :return: int
        """
        if self.buffer == b"":
            return 0

        try:
            pduLength = self.parser.getPDULength(self.buffer)
        except ValueError:
            return 1

        return pduLength - len(self.buffer)

    def recv(self, data):
        data = self.buffer + data

        while len(data) > 0:
            if not self.parser.isCompletePDU(data):
                self.buffer = data
                data = b""
            else:
                pduLength = self.parser.getPDULength(data)
                pduData = data[: pduLength]

                pdu = self.parser.parse(pduData)
                self.pduReceived(pdu, True)
                data = data[pduLength :]
                self.buffer = b""

    def sendPDU(self, pdu):
        data = self.parser.write(pdu)
        self.previous.send(data)

    def sendData(self, data):
        self.previous.send(data)

    def send(self, data):
        raise NotImplementedError("send must be overridden")