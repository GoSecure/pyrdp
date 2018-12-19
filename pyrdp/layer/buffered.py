#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.layer.layer import Layer
from pyrdp.parser import SegmentationParser


class BufferedLayer(Layer):
    """
    Abstract class for layers which might need reassembly.
    """

    def __init__(self, parser: SegmentationParser):
        Layer.__init__(self, parser, hasNext=True)
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
            pduLength = self.mainParser.getPDULength(self.buffer)
        except ValueError:
            return 1

        return pduLength - len(self.buffer)

    def recv(self, data):
        data = self.buffer + data

        while len(data) > 0:
            if not self.mainParser.isCompletePDU(data):
                self.buffer = data
                data = b""
            else:
                pduLength = self.mainParser.getPDULength(data)
                pduData = data[: pduLength]
                data = data[pduLength :]
                self.buffer = b""

                pdu = self.mainParser.parse(pduData)
                self.pduReceived(pdu, self.hasNext)

    def sendPDU(self, pdu):
        data = self.mainParser.write(pdu)
        self.previous.send(data)

    def sendData(self, data):
        self.previous.send(data)

    def send(self, data):
        raise NotImplementedError("send must be overridden")
