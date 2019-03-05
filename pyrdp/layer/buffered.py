#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from pyrdp.layer.layer import IntermediateLayer
from pyrdp.parser import SegmentationParser
from pyrdp.pdu import PDU


class BufferedLayer(IntermediateLayer):
    """
    Base class for Layers that can receive PDUs spread across multiple calls to recv.
    """

    def __init__(self, parser: SegmentationParser):
        super().__init__(parser)
        self.buffer = b""

    def getDataLengthRequired(self) -> int:
        """
        Get the minimum amount that must be read next.
        This does not have to be the actual size of the PDU: if you return 1 twice in a row, you will read 1 byte twice
        in a row.
        This should always return 0 if the buffer is empty.
        """
        if self.buffer == b"":
            return 0

        try:
            pduLength = self.mainParser.getPDULength(self.buffer)
        except ValueError:
            return 1

        return pduLength - len(self.buffer)

    def recv(self, data: bytes):
        """
        Buffer data until we have a complete PDU, then parse the PDU and process it.
        :param data: received bytes.
        """
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
                self.pduReceived(pdu)

    def shouldForward(self, pdu: PDU) -> bool:
        return True
