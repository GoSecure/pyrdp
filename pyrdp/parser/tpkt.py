#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import Uint16BE, Uint8
from pyrdp.exceptions import ParsingError
from pyrdp.parser.segmentation import SegmentationParser
from pyrdp.pdu import TPKTPDU


class TPKTParser(SegmentationParser):
    """
    Parser for TPKT traffic to read and write TPKT messages
    """
    def isCompletePDU(self, data: bytes) -> bool:
        """
        Check if the PDU is fully contained in data.
        :param data: the data.
        """
        if len(data) < 4:
            return False

        length = self.getPDULength(data)
        return len(data) >= length

    def isTPKTPDU(self, data: bytes) -> bool:
        """
        Check if the PDU in data is a TPKT PDU.
        :param data: the data.
        """
        return Uint8.unpack(data[0]) == 3

    def getPDULength(self, data: bytes) -> int:
        """
        Get the length of the PDU contained in data.
        :param data: the PDU data.
        """
        return Uint16BE.unpack(data[2 : 4])

    def parse(self, data: bytes) -> TPKTPDU:
        """
        Read the byte stream and return a TPKTPDU
        """

        _version = Uint8.unpack(data[0 : 1])
        _padding = Uint8.unpack(data[1 : 2])
        length = Uint16BE.unpack(data[2 : 4])
        payload = data[4 : length]

        if len(payload) != length - 4:
            raise ParsingError("Payload is too short for TPKT length field")

        return TPKTPDU(payload)

    def write(self, pdu: TPKTPDU) -> bytes:
        """
        Encode a TPKTPDU into bytes to send on the network.
        """

        stream = BytesIO()
        stream.write(Uint8.pack(pdu.header))
        stream.write(b"\x00")
        stream.write(Uint16BE.pack(len(pdu.payload) + 4))
        stream.write(pdu.payload)

        return stream.getvalue()
