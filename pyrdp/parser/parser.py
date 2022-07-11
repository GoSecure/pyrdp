#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from io import BytesIO

from pyrdp.core import FilePositionGuard
from pyrdp.exceptions import ParsingError
from pyrdp.pdu import PDU


class BaseParser:
    def parse(self, data):
        """
        Decode a PDU from data.
        :param data: PDU data.
        :return: an instance of a PDU class.
        """

        try:
            return self.doParse(data)
        except ParsingError as e:
            self.handleParsingError(e, data)
            raise

    def doParse(self, data) -> PDU:
        raise NotImplementedError("Parse is not implemented")

    def handleParsingError(self, e: ParsingError, data):
        """
        Add self and data to the list of layers of the parsing error.
        """
        raise NotImplementedError("handleParsingError is not implemented")

    def write(self, pdu: PDU) -> bytes:
        """
        Encode a PDU to bytes.
        :param pdu: instance of a PDU class.
        """
        raise NotImplementedError("Write is not implemented")


class Parser(BaseParser):
    # For type hints
    def parse(self, data: bytes):
        return super().parse(data)

    def doParse(self, data: bytes) -> PDU:
        return super().doParse(data)

    def handleParsingError(self, e: ParsingError, data: bytes):
        e.addLayer(self, data)


class StreamParser(BaseParser):
    # For type hints
    def parse(self, stream: BytesIO):
        return super().parse(stream)

    def doParse(self, stream: BytesIO) -> PDU:
        return super().doParse(stream)

    def handleParsingError(self, e: ParsingError, stream: BytesIO):
        with FilePositionGuard(stream):
            e.addLayer(self, stream.read())
