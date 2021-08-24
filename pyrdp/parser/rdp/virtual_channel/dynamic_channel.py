#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import Uint16LE, Uint8
from pyrdp.enum.virtual_channel.dynamic_channel import CbId, DynamicChannelCommand
from pyrdp.parser import Parser
from pyrdp.pdu import PDU
from pyrdp.pdu.rdp.virtual_channel.dynamic_channel import CreateRequestPDU, DataPDU, \
    DynamicChannelPDU


class DynamicChannelParser(Parser):
    """
    Parser for the dynamic channel (drdynvc) packets.
    """

    def __init__(self, isClient):
        super().__init__()
        self.isClient = isClient

        if self.isClient:
            # Parsers and writers unique for client

            self.parsers = {

            }

            self.writers = {
                DynamicChannelCommand.CREATE: self.writeCreateRequest
            }
        else:
            # Parsers and writers unique for server

            self.parsers = {
                DynamicChannelCommand.CREATE: self.parseCreateRequest
            }

            self.writers = {

            }

        # Parsers and writers for both client and server

        self.parsers.update({
            DynamicChannelCommand.DATA: self.parseData
        })

        self.writers.update({
            DynamicChannelCommand.DATA: self.writeData
        })

    def doParse(self, data: bytes) -> PDU:
        stream = BytesIO(data)
        header = Uint8.unpack(stream)
        cbid = (header & 0b00000011)
        sp = (header & 0b00001100) >> 2
        cmd = (header & 0b11110000) >> 4
        pdu = DynamicChannelPDU(cbid, sp, cmd, stream.read())
        if cmd in self.parsers:
            return self.parsers[cmd](pdu)
        else:
            return pdu

    def parseCreateRequest(self, pdu: DynamicChannelPDU) -> CreateRequestPDU:
        """
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc/4448ba4d-9a72-429f-8b65-6f4ec44f2985
        :param pdu: The PDU with the payload to decode.
        """
        stream = BytesIO(pdu.payload)
        channelId = self.readChannelId(stream, pdu.cbid)
        channelName = ""
        char = stream.read(1).decode()
        while char != "\x00":
            channelName += char
            char = stream.read(1).decode()
        return CreateRequestPDU(pdu.cbid, pdu.sp, channelId, channelName)

    def writeCreateRequest(self, pdu: CreateRequestPDU, stream: BytesIO):
        """
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc/4448ba4d-9a72-429f-8b65-6f4ec44f2985
        """
        self.writeChannelId(stream, pdu.cbid, pdu.channelId)
        stream.write(pdu.channelName.encode() + b"\x00")

    def parseData(self, pdu: DynamicChannelPDU) -> DataPDU:
        """
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc/15b59886-db44-47f1-8da3-47c8fcd82803
        """
        stream = BytesIO(pdu.payload)
        channelId = self.readChannelId(stream, pdu.cbid)
        data = stream.read()
        return DataPDU(pdu.cbid, pdu.sp, channelId, payload=data)

    def writeData(self, pdu: DataPDU, stream: BytesIO):
        """
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc/15b59886-db44-47f1-8da3-47c8fcd82803
        """
        self.writeChannelId(stream, pdu.cbid, pdu.channelId)
        stream.write(pdu.payload)

    def write(self, pdu: DynamicChannelPDU) -> bytes:
        stream = BytesIO()
        header = pdu.cbid
        header |= pdu.sp << 2
        header |= pdu.cmd << 4
        Uint8.pack(header, stream)
        if pdu.cmd in self.writers:
            self.writers[pdu.cmd](pdu, stream)
        else:
            stream.write(pdu.payload)

        return stream.getvalue()

    def readChannelId(self, stream: BytesIO, cbid: int):
        if cbid == CbId.ONE_BYTE:
            return Uint8.unpack(stream)
        elif cbid == CbId.TWO_BYTE:
            return Uint16LE.unpack(stream)
        elif cbid == CbId.FOUR_BYTES:
            return Uint16LE.unpack(stream)
        else:
            raise ValueError(f"Invalid channel id length: {cbid}")

    def writeChannelId(self, stream: BytesIO, cbid: int, channelId: int):
        if cbid == CbId.ONE_BYTE:
            return Uint8.pack(channelId, stream)
        elif cbid == CbId.TWO_BYTE:
            return Uint16LE.pack(channelId, stream)
        elif cbid == CbId.FOUR_BYTES:
            return Uint16LE.pack(channelId, stream)
        else:
            raise ValueError(f"Invalid channel id length: {cbid}")
