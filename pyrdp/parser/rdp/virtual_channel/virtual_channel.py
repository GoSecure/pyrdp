#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2019, 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO
from typing import List

from pyrdp.core import Uint32LE
from pyrdp.enum import VirtualChannelPDUFlag
from pyrdp.parser.parser import Parser
from pyrdp.pdu import VirtualChannelPDU


class VirtualChannelParser(Parser):
    """
    Parser class for VirtualChannel PDUs.
    """

    MAX_CHUNK_SIZE = 1600  # https://msdn.microsoft.com/en-us/library/cc240548.aspx

    def doParse(self, data: bytes) -> VirtualChannelPDU:
        stream = BytesIO(data)
        length = Uint32LE.unpack(stream)
        flags = Uint32LE.unpack(stream)
        payload = stream.read(length)
        return VirtualChannelPDU(flags, payload)

    def write(self, pdu: VirtualChannelPDU) -> List[bytes]:
        rawPacketList = []
        payloadStream = BytesIO(pdu.payload)
        lengthRemaining = len(pdu.payload)

        while lengthRemaining > 0:
            chunkSize = min(lengthRemaining, self.MAX_CHUNK_SIZE)
            chunk = payloadStream.read(chunkSize)
            flags = pdu.flags & ~(VirtualChannelPDUFlag.CHANNEL_FLAG_FIRST | VirtualChannelPDUFlag.CHANNEL_FLAG_LAST)

            if len(rawPacketList) == 0:
                # Means it's the first packet.
                flags |= VirtualChannelPDUFlag.CHANNEL_FLAG_FIRST

            if lengthRemaining <= self.MAX_CHUNK_SIZE:
                # Means it's the last packet.
                flags |= VirtualChannelPDUFlag.CHANNEL_FLAG_LAST

            outputStream = BytesIO()
            Uint32LE.pack(len(pdu.payload), outputStream)
            Uint32LE.pack(flags, outputStream)
            outputStream.write(chunk)

            rawPacketList.append(outputStream.getvalue())
            lengthRemaining -= chunkSize

        return rawPacketList
