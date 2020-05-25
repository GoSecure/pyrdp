#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import Uint16LE, Uint32LE
from pyrdp.enum import ClipboardMessageFlags, ClipboardMessageType
from pyrdp.parser.parser import Parser
from pyrdp.pdu import ClipboardPDU, FormatDataRequestPDU, FormatDataResponsePDU, FormatListPDU, LongFormatName, ClipboardFormatName


class ClipboardParser(Parser):
    """
    Parser class for clipboard PDUs
    """

    def __init__(self):
        self.formats = {}  # Supported Clipboard Formats
        self.req = None  # Active Request

    def parse(self, data):
        stream = BytesIO(data)
        msgType = Uint16LE.unpack(stream)
        msgFlags = Uint16LE.unpack(stream)
        dataLen = Uint32LE.unpack(stream)
        payload = stream.read(dataLen)

        if msgType == ClipboardMessageType.CB_FORMAT_DATA_REQUEST:
            clipboardPDU = self.parseFormatDataRequest(payload, msgFlags)
            self.req = clipboardPDU
        elif msgType == ClipboardMessageType.CB_FORMAT_DATA_RESPONSE:
            clipboardPDU = self.parseFormatDataResponse(payload, msgFlags)
            self.req = None
        elif msgType == ClipboardMessageType.CB_FORMAT_LIST:
            clipboardPDU = self.parseFormatList(payload, msgFlags)
        # elif msgType == ClipboardMessageType.CB_FILECONTENTS_REQUEST:
        #     clipboardPDU = self.parseFileContentsRequest(payload, msgFlags)
        # elif msgType == ClipboardMessageType.CB_FILECONTENTS_RESPONSE:
        #     clipboardPDU = self.parseFileContentsResponse(payload, msgFlags)
        else:
            clipboardPDU = ClipboardPDU(ClipboardMessageType(msgType), msgFlags, payload)

        return clipboardPDU

    def parseFileContentsRequest(self, payload, msgFlags):
        pass

    def parseFileContentsResponse(self, payload, msgFlags):
        pass

    def parseFormatDataRequest(self, payload, msgFlags):
        s = BytesIO(payload)
        return FormatDataRequestPDU(Uint32LE.unpack(s))

    def parseFormatDataResponse(self, payload, msgFlags):
        isSuccessful = True if msgFlags & ClipboardMessageFlags.CB_RESPONSE_OK else False
        fid = self.req.requestedFormatId
        if isSuccessful and fid in self.formats:
            fmt = str(self.formats[fid])
            if fmt == ClipboardFormatName.FILE_LIST:
                # TODO: Parse file list.
                stream = BytesIO(payload)

        return FormatDataResponsePDU(payload, isSuccessful)

    def parseFormatList(self, payload, msgFlags):
        # Assumes LongFormatNames. This might be bad. Should check capabilities beforehand

        stream = BytesIO(payload)
        formats = {}

        while stream.tell() < len(stream.getvalue()):
            formatId = Uint32LE.unpack(stream)
            formatName = b""
            lastChar = b""

            while lastChar != b"\x00\x00":
                lastChar = stream.read(2)
                formatName += lastChar

            formats[formatId] = LongFormatName(formatId, formatName)

        return FormatListPDU(formats, msgFlags)

    def write(self, pdu):
        """
        :type pdu: ClipboardPDU
        :return: str
        """

        stream = BytesIO()
        Uint16LE.pack(pdu.msgType, stream)
        Uint16LE.pack(pdu.msgFlags, stream)
        if isinstance(pdu, FormatDataResponsePDU):
            self.writeFormatDataResponse(stream, pdu)
        elif isinstance(pdu, FormatDataRequestPDU):
            self.writeFormatDataRequest(stream, pdu)
        elif isinstance(pdu, FormatListPDU):
            self.writeFormatList(stream, pdu)
        else:
            Uint32LE.pack(len(pdu.payload), stream)
            stream.write(pdu.payload)
        return stream.getvalue()

    def writeFormatDataResponse(self, stream, pdu):
        """
        Write the FormatDataResponsePDU starting at dataLen.
        :type stream: BytesIO
        :type pdu: FormatDataResponsePDU
        """
        Uint32LE.pack(len(pdu.requestedFormatData), stream)
        stream.write(pdu.requestedFormatData)

    def writeFormatList(self, stream, pdu):
        """
        Write the FormatListPDU starting at dataLen. Assumes LongFormatNames
        :type stream: BytesIO
        :type pdu: FormatListPDU
        """
        substream = BytesIO()

        for format in pdu.formatList.values():
            Uint32LE.pack(format.formatId, substream)
            formatName = format.formatName
            lastChar = b""
            pos = 0

            while lastChar != b"\x00\x00":
                lastChar = formatName[pos:pos + 2]
                substream.write(lastChar)
                pos += 2

        Uint32LE.pack(len(substream.getvalue()), stream)
        stream.write(substream.getvalue())

    def writeFormatDataRequest(self, stream, pdu):
        """
        Write the FormatDataRequestPDU starting at dataLen. Assumes LongFormatNames.
        :type stream: BytesIO
        :type pdu: FormatDataRequestPDU
        """
        Uint32LE.pack(4, stream)  # datalen
        Uint32LE.pack(pdu.requestedFormatId, stream)
