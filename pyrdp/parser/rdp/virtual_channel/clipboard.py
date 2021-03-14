#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import Uint16LE, Uint32LE, Uint64LE
from pyrdp.enum import ClipboardMessageFlags, ClipboardMessageType, ClipboardFormatName, ClipboardFormatNumber
from pyrdp.parser.parser import Parser
from pyrdp.pdu import ClipboardPDU, FormatDataRequestPDU, FormatDataResponsePDU, FormatListPDU, LongFormatName, FileContentsRequestPDU, FileContentsResponsePDU


class ClipboardParser(Parser):
    """
    Parser class for clipboard PDUs
    """

    def __init__(self):
        self.formats = {}  # Supported Clipboard Formats
        self.req = None  # Active Request

        self.dispatch = {
            ClipboardMessageType.CB_FORMAT_DATA_REQUEST: self.parseFormatDataRequest,
            ClipboardMessageType.CB_FORMAT_DATA_RESPONSE: self.parseFormatDataResponse,
            ClipboardMessageType.CB_FORMAT_LIST: self.parseFormatList,
            ClipboardMessageType.CB_FILECONTENTS_REQUEST: self.parseFileContentsRequest,
            ClipboardMessageType.CB_FILECONTENTS_RESPONSE: self.parseFileContentsResponse,
        }

    def doParse(self, data):
        stream = BytesIO(data)
        msgType = Uint16LE.unpack(stream)
        msgFlags = Uint16LE.unpack(stream)
        dataLen = Uint32LE.unpack(stream)
        payload = stream.read(dataLen)

        if msgType in self.dispatch:
            clipboardPDU = self.dispatch[msgType](payload, msgFlags)
        else:
            clipboardPDU = ClipboardPDU(ClipboardMessageType(msgType), msgFlags, payload)

        return clipboardPDU

    def parseFileContentsRequest(self, payload, msgFlags):
        stream = BytesIO(payload)
        streamId = Uint32LE.unpack(stream)
        lindex = Uint32LE.unpack(stream)
        dwFlags =  Uint32LE.unpack(stream)
        posLo = Uint32LE.unpack(stream)
        posHi = Uint32LE.unpack(stream)
        cbRequested = Uint32LE.unpack(stream)
        clipDataId = Uint32LE.unpack(stream)

        pos = posHi << 32 | posLo
        return FileContentsRequestPDU(payload, streamId, lindex, msgFlags, dwFlags, pos, cbRequested, clipDataId)

    def parseFileContentsResponse(self, payload, msgFlags):
        stream = BytesIO(payload)
        streamId = Uint32LE.unpack(stream)
        # FIXME: Need to grab the actual file size from the reply.
        data = stream.read()
        return FileContentsResponsePDU(payload, msgFlags, streamId, data)

    def parseFormatDataRequest(self, payload, msgFlags):
        s = BytesIO(payload)
        out = FormatDataRequestPDU(Uint32LE.unpack(s))
        self.req = out
        return out

    def parseFormatDataResponse(self, payload, msgFlags):
        isSuccessful = True if msgFlags & ClipboardMessageFlags.CB_RESPONSE_OK else False
        fid = self.req.requestedFormatId if self.req else ClipboardFormatNumber.GENERIC
        pdu = FormatDataResponsePDU(payload, isSuccessful, fid)

        if isSuccessful and fid in self.formats:
            fmt = str(self.formats[fid])

            if fmt == ClipboardFormatName.FILE_LIST.value:
                stream = BytesIO(payload)
                cItems = Uint32LE.unpack(stream)
                pdu.files = [FileDescriptor.parse(stream) for _ in range(cItems)]

        self.req = None
        return pdu

    def parseFormatList(self, payload, msgFlags):
        # Assumes LongFormatNames. This might be bad. Should check capabilities beforehand

        stream = BytesIO(payload)

        self.formats = {}

        while stream.tell() < len(stream.getvalue()):
            formatId = Uint32LE.unpack(stream)
            formatName = b""
            lastChar = b""

            while lastChar != b"\x00\x00":
                lastChar = stream.read(2)
                formatName += lastChar

            self.formats[formatId] = LongFormatName(formatId, formatName)

        return FormatListPDU(dict(self.formats), msgFlags)

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



class FileDescriptor:
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeclip/a765d784-2b39-4b88-9faa-88f8666f9c35
    """
    def __init__(self):
        self.flags = 0
        self.attribs = 0
        self.lastWrite = 0
        self.size = 0
        self.filename = ''

    def parse(stream: BytesIO) -> 'FileDescriptor':
        fd = FileDescriptor()
        fd.flags = Uint32LE.unpack(stream)
        stream.read(32)  # reserved1
        fd.attribs = Uint32LE.unpack(stream)
        stream.read(16)  # reserved2

        fd.lastWrite = Uint64LE.unpack(stream)
        sizeHi = Uint32LE.unpack(stream)
        sizeLo = Uint32LE.unpack(stream)
        fd.size = (sizeHi << 32) | sizeLo
        filename = stream.read(520)

        fd.filename = filename.decode('utf-16le').strip('\x00')

        return fd

