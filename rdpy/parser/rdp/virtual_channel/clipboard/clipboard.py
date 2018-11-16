from StringIO import StringIO

from rdpy.core.packing import Uint16LE, Uint32LE
from rdpy.enum.virtual_channel.clipboard.clipboard import ClipboardMessageType, ClipboardMessageFlags
from rdpy.pdu.rdp.virtual_channel.clipboard.clipboard import ClipboardPDU
from rdpy.pdu.rdp.virtual_channel.clipboard.paste import FormatDataResponsePDU


class ClipboardParser:
    """
    Parser class for clipboard PDUs
    """

    def parse(self, data):
        stream = StringIO(data)
        msgType = Uint16LE.unpack(stream)
        msgFlags = Uint16LE.unpack(stream)
        dataLen = Uint32LE.unpack(stream)
        payload = stream.read(dataLen)
        if msgType == ClipboardMessageType.CB_FORMAT_DATA_RESPONSE:
            clipboardPDU = self.parseFormatDataResponse(payload, msgFlags)
        else:
            clipboardPDU = ClipboardPDU(ClipboardMessageType(msgType), msgFlags, payload)
        return clipboardPDU

    def parseFormatDataResponse(self, payload, msgFlags):
        isSuccessful = True if msgFlags & ClipboardMessageFlags.CB_RESPONSE_OK else False
        return FormatDataResponsePDU(payload, isSuccessful)

    def write(self, pdu):
        """
        :type pdu: ClipboardPDU
        :return: str
        """

        stream = StringIO()
        Uint16LE.pack(pdu.msgType, stream)
        Uint16LE.pack(pdu.msgFlags, stream)
        if pdu.msgType == ClipboardMessageType.CB_FORMAT_DATA_RESPONSE:
            self.writeFormatDataResponse(stream, pdu)
        else:
            Uint32LE.pack(len(pdu.payload), stream)
            stream.write(pdu.payload)
        return stream.getvalue()

    def writeFormatDataResponse(self, stream, pdu):
        """
        Write the FormatDataResponsePDU starting at dataLen.
        :type stream: StringIO
        :type pdu: FormatDataResponsePDU
        """
        Uint32LE.pack(len(pdu.requestedFormatData), stream)
        stream.write(pdu.requestedFormatData)
