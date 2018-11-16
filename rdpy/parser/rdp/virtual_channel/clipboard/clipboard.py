from StringIO import StringIO

from rdpy.core.packing import Uint16LE, Uint32LE
from rdpy.enum.virtual_channel.clipboard.clipboard import ClipboardMessageType
from rdpy.pdu.rdp.virtual_channel.clipboard.clipboard import ClipboardPDU


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
        if msgType == ClipboardMessageType.CB_FORMAT_DATA_REQUEST:
            clipboardPDU = ClipboardPDU(ClipboardMessageType(msgType), msgFlags, payload)
        else:
            clipboardPDU = ClipboardPDU(ClipboardMessageType(msgType), msgFlags, payload)
        return clipboardPDU

    def write(self, pdu):
        """
        :type pdu: ClipboardPDU
        :return: str
        """

        stream = StringIO()
        Uint16LE.pack(pdu.msgType, stream)
        Uint16LE.pack(pdu.msgFlags, stream)
        Uint32LE.pack(len(pdu.payload), stream)
        stream.write(pdu.payload)
        return stream.getvalue()
