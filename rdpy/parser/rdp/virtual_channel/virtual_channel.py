from StringIO import StringIO

from rdpy.core.packing import Uint32LE
from rdpy.parser.parser import Parser
from rdpy.pdu.rdp.virtual_channel.virtual_channel import VirtualChannelPDU


class VirtualChannelParser(Parser):
    """
    Parser class for VirtualChannel PDUs.
    """

    def parse(self, data):
        """
        :type data: str
        :return: VirtualChannelPDU
        """
        stream = StringIO(data)
        length = Uint32LE.unpack(stream)
        flags = Uint32LE.unpack(stream)
        payload = stream.read(length)
        return VirtualChannelPDU(length, flags, payload)

    def write(self, pdu):
        """
        :type pdu: VirtualChannelPDU
        :return: str
        """
        stream = StringIO()
        Uint32LE.pack(pdu.length, stream)
        Uint32LE.pack(pdu.flags, stream)
        stream.write(pdu.payload)
        return stream.getvalue()
