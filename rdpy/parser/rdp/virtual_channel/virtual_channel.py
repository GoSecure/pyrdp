from io import BytesIO

from rdpy.core.packing import Uint32LE
from rdpy.enum.virtual_channel.virtual_channel import ChannelFlag
from rdpy.parser.parser import Parser
from rdpy.pdu.rdp.virtual_channel.virtual_channel import VirtualChannelPDU


class VirtualChannelParser(Parser):
    """
    Parser class for VirtualChannel PDUs.
    """

    MAX_CHUNK_SIZE = 1600  # https://msdn.microsoft.com/en-us/library/cc240548.aspx

    def parse(self, data):
        """
        :type data: str
        :return: VirtualChannelPDU
        """
        stream = BytesIO(data)
        length = Uint32LE.unpack(stream)
        flags = Uint32LE.unpack(stream)
        payload = stream.read(length)
        return VirtualChannelPDU(length, flags, payload)

    def write(self, pdu):
        """
        :type pdu: VirtualChannelPDU
        :return: A LIST of VirtualChannelPDUs as raw bytes. The first one has the CHANNEL_FLAG_FIRST
                 set and the last one has the CHANNEL_FLAG_LAST set.
        """
        rawPacketList = []
        length = pdu.length
        dataStream = BytesIO(pdu.payload)
        while length > 0:
            stream = BytesIO()
            Uint32LE.pack(pdu.length, stream)
            flags = pdu.flags & 0b11111111111111111111111111111100
            if len(rawPacketList) == 0:
                # Means it's the first packet.
                flags |= ChannelFlag.CHANNEL_FLAG_FIRST
            if length <= self.MAX_CHUNK_SIZE:
                # Means it's the last packet.
                flags |= ChannelFlag.CHANNEL_FLAG_LAST
            Uint32LE.pack(flags, stream)
            toWrite = self.MAX_CHUNK_SIZE if length >= self.MAX_CHUNK_SIZE else length
            stream.write(dataStream.read(toWrite))
            rawPacketList.append(stream.getvalue())
            length -= toWrite
        return rawPacketList
