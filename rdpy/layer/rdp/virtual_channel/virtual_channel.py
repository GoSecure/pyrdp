from rdpy.core.logging import log
from rdpy.enum.virtual_channel.virtual_channel import ChannelFlag
from rdpy.layer.layer import Layer
from rdpy.parser.rdp.virtual_channel.virtual_channel import VirtualChannelParser
from rdpy.pdu.rdp.virtual_channel.virtual_channel import VirtualChannelPDU


class VirtualChannelLayer(Layer):
    """
    Layer that handles the virtual channel layer of the RDP protocol:
    https://msdn.microsoft.com/en-us/library/cc240548.aspx
    """

    def __init__(self, activateShowProtocolFlag=True):
        """
        :param activateShowProtocolFlag: True if the channelFlagShowProtocol must be set (depends on virtual channels)
        """
        Layer.__init__(self, VirtualChannelParser(), hasNext=True)
        self.activateShowProtocolFlag = activateShowProtocolFlag
        self.pduBuffer = b""

    def recv(self, data: bytes):
        virtualChannelPDU = self.mainParser.parse(data)

        if virtualChannelPDU.flags & ChannelFlag.CHANNEL_PACKET_COMPRESSED != 0:
            log.error("Compression flag is set on virtual channel data, it is NOT handled, crash will most likely occur.")

        flags = virtualChannelPDU.flags
        if flags & ChannelFlag.CHANNEL_FLAG_FIRST:
            self.pduBuffer = virtualChannelPDU.payload
        else:
            self.pduBuffer += virtualChannelPDU.payload

        if flags & ChannelFlag.CHANNEL_FLAG_LAST:
            # Reassembly done, change the payload of the virtualChannelPDU for processing by the observer.
            virtualChannelPDU.payload = self.pduBuffer
            self.pduReceived(virtualChannelPDU, self.hasNext)

    def send(self, payload):
        """
        Send payload on the upper layer by encapsulating it in a VirtualChannelPDU.
        :type payload: bytes
        """
        flags = ChannelFlag.CHANNEL_FLAG_FIRST | ChannelFlag.CHANNEL_FLAG_LAST
        if self.activateShowProtocolFlag:
            flags |= ChannelFlag.CHANNEL_FLAG_SHOW_PROTOCOL
        virtualChannelPDU = VirtualChannelPDU(len(payload), flags, payload)
        rawVirtualChannelPDUsList = self.mainParser.write(virtualChannelPDU)
        # Since a virtualChannelPDU may need to be sent using several packets
        for data in rawVirtualChannelPDUsList:
            self.previous.send(data)
