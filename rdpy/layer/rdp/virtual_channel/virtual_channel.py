from rdpy.core.layer import Layer
from rdpy.enum.virtual_channel.virtual_channel import ChannelFlag
from rdpy.parser.rdp.virtual_channel.virtual_channel import VirtualChannelParser
from rdpy.pdu.rdp.virtual_channel.virtual_channel import VirtualChannelPDU


class VirtualChannelLayer(Layer):
    """
    Layer that handles the virtual channel layer of the RDP protocol:
    https://msdn.microsoft.com/en-us/library/cc240548.aspx
    """

    def __init__(self):
        Layer.__init__(self)
        self.virtualChannelParser = VirtualChannelParser()
        self.pduBuffer = b""

    def recv(self, data):
        """
        :type data: bytes
        """
        virtualChannelPDU = self.virtualChannelParser.parse(data)

        flags = virtualChannelPDU.flags
        if flags & ChannelFlag.CHANNEL_FLAG_FIRST:
            self.pduBuffer = virtualChannelPDU.payload
        else:
            self.pduBuffer += virtualChannelPDU.payload

        if flags & ChannelFlag.CHANNEL_FLAG_LAST:
            # Reassembly done, change the payload of the virtualChannelPDU for processing by the observer.
            virtualChannelPDU.payload = self.pduBuffer
            self.pduReceived(virtualChannelPDU, True)

    def send(self, payload):
        """
        Send payload on the upper layer by encapsulating it in a VirtualChannelPDU.
        :type payload: bytes
        """
        flags = ChannelFlag.CHANNEL_FLAG_FIRST | ChannelFlag.CHANNEL_FLAG_LAST | ChannelFlag.CHANNEL_FLAG_SHOW_PROTOCOL
        virtualChannelPDU = VirtualChannelPDU(len(payload), flags, payload)
        rawVirtualChannelPDUsList = self.virtualChannelParser.write(virtualChannelPDU)
        # Since a virtualChannelPDU may need to be sent using several packets
        for data in rawVirtualChannelPDUsList:
            self.previous.send(data)
