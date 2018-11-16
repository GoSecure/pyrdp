from rdpy.core.newlayer import Layer
from rdpy.enum.virtual_channel.virtual_channel import ChannelFlag
from rdpy.parser.rdp.virtual_channel.virtual_channel import VirtualChannelParser
from rdpy.pdu.rdp.virtual_channel.virtual_channel import VirtualChannelPDU


class VirtualChannelLayer(Layer):
    """
    Layer that handles the virtual channel layer of the RDP protocol:
    https://msdn.microsoft.com/en-us/library/cc240548.aspx
    """

    def __init__(self):
        super(VirtualChannelLayer, self).__init__()
        self.virtualChannelParser = VirtualChannelParser()

    def recv(self, data):
        """
        :type data: str
        """
        virtualChannelPDU = self.virtualChannelParser.parse(data)
        completeChunk = ChannelFlag.CHANNEL_FLAG_FIRST | ChannelFlag.CHANNEL_FLAG_LAST

        if virtualChannelPDU.flags & completeChunk != completeChunk:
            raise RuntimeError("The virtual channel packet must be reassembled. It is not handled.")

        self.pduReceived(virtualChannelPDU, True)

    def send(self, payload):
        """
        Send payload on the upper layer by encapsulating it in a VirtualChannelPDU.
        :type payload: str
        """
        flags = ChannelFlag.CHANNEL_FLAG_FIRST | ChannelFlag.CHANNEL_FLAG_LAST | ChannelFlag.CHANNEL_FLAG_SHOW_PROTOCOL
        virtualChannelPDU = VirtualChannelPDU(len(payload), flags, payload)
        self.previous.send(self.virtualChannelParser.write(virtualChannelPDU))
