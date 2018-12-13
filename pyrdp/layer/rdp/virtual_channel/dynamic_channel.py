from pyrdp.layer import Layer
from pyrdp.parser.rdp.virtual_channel.dynamic_channel import DynamicChannelParser


class DynamicChannelLayer(Layer):
    """
    Layer to receive and send DynamicChannel channel (drdynvc) packets.
    """

    def __init__(self, parser=DynamicChannelParser()):
        super().__init__(parser, hasNext=False)
