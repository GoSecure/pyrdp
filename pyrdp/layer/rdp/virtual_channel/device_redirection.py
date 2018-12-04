from pyrdp.layer.layer import Layer
from pyrdp.parser.rdp.virtual_channel.device_redirection import DeviceRedirectionParser


class DeviceRedirectionLayer(Layer):
    """
    Layer to receive and send DeviceRedirection channel (rdpdr) packets.
    """

    def __init__(self):
        super().__init__(DeviceRedirectionParser(), hasNext=False)