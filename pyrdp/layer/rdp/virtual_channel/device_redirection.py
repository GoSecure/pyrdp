from pyrdp.layer.layer import Layer
from pyrdp.parser import DeviceRedirectionParser


class DeviceRedirectionLayer(Layer):
    """
    Layer to receive and send DeviceRedirection channel (rdpdr) packets.
    """

    def __init__(self, parser = DeviceRedirectionParser()):
        super().__init__(parser, hasNext=False)
