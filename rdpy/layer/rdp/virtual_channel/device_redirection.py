from rdpy.core.layer import Layer
from rdpy.parser.rdp.virtual_channel.device_redirection import DeviceRedirectionParser


class DeviceRedirectionLayer(Layer):
    """
    Layer to receive and send DeviceRedirection channel (rdpdr) packets.
    """

    def __init__(self):
        super().__init__()
        self.deviceRedirectionParser = DeviceRedirectionParser()

    def recv(self, data: bytes):
        pdu = self.deviceRedirectionParser.parse(data)
        self.pduReceived(pdu, False)
