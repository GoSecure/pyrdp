from rdpy.core.newlayer import Layer
from rdpy.parser.rdp.virtual_channel.clipboard.clipboard import ClipboardParser


class ClipboardLayer(Layer):
    """
    Layer to manage reception of the clipboard virtual channel data.
    https://msdn.microsoft.com/en-us/library/cc241066.aspx
    """

    def __init__(self):
        super(ClipboardLayer, self).__init__()
        self.clipboardParser = ClipboardParser()

    def recv(self, data):
        """
        :type data: str
        """
        clipboardPDU = self.clipboardParser.parse(data)
        self.pduReceived(clipboardPDU, False)

    def send(self, pdu):
        """
        :type pdu: rdpy.pdu.rdp.virtual_channel.clipboard.clipboard.ClipboardPDU
        """
        self.previous.send(self.clipboardParser.write(pdu))
