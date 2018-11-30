from rdpy.layer.layer import Layer
from rdpy.parser.rdp.virtual_channel.clipboard import ClipboardParser


class ClipboardLayer(Layer):
    """
    Layer to manage reception of the clipboard virtual channel data.
    https://msdn.microsoft.com/en-us/library/cc241066.aspx
    """

    def __init__(self):
        Layer.__init__(self, ClipboardParser(), hasNext=False)
