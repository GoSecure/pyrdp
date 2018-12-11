from pyrdp.layer.layer import Layer
from pyrdp.parser import ClipboardParser


class ClipboardLayer(Layer):
    """
    Layer to manage reception of the clipboard virtual channel data.
    https://msdn.microsoft.com/en-us/library/cc241066.aspx
    """

    def __init__(self, parser = ClipboardParser()):
        Layer.__init__(self, parser, hasNext=False)
