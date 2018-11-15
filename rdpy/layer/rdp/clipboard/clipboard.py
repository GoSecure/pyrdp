from rdpy.core.newlayer import Layer


class ClipboardLayer(Layer):
    """
    Layer to manage reception of the clipboard virtual channel data.
    https://msdn.microsoft.com/en-us/library/cc241066.aspx
    """

    def __init__(self):
        super(ClipboardLayer, self).__init__()
