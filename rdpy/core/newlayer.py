class Layer(object):
    """
    @summary:  A simple double linked list with presentation and transport layer
                and a subset of event (connect and close)
    """
    def __init__(self):
        """
        @param presentation: presentation layer
        """
        self.previous = None
        self.next = None
    
    def setNext(self, layer):
        self.next = layer
        layer.previous = self