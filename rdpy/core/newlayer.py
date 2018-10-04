from subject import Subject

class LayerObserver(object):
    """
    Layer observer class, notified whenever a layer receives a PDU.
    """
    def pduReceived(self, pdu):
        """
        Method called when a PDU is received
        """
        pass

class LayerRoutedObserver(LayerObserver):
    """
    Layer observer that routes PDUs to methods by checking the PDU's header.
    """
    def __init__(self, handlers):
        """
        :param handlers: a dictionary of headers to callbacks (callable objects)
        """
        LayerObserver.__init__(self)
        self.handlers = handlers

    def pduReceived(self, pdu):
        if pdu.header not in self.handlers:
            self.unknownHeader(pdu)
        else:
            self.handlers[pdu.header](pdu)

    def unknownHeader(self, pdu):
        """
        Method called when a PDU with an unknown header is received
        """
        pass

class LayerStrictRoutedObserver(LayerRoutedObserver):
    """
    Layer observer that throws an exception when an unknown header is received.
    """
    def __init__(self, handlers):
        """
        :param handlers: a dictionary of headers to callbacks (callable objects)
        """
        LayerRoutedObserver.__init__(self, handlers)
    
    def unknownHeader(self, pdu):
        """
        Method called when a PDU with an unknown header is received
        """
        raise Exception("Unknown PDU header received: 0x%lx" % pdu.header)

class Layer(Subject):
    """
    A doubly-linked list of network layers. An observer can be attached to capture incoming PDUs.
    """
    def __init__(self):
        Subject.__init__(self)
        self.previous = None
        self.next = None
    
    def setNext(self, layer):
        """
        Set the next layer in the list.
        :param layer: the next layer.
        """
        self.next = layer
        layer.previous = self
    
    def pduReceived(self, pdu, forward):
        """
        Called when a PDU is received. Notifies the observer and optionally forwards the payload to the next layer.
        :param pdu: the PDU.
        :param forward: whether the PDU's payload should be forwarded to the next layer.
        """
        if self.observer is not None:
            self.observer.pduReceived(pdu)
        
        if forward and self.next is not None:
            self.next.recv(pdu.payload)