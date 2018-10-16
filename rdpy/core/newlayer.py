from observer import Observer
from subject import Subject, ObservedBy

class LayerObserver(Observer):
    """
    Layer observer class, notified whenever a layer receives a PDU.
    """
    def __init__(self, **kwargs):
        Observer.__init__(self, **kwargs)

    def onPDUReceived(self, pdu):
        """
        Method called when a PDU is received
        """
        pass

class LayerRoutedObserver(LayerObserver):
    """
    Layer observer that routes PDUs to methods by checking the PDU's header.
    """
    def __init__(self, handlers, **kwargs):
        """
        :param handlers: a dictionary of headers to method names
        """
        LayerObserver.__init__(self, **kwargs)
        self.handlers = {}

        for (header, name) in handlers.items():
            self.handlers[header] = getattr(self, name)


    def onPDUReceived(self, pdu):
        if pdu.header not in self.handlers:
            self.onUnknownHeader(pdu)
        else:
            self.handlers[pdu.header](pdu)

    def onUnknownHeader(self, pdu):
        """
        Method called when a PDU with an unknown header is received
        """
        pass

class LayerStrictRoutedObserver(LayerRoutedObserver):
    """
    Layer observer that throws an exception when an unknown header is received.
    """
    def __init__(self, handlers, **kwargs):
        """
        :param handlers: a dictionary of headers to callbacks (callable objects)
        """
        LayerRoutedObserver.__init__(self, handlers, **kwargs)
    
    def onUnknownHeader(self, pdu):
        """
        Method called when a PDU with an unknown header is received
        """
        raise Exception("Unknown PDU header received: 0x%lx" % pdu.header)


@ObservedBy(LayerObserver)
class Layer(Subject):
    """
    A doubly-linked list of network layers. An observer can be attached to capture incoming PDUs.
    ObservedBy: LayerObserver
    """
    def __init__(self):
        Subject.__init__(self)
        self.previous = None
        self.next = None
    
    def setNext(self, layer):
        """
        Set the next layer in the protocol hierarchy (ex: IP's next layer would be TCP).
        :param layer: The next layer.
        :type layer: Layer
        """
        self.next = layer
        layer.previous = self
    
    def pduReceived(self, pdu, forward):
        """
        Called when a PDU is received.
        Notifies the attached observer and optionally forwards the payload to the next layer.
        :param pdu: the PDU.
        :param forward: whether the PDU's payload should be forwarded to the next layer.
        :type forward: bool
        """
        if self.observer is not None:
            self.observer.onPDUReceived(pdu)
        
        if forward and self.next is not None:
            self.next.recv(pdu.payload)
