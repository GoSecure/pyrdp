#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Optional

from pyrdp.core import ObservedBy, Observer, Subject, EventEngine
from pyrdp.exceptions import UnknownPDUTypeError
from pyrdp.parser import Parser
from pyrdp.pdu import PDU


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
        :type handlers: dict
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
        :param handlers: a dictionary of headers to method names
        :type handlers: dict
        """
        LayerRoutedObserver.__init__(self, handlers, **kwargs)
    
    def onUnknownHeader(self, pdu):
        """
        Method called when a PDU with an unknown header is received
        """
        raise UnknownPDUTypeError("Unknown PDU header received: 0x%2lx" % pdu.header, type(pdu))


@ObservedBy(LayerObserver)
class Layer(Subject):
    """
    A doubly-linked list of network layers. An observer can be attached to capture incoming PDUs.
    ObservedBy: LayerObserver
    """
    def __init__(self, mainParser: Optional[Parser]=None, hasNext=True):
        Subject.__init__(self)
        self.eventEngine = EventEngine()
        self.hasNext = hasNext
        self.mainParser = mainParser
        self.previous: Layer = None
        self.next: Layer = None

    @staticmethod
    def chain(first: 'Layer', second: 'Layer', *layers: ['Layer']):
        """
        Chain a series of layers together by calling setNext iteratively.
        :param first: first layer in the chain.
        :param second: second layer in the chain.
        :param layers: additional layers in the chain.
        """
        first.setNext(second)

        current = second
        for nextLayer in layers:
            current.setNext(nextLayer)
            current = nextLayer
    
    def setNext(self, layer: 'Layer'):
        """
        Set the next layer in the protocol hierarchy (ex: IP's next layer would be TCP/UDP).
        :param layer: The next layer.
        """
        self.next = layer
        layer.previous = self
    
    def pduReceived(self, pdu: PDU, forward: bool):
        """
        Called when a PDU is received.
        Notifies the attached observer and optionally forwards the payload to the next layer.
        :param pdu: the PDU.
        :param forward: whether the PDU's payload should be forwarded to the next layer.
        :type forward: bool
        """
        self.eventEngine.processObject(pdu)

        if self.observer is not None:
            self.observer.onPDUReceived(pdu)
        
        if forward and self.next is not None:
            self.next.recv(pdu.payload)

    async def waitPDU(self, *args, **kwargs):
        """
        Wait for a PDU matching certain criteria (see EventEngine.wait)
        :return: PDU
        """
        return await self.eventEngine.wait(*args, **kwargs)

    def recv(self, data: bytes):
        pdu = self.mainParser.parse(data)
        self.pduReceived(pdu, self.hasNext)

    def send(self, data: bytes):
        self.previous.send(data)
