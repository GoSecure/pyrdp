#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from abc import ABCMeta, abstractmethod
from typing import Union

from pyrdp.core import EventEngine, ObservedBy, Observer, Subject
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


class ByteSender(metaclass = ABCMeta):
    """
    Basic interface that defines the sendBytes method.
    """

    @abstractmethod
    def sendBytes(self, data: bytes):
        raise NotImplementedError("sendBytes must be overridden")


@ObservedBy(LayerObserver)
class Layer(Subject):
    """
    A layer transforms bytes into PDUs by using a given parser.
    Parsed PDUs are processed by the event engine.
    Observers can be attached to be notified of incoming PDUs.
    ObservedBy: LayerObserver
    """
    def __init__(self, mainParser: Parser):
        super().__init__()
        self.mainParser = mainParser
        self.eventEngine = EventEngine()
        self.previous: ByteSender = None

    def setPrevious(self, previous: ByteSender):
        self.previous = previous
    
    def pduReceived(self, pdu: PDU):
        """
        Call when a PDU is received to have it processed (notify the observer and pass it through the event engine).
        :param pdu: the PDU.
        """
        self.eventEngine.processObject(pdu)

        if self.observer is not None:
            self.observer.onPDUReceived(pdu)

    def recv(self, data: bytes):
        """
        Parse received bytes to a PDU and process it.
        :param data: bytes received.
        """
        pdu = self.mainParser.parse(data)
        self.pduReceived(pdu)

    def sendPDU(self, pdu: PDU):
        """
        Send a PDU to the previous layer.
        :param pdu: the PDU.
        """
        data = self.mainParser.write(pdu)
        self.previous.sendBytes(data)

    async def waitPDU(self, *args, **kwargs) -> PDU:
        """
        Wait for a PDU matching certain criteria (see EventEngine.wait).
        """
        return await self.eventEngine.wait(*args, **kwargs)


class LayerChainItem(ByteSender):
    def __init__(self):
        super().__init__()
        self.next: Layer = None

    @staticmethod
    def chain(first: 'LayerChainItem', second: Union['Layer', 'LayerChainItem'], *layers: [Union['Layer', 'LayerChainItem']]):
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
        layer.setPrevious(self)


class IntermediateLayer(Layer, LayerChainItem):
    """
    Layer that usually forwards some or all PDUs to another layer.
    """

    def __init__(self, mainParser: Parser):
        super().__init__(mainParser)

    def pduReceived(self, pdu: PDU):
        Layer.pduReceived(self, pdu)

        if self.next is not None and self.shouldForward(pdu):
            self.next.recv(pdu.payload)

    def sendBytes(self, data: bytes):
        self.previous.sendBytes(data)

    def shouldForward(self, pdu: PDU) -> bool:
        raise NotImplementedError("shouldForward must be overridden")