#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.pdu import PDU


class Observer:
    """
    Base observer class used across PyRDP.
    """
    def __init__(self, **kwargs):
        """
        Initialize a new Observer object.
        The kwargs are used to allow users to define custom handlers and pass them as arguments instead of inheriting from an observer class.
        This is useful in case of multiple inheritance, because only one method of the same name is preserved.
        """
        self.peer: Observer = None
        for (name, handler) in kwargs.items():
            if hasattr(self, name):
                setattr(self, name, handler)
            else:
                raise TypeError("Unexpected keyword argument '%s'" % name)

    def setPeer(self, peer: 'Observer'):
        self.peer = peer
        peer.peer = self

    def onPDUReceived(self, pdu: PDU):
        pass


class CompositeObserver:
    """
    Observer class that contains other observers and delegates method calls to them.
    """
    def __init__(self):
        self.observers = []

    def __getattr__(self, item):
        """
        Creates a CompositeObserverCall object, which will invoke doCall when it is called.
        """
        return CompositeObserverCall(self, item)

    def __nonzero__(self):
        return True

    def doCall(self, item, args, kwargs):
        """
        When a method is called, invoke the same method on every observer object.
        """
        for observer in self.observers:
            getattr(observer, item)(*args, **kwargs)

    def addObserver(self, observer):
        """
        Add an observer to the composite.
        :type observer: Observer
        """
        self.observers.append(observer)

    def removeObserver(self, observer):
        """
        Remove an observer from the composite.
        :type observer: Observer
        """
        self.observers.remove(observer)

class CompositeObserverCall:
    """
    Object that calls back to the CompositeObserver when it is called.
    """
    def __init__(self, composite, item):
        self.composite = composite
        self.item = item

    def __call__(self, *args, **kwargs):
        """
        Delegate the call to the composite.
        """
        self.composite.doCall(self.item, args, kwargs)