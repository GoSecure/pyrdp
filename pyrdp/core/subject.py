#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.core.observer import CompositeObserver, Observer


class Subject:
    """
    Base class for objects that can have observers.
    """
    def __init__(self):
        super().__init__()
        self.observer = CompositeObserver()

    def addObserver(self, observer: Observer):
        """
        Add an observer to this subject.
        """
        return self.observer.addObserver(observer)

    def removeObserver(self, observer: Observer):
        """
        Remove an observer from this subject.
        """
        return self.observer.removeObserver(observer)

def ObservedBy(ObserverClass: type):
    """
    This decorator adds a `createObserver` method to a class that creates an
    observer object and forwards all keyword arguments to its constructor.

    :param ObserverClass: The observer class.
    """
    def setCreateObserverMethod(SubjectClass: type) -> type:
        """
        Add a createObserver method to a class.
        :param SubjectClass: the subject class.
        """

        def createObserver(self, **kwargs):
            """
            Creates a new observer by forwarding all keyword arguments to it.
            """
            observer = ObserverClass(**kwargs)
            self.addObserver(observer)
            return observer

        SubjectClass.createObserver = createObserver
        return SubjectClass
    
    return setCreateObserverMethod