#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
import operator
from typing import Callable, Dict


class Event:
    """
    An asyncio.Event wrapper that will be triggered when an object passes a check.
    """
    def __init__(self):
        self.aioEvent = asyncio.Event()
        self.object = None

    def check(self, obj) -> bool:
        """
        Check if an object is a match for this event.
        :param obj: the object we are trying to match.
        :return: True if the object matches, otherwise False.
        """
        raise NotImplementedError("check must be overridden")


class FunctionEvent(Event):
    """
    An asyncio.Event wrapper that will be triggered when a given callable returns True.
    """
    def __init__(self, predicate: Callable[[object], bool]):
        super().__init__()
        self.predicate = predicate

    def check(self, obj) -> bool:
        """
        Check if an object is a match for this event by calling the provided callable.
        :param obj: the object we are trying to match.
        :return: True if the object matches, otherwise False.
        """
        return self.predicate(obj)


class PropertyEvent(Event):
    """
    An asyncio.Event wrapper that will be triggered when an object's attributes have specific values.
    """
    def __init__(self, attributes: Dict[str, object]):
        super().__init__()
        self.attributes = {operator.attrgetter(key): value for key, value in attributes.items()}

    def check(self, obj) -> bool:
        """
        Check if an object is a match for this event by checking that its attributes match the given dict.
        :param obj: the object we are trying to match.
        :return: True if the object matches, otherwise False.
        """
        for getter, expectedValue in self.attributes.items():
            try:
                attributeValue = getter(obj)
            except AttributeError:
                return False

            if attributeValue != expectedValue:
                return False

        return True


class EventEngine:
    """
    An event engine is a queue of asyncio.Event wrappers.
    Every time an object of interest is received, it should be passed to processObject.
    The event engine will try to match the object with every event being awaited until a match is made (if any).
    If a match is made, the event that was checked will be triggered and the object will be consumed (only one match is allowed per object).
    If an object could potentially be matched with multiple events, only the event that was added first will be triggered.

    Users of this class are expected to call the wait function and pass it attributes that it should have and / or a predicate
    function that will be used to check if the objects that are received match. Example:

    class Foo:
        def __init__(self, value):
            self.attribute = value

    class Bar:
        attribute = 42

    engine = EventEngine()

    # ...

    async def myCoroutine():
        foo = await engine.wait({"attribute": 42})
        print(foo.attribute) # Prints 42

    # ...

    # This will resolve the await in myCoroutine
    engine.processObject(Foo(42))

    # This will not resolve the await in myCoroutine because attribute != 42
    engine.processObject(Foo(123))

    # This will also resolve because it has an attribute called "attribute" with a value of 42
    engine.processObject(Bar(42))
    """

    @staticmethod
    def Anything(_):
        """
        This predicate can be used to wait for any object.
        """
        return True

    def __init__(self):
        """
        Create a new (empty) event engine.
        """
        self.events: [Event] = []

    def processObject(self, obj):
        """
        Call when an object of interest is received. The engine will try to match the object to events currently awaited.
        :param obj: the object of interest.
        :return: True if a match was made, otherwise False.
        """
        for event in self.events:
            if event.check(obj):
                self.events.remove(event)
                event.object = obj
                event.aioEvent.set()
                return True

        return False

    async def wait(self, where: Dict[str, object] = None, match: Callable[[object], bool] = None):
        """
        Call to wait for an object matching certain criteria to arrive.
        If both predicate and attributes are not None, then attributes will be matched first, then predicate.
        If both predicate and attributes are None, then any object will be matched.
        :param where: dict of attribute name -> value that the object should have.
        :param match: function that will be used to match the object (returns True for matching objects).
        :return: the object that matched the criteria.
        """
        propertyEvent: PropertyEvent = None

        if where:
            propertyEvent = PropertyEvent(where)

        if match is not None:
            if propertyEvent:
                event = FunctionEvent(lambda obj: propertyEvent.check(obj) and match(obj))
            else:
                event = FunctionEvent(match)
        elif propertyEvent:
            event = propertyEvent
        else:
            event = FunctionEvent(EventEngine.Anything)

        self.events.append(event)
        await event.aioEvent.wait()
        return event.object
