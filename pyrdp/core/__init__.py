#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.core.event import EventEngine
from pyrdp.core.helpers import decodeUTF16LE, encodeUTF16LE
from pyrdp.core.observer import CompositeObserver, Observer
from pyrdp.core.packing import Int16BE, Int16LE, Int32BE, Int32LE, Int8, Uint16BE, Uint16LE, Uint32BE, Uint32LE, \
    Uint64LE, Uint8
from pyrdp.core.stream import ByteStream, StrictStream
from pyrdp.core.subject import ObservedBy, Subject
from pyrdp.core.timer import Timer
from pyrdp.core.twisted import AwaitableClientFactory

import asyncio
import typing

def defer(coroutine: typing.Union[typing.Coroutine, asyncio.Future]):
    """
    Create a twisted Deferred from a coroutine or future and ensure it will run (call ensureDeferred on it).
    :param coroutine: coroutine to defer.
    """
    from twisted.internet.defer import ensureDeferred, Deferred

    ensureDeferred(Deferred.fromFuture(asyncio.ensure_future(coroutine)))