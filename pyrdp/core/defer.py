#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
import typing

def defer(coroutine: typing.Union[typing.Coroutine, asyncio.Future]):
    """
    Create a twisted Deferred from a coroutine or future and ensure it will run (call ensureDeferred on it).
    :param coroutine: coroutine to defer.
    """
    from twisted.internet.defer import ensureDeferred, Deferred

    ensureDeferred(Deferred.fromFuture(asyncio.ensure_future(coroutine)))