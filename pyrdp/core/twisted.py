#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
from typing import Callable, Union

from twisted.internet.protocol import ClientFactory, Protocol


class AwaitableClientFactory(ClientFactory):
    """
    Twisted Client Factory with an asyncio.Event that is set when the connection is established.
    """

    def __init__(self, protocol: Union[Protocol, Callable[[], Protocol]]):
        """
        :param protocol: protocol to return in buildProtocol, or callable that returns a Protocol object.
        """

        self.protocol = protocol
        self.connected = asyncio.Event()

    def buildProtocol(self, addr):
        self.connected.set()

        if callable(self.protocol):
            return self.protocol()
        else:
            return self.protocol