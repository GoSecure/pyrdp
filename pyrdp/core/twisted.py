#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
from typing import Callable, Union
import socket
import logging

from twisted.internet.protocol import ClientFactory, Protocol
from twisted.internet import tcp, fdesc, reactor

LOG = logging.getLogger(__name__)


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


class TransparentClient(tcp.Client):
    """A TCP client that supports transparent proxying."""

    def createInternetSocket(self):
        """Overridden"""

        err = None
        s = socket.socket(self.addressFamily, self.socketType)
        s.setblocking(0)
        fdesc._setCloseOnExec(s.fileno())

        try:
            if not s.getsockopt(socket.SOL_IP, socket.IP_TRANSPARENT):
                s.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
        except Exception as e:
            LOG.error('Failed to establish transparent proxy: %s', e)

        return s  # Maintain non-transparent behavior.


class TransparentConnector(tcp.Connector):
    """A TCP connector which creates TransparentClients."""

    def _makeTransport(self):
        return TransparentClient(self.host, self.port, self.bindAddress, self, self.reactor)


def connectTransparent(host, port, factory, timeout=30, bindAddress=None):
    """Create a transparent proxy connection managed by Twisted."""
    c = TransparentConnector(host, port, factory, timeout, bindAddress, reactor)
    c.connect()
    return c
