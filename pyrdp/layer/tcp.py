#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
import logging
from binascii import hexlify

from twisted.internet.protocol import connectionDone, Protocol

from pyrdp.core import ObservedBy
from pyrdp.layer.layer import IntermediateLayer, LayerObserver
from pyrdp.logging import LOGGER_NAMES, getSSLLogger
from pyrdp.parser.tcp import TCPParser
from pyrdp.pdu import PDU


class TCPObserver(LayerObserver):
    def onConnection(self):
        """
        Called when a TCP connection is made.
        """
        pass

    def onDisconnection(self, reason):
        """
        Called when the TCP connection is lost.
        :param reason: reason for disconnection.
        """
        pass


@ObservedBy(TCPObserver)
class TwistedTCPLayer(IntermediateLayer, Protocol):
    """
    Twisted protocol class and first layer in a stack.
    ObservedBy: TCPObserver
    Never notifies observers about PDUs because there isn't really a TCP PDU type per se.
    TCP observers are notified when a connection is made.
    """

    def __init__(self):
        self.log = logging.getLogger(LOGGER_NAMES.PYRDP)
        super().__init__(TCPParser())
        self.connectedEvent = asyncio.Event()
        self.logSSLRequired = False

    def logSSLParameters(self):
        """
        Log the SSL parameters of the connection in a format suitable for decryption by Wireshark.
        """
        getSSLLogger().info(self.transport.protocol._tlsConnection.client_random(), self.transport.protocol._tlsConnection.master_key())

    def connectionMade(self):
        """
        When the TCP handshake is completed, notify the observer.
        """
        self.connectedEvent.set()
        self.observer.onConnection()

    def connectionLost(self, reason=connectionDone):
        """
        :param reason: reason for disconnection.
        """
        self.observer.onDisconnection(reason)

    def disconnect(self, abort = False):
        """
        Close the TCP connection.
        :param abort: True to force close the connection, False to end gracefully.
        """

        if self.transport:
            if abort:
                self.transport.abortConnection()
            else:
                self.transport.loseConnection()

    def dataReceived(self, data: bytes):
        """
        Called whenever data is received.
        :param data: bytes received.
        """
        try:
            if self.logSSLRequired:
                self.logSSLParameters()
                self.logSSLRequired = False

            self.recv(data)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.log.exception(e)
            self.log.error("Exception occurred when receiving: %(data)s" , {"data": hexlify(data).decode()})
            raise

    def sendBytes(self, data: bytes):
        """
        Send raw TCP bytes.
        :param data: bytes to send.
        """
        self.transport.write(data)

    def startTLS(self, tlsContext):
        """
        Perform a TLS handshake so that all further communications are encrypted.
        :param tlsContext: Twisted TLS Context object (like DefaultOpenSSLContextFactory)
        """
        self.logSSLRequired = True
        self.transport.startTLS(tlsContext)

    def shouldForward(self, pdu: PDU) -> bool:
        return True


@ObservedBy(TCPObserver)
class AsyncIOTCPLayer(IntermediateLayer, asyncio.Protocol):
    """
    AsyncIO protocol class and first layer in a stack.
    ObservedBy: TCPObserver
    Never notifies observers about PDUs because there isn't really a TCP PDU type per se.
    TCP observers are notified when a connection is made.
    """

    def __init__(self):
        super().__init__(TCPParser())
        self.connectedEvent = asyncio.Event()
        self.transport: asyncio.Transport = None

    def connection_made(self, transport: asyncio.BaseTransport):
        """
        When the TCP handshake is completed, notify the observer.
        """
        self.transport = transport
        self.connectedEvent.set()
        self.observer.onConnection()

    def connection_lost(self, exception=connectionDone):
        """
        :param exception: reason for disconnection.
        """
        self.observer.onDisconnection(exception)

    def disconnect(self, abort = False):
        """
        Close the TCP connection.
        :param abort: True to force close the connection, False to end gracefully.
        """
        if abort:
            self.transport.abort()
        else:
            self.transport.close()

    def data_received(self, data: bytes):
        """
        Called whenever data is received.
        :param data: bytes received.
        """

        try:
            self.recv(data)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            logging.getLogger(LOGGER_NAMES.PYRDP).exception(e)
            raise

    def sendBytes(self, data: bytes):
        """
        Send raw TCP bytes.
        :param data: bytes to send.
        """
        self.transport.write(data)

    def shouldForward(self, pdu: PDU) -> bool:
        return True