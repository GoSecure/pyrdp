#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import typing
from logging import LoggerAdapter

from pyrdp.core import defer
from pyrdp.enum import NegotiationFailureCode, NegotiationProtocols, NegotiationType
from pyrdp.layer import X224Layer
from pyrdp.mitm.state import RDPMITMState
from pyrdp.parser import NegotiationRequestParser, NegotiationResponseParser
from pyrdp.pdu import NegotiationRequestPDU, NegotiationResponsePDU, X224ConnectionConfirmPDU, X224ConnectionRequestPDU, \
    X224DisconnectRequestPDU, X224ErrorPDU


class X224MITM:
    def __init__(self, client: X224Layer, server: X224Layer, log: LoggerAdapter, state: RDPMITMState, connector: typing.Coroutine, startTLSCallback: typing.Callable[[], None]):
        """

        :param client: X224 layer for the client side
        :param server: X224 layer for the server side
        :param log: logger for this component
        :param state: state of the MITM
        :param connector: coroutine that connects to the server, awaited when a connection request is received
        :param startTLSCallback: callback that should execute a startTLS on the client and server sides
        """

        super().__init__()
        self.client = client
        self.server = server
        self.log = log
        self.state = state
        self.connector = connector
        self.startTLSCallback = startTLSCallback
        self.originalRequest: typing.Optional[NegotiationRequestPDU] = None

        self.client.createObserver(
            onConnectionRequest = self.onConnectionRequest,
            onDisconnectRequest = self.onClientDisconnectRequest,
            onError = self.onClientError
        )

        self.server.createObserver(
            onConnectionConfirm = self.onConnectionConfirm,
            onDisconnectRequest = self.onServerDisconnectRequest,
            onError=self.onServerError
        )

    def onConnectionRequest(self, pdu: X224ConnectionRequestPDU):
        """
        Log the connection cookie and handle connection protocols.
        :param pdu: the connection request
        """

        parser = NegotiationRequestParser()
        self.originalRequest = parser.parse(pdu.payload)
        self.state.requestedProtocols = self.originalRequest.requestedProtocols

        if self.originalRequest.cookie:
            self.log.info("%(cookie)s", {"cookie": self.originalRequest.cookie.decode()})
        else:
            self.log.info("No cookie for this connection")

        chosenProtocols = self.originalRequest.requestedProtocols

        if chosenProtocols is not None:
            # Only SSL is implemented, so remove other protocol flags
            chosenProtocols &= NegotiationProtocols.SSL

        modifiedRequest = NegotiationRequestPDU(
            self.originalRequest.cookie,
            self.originalRequest.flags,
            chosenProtocols,
            self.originalRequest.correlationFlags,
            self.originalRequest.correlationID,
        )

        payload = parser.write(modifiedRequest)
        defer(self.connectToServer(payload))

    async def connectToServer(self, payload: bytes):
        """
        Awaits the coroutine that connects to the server.
        :param payload: the connection request payload
        """
        await self.connector
        self.server.sendConnectionRequest(payload = payload)

    def onConnectionConfirm(self, pdu: X224ConnectionConfirmPDU):
        """
        Execute a startTLS if the SSL protocol was selected.
        :param _: the connection confirm PDU
        """

        # X224 Response
        protocols = NegotiationProtocols.SSL if self.originalRequest.tlsSupported else NegotiationProtocols.NONE

        parser = NegotiationResponseParser()
        response = parser.parse(pdu.payload)
        if response.type == NegotiationType.TYPE_RDP_NEG_FAILURE:
            self.log.info("The server failed the negotiation. Error: %(error)s", {"error": NegotiationFailureCode.getMessage(response.failureCode)})
            return

        # TODO: cleanup
        payload = parser.write(NegotiationResponsePDU(NegotiationType.TYPE_RDP_NEG_RSP, 0x00, protocols))
        self.client.sendConnectionConfirm(payload, source=0x1234)

        if self.originalRequest.tlsSupported:
            self.startTLSCallback()
            self.state.useTLS = True

    def onClientDisconnectRequest(self, pdu: X224DisconnectRequestPDU):
        self.server.sendPDU(pdu)

    def onServerDisconnectRequest(self, pdu: X224DisconnectRequestPDU):
        self.client.sendPDU(pdu)

    def onClientError(self, pdu: X224ErrorPDU):
        self.server.sendPDU(pdu)

    def onServerError(self, pdu: X224ErrorPDU):
        self.client.sendPDU(pdu)