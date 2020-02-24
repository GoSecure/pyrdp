#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Dict, Optional

from Crypto.PublicKey import RSA

from pyrdp.enum import NegotiationProtocols, ParserMode
from pyrdp.layer import FastPathLayer, SecurityLayer, TLSSecurityLayer
from pyrdp.parser import createFastPathParser
from pyrdp.pdu import ClientChannelDefinition
from pyrdp.security import RC4CrypterProxy, SecuritySettings
from pyrdp.mitm import MITMConfig


class RDPMITMState:
    """
    State object for the RDP MITM. This is for data that needs to be shared across components.
    """

    def __init__(self, config: MITMConfig):
        self.requestedProtocols: Optional[NegotiationProtocols] = None
        """The original request protocols"""

        self.config = config
        """The MITM configuration."""

        self.useTLS = False
        """Whether the connection uses TLS or not"""

        self.securitySettings = SecuritySettings()
        """The security settings for the connection"""

        self.channelDefinitions: [ClientChannelDefinition] = []
        """The channel definitions from the client"""

        self.channelMap: Dict[int, str] = {}
        """Dictionary of channel names to channel IDs"""

        self.rc4RSAKey = RSA.generate(2048)
        """The RSA key for the RC4 key exchange"""

        self.crypters = {
            ParserMode.CLIENT: RC4CrypterProxy(RC4CrypterProxy.Mode.CLIENT),
            ParserMode.SERVER: RC4CrypterProxy(RC4CrypterProxy.Mode.SERVER)
        }
        """Crypters for the client and server side"""

        self.forwardInput = True
        """Whether input from the client should be forwarded to the server"""

        self.forwardOutput = True
        """Whether output from the server should be forwarded to the client"""

        self.loggedIn = False
        """Keep tracks of the client login status"""

        self.inputBuffer = ""
        """Used to store what the client types"""

        self.credentialsCandidate = ""
        """The potential client password"""

        self.shiftPressed = False
        """The current keyboard shift state"""

        self.capsLockOn = False
        """The current keyboard capsLock state"""

        self.ctrlPressed = False
        """The current keybaord ctrl state"""

        self.securitySettings.addObserver(self.crypters[ParserMode.CLIENT])
        self.securitySettings.addObserver(self.crypters[ParserMode.SERVER])

    def createSecurityLayer(self, mode: ParserMode, isVirtualChannel: bool) -> SecurityLayer:
        """
        Create a security layer.
        :param mode: the mode of the security layer (client or server)
        :param isVirtualChannel: True if the security layer is for a virtual channel, False if it's for slow-path data.
        """

        if self.useTLS:
            layer = TLSSecurityLayer()
            layer.securityHeaderExpected = not isVirtualChannel
            return layer
        else:
            crypter = self.crypters[mode]
            return SecurityLayer.create(self.securitySettings.encryptionMethod, crypter)

    def createFastPathLayer(self, mode: ParserMode) -> FastPathLayer:
        """
        Create a fast-path layer.
        :param mode: the mode of the layer (client or server)
        """

        parser = createFastPathParser(self.useTLS, self.securitySettings.encryptionMethod, self.crypters[mode], mode)
        return FastPathLayer(parser)
