#
# This file is part of the PyRDP project.
# Copyright (C) 2021, 2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging
import codecs
import secrets

from pyrdp.enum import NTLMSSPMessageType
from pyrdp.layer import SegmentationObserver, IntermediateLayer
from pyrdp.logging import LOGGER_NAMES
from pyrdp.logging.formatters import NTLMSSPHashFormatter
from pyrdp.parser import NTLMSSPParser
from pyrdp.pdu import NTLMSSPPDU, NTLMSSPChallengePDU, NTLMSSPAuthenticatePDU
from pyrdp.security import NTLMSSPState


class NLAHandler(SegmentationObserver):
    """
    Handles NLA packets by forwarding them transparently, using the onUnknownHeader event from SegmentationObserver.
    The event will be triggered when packets are sent that are neither fast-path nor TPKT (i.e: NLA).
    This also logs the hash of NLA connection attempts.
    """

    def __init__(self, sink: IntermediateLayer, state: NTLMSSPState, log: logging.LoggerAdapter, ntlmCapture: bool = False, challenge: str = None):
        """
        Create a new NLA Handler.
        sink: layer to forward packets to.
        state: NTLMSSPState that is shared between both the client-facing handler and the server-facing handler.
        """

        super().__init__()
        self.sink = sink
        self.ntlmSSPState = state
        self.ntlmSSPParser = NTLMSSPParser()
        self.ntlmCapture = ntlmCapture
        self.challenge = challenge
        self.log = log

    def getChallenge(self):
        """
        Return configured challenge or a random 64-bit challenge
        """
        if self.challenge is None:
            challenge = b'%016x' % secrets.randbits(16 * 4)
        else:
            challenge = self.challenge
        return codecs.decode(challenge, 'hex')

    def onUnknownHeader(self, header, data: bytes):
        signatureOffset = self.ntlmSSPParser.findMessage(data)

        if signatureOffset != -1:
            message: NTLMSSPPDU = self.ntlmSSPParser.parse(data)

            if message.messageType == NTLMSSPMessageType.NEGOTIATE_MESSAGE and self.ntlmCapture:
                # Reset state on new negotiation to prevent stale state from previous connection
                # This fixes issue #465: silent connection errors on reconnection
                if not self.ntlmSSPState:
                    self.log.info("Creating new NTLMSSP state for NLA capture")
                    self.ntlmSSPState = NTLMSSPState()
                else:
                    # Clear any stale authentication data from previous connection
                    self.log.debug("Resetting NTLMSSP state for new negotiation")
                    self.ntlmSSPState.authenticate = None

                rawChallenge = self.getChallenge()
                self.log.debug("NTLMSSP Negotiation")
                challenge: NTLMSSPChallengePDU = NTLMSSPChallengePDU(rawChallenge)

                self.ntlmSSPState.setMessage(message)
                self.ntlmSSPState.setMessage(challenge)
                self.ntlmSSPState.challenge.serverChallenge = rawChallenge
                data = self.ntlmSSPParser.writeNTLMSSPChallenge('WINNT', rawChallenge)
            elif message.messageType == NTLMSSPMessageType.AUTHENTICATE_MESSAGE:
                # Validate state before using it
                if not self.ntlmSSPState or not self.ntlmSSPState.challenge:
                    self.log.error("Received AUTHENTICATE message without prior CHALLENGE. Connection state may be corrupted.")
                    # Still forward the message but log the error for debugging
                    self.sink.sendBytes(data)
                    return

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

                self.ntlmSSPState.setMessage(message)
            else:
                # For other message types, just update state
                if self.ntlmSSPState:
                    self.ntlmSSPState.setMessage(message)

        self.sink.sendBytes(data)
