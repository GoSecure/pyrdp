#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import NTLMSSPMessageType
from pyrdp.pdu.pdu import PDU


class NTLMSSPPDU(PDU):
    def __init__(self, messageType: NTLMSSPMessageType):
        super().__init__()
        self.messageType = messageType


class NTLMSSPNegotiatePDU(NTLMSSPPDU):
    def __init__(self):
        super().__init__(NTLMSSPMessageType.NEGOTIATE_MESSAGE)


class NTLMSSPChallengePDU(NTLMSSPPDU):
    def __init__(self, serverChallenge: bytes):
        super().__init__(NTLMSSPMessageType.CHALLENGE_MESSAGE)
        self.serverChallenge = serverChallenge


class NTLMSSPAuthenticatePDU(NTLMSSPPDU):
    def __init__(self, user: str, domain: str, proof: bytes, response: bytes):
        super().__init__(NTLMSSPMessageType.AUTHENTICATE_MESSAGE)
        self.user = user
        self.domain = domain
        self.proof = proof
        self.response = response
