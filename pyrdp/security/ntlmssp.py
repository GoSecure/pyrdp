#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Optional

from pyrdp.enum import NTLMSSPMessageType
from pyrdp.pdu import NTLMSSPAuthenticatePDU, NTLMSSPChallengePDU, NTLMSSPNegotiatePDU, NTLMSSPPDU


class NTLMSSPState:
    def __init__(self):
        self.negotiate: Optional[NTLMSSPNegotiatePDU] = None
        self.challenge: Optional[NTLMSSPChallengePDU] = None
        self.authenticate: Optional[NTLMSSPAuthenticatePDU] = None

    def setMessage(self, pdu: NTLMSSPPDU):
        if pdu.messageType == NTLMSSPMessageType.NEGOTIATE_MESSAGE:
            self.negotiate = pdu
        elif pdu.messageType == NTLMSSPMessageType.CHALLENGE_MESSAGE:
            self.challenge = pdu
        else:
            self.authenticate = pdu
