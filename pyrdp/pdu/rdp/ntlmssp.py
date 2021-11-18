#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import ber
from pyrdp.core.packing import Uint8, Uint16LE, Uint32LE, Uint64LE
from pyrdp.enum import NTLMSSPMessageType, NTLMSSPChallengeType, NTLMSSPChallengeVersion
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

class NTLMSSPChallengePayloadPDU(PDU):
    """
    Payload of CHALLENGE message containing a data array
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
    """
    def __init__(self, workstation: str):
        super().__init__()
        self.workstation = workstation

class NTLMSSPAuthenticatePDU(NTLMSSPPDU):
    def __init__(self, user: str, domain: str, proof: bytes, response: bytes):
        super().__init__(NTLMSSPMessageType.AUTHENTICATE_MESSAGE)
        self.user = user
        self.domain = domain
        self.proof = proof
        self.response = response

class NTLMSSPTSRequestPDU(PDU):
    """
    PDU for TSRequest structures used by CredSSP (client/server) for SPNEGO and Kerberos/NTLM messages
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685
    """
    def __init__(self, version: int, negoTokens: BytesIO):
        super().__init__()
        self.version = version
        self.negoTokens = negoTokens

