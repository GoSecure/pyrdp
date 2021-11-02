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

    def write(self, workstation: str) -> bytes:
        stream = BytesIO()
        
        workstation = workstation.encode('utf-16le')
        nameLen = len(workstation)
        pairsLen = self.writePayload(stream, workstation, nameLen)
        
        stream.write(b'NTLMSSP\x00')                                                    # signature
        stream.write(Uint32LE.pack(self.messageType))                                   # message type
        stream.write(Uint16LE.pack(nameLen))                                            # workstation length
        stream.write(Uint16LE.pack(nameLen))                                            # workstation max length
        stream.write(Uint32LE.pack(NTLMSSPChallengeType.WORKSTATION_BUFFER_OFFSET))     # workstation buffer offset
        stream.write(Uint32LE.pack(NTLMSSPChallengeType.NEGOTIATE_FLAGS))               # negotiate flags
        stream.write(self.serverChallenge)                                              # server challenge
        stream.write(Uint64LE.pack(0))                                                  # reserved
        stream.write(Uint16LE.pack(pairsLen))                                           # target info len
        stream.write(Uint16LE.pack(pairsLen))                                           # target info max len
        stream.write(Uint32LE.pack(NTLMSSPChallengeType.WORKSTATION_BUFFER_OFFSET + nameLen)) # target info buffer offset
        stream.write(Uint8.pack(NTLMSSPChallengeVersion.NEG_PROD_MAJOR_VERSION_HIGH))   # product major version
        stream.write(Uint8.pack(NTLMSSPChallengeVersion.NEG_PROD_MINOR_VERSION_LOW))    # product minor version
        stream.write(Uint16LE.pack(NTLMSSPChallengeVersion.NEG_PROD_VERSION_BUILT))     # product build
        stream.write(Uint8.pack(0))                                                     # reserved
        stream.write(Uint8.pack(0))                                                     # reserved
        stream.write(Uint8.pack(0))                                                     # reserved
        stream.write(Uint8.pack(NTLMSSPChallengeVersion.NEG_NTLM_REVISION_CURRENT))     # NTLM revision current
        
        self.writeASN(stream)
        return stream.getvalue()
    
    def writeASN(self, stream: BytesIO):
        message = stream.getvalue()
        messageLen = len(message)

        # ASN.1 description
        # SEQUENCE (2 elem)
        #   [0] (1 elem)
        #     INTEGER 5
        #   [1] (1 elem)
        #     SEQUENCE (1 elem)
        #       SEQUENCE (1 elem)
        #         [0] (1 elem)
        #           OCTET STRING (...)
        stream.seek(0)
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(messageLen + 25))
        stream.write(b'\xa0' + ber.writeLength(3))
        stream.write(ber.writeInteger(NTLMSSPChallengeVersion.CREDSSP_VERSION)) # CredSSP version
        stream.write(b'\xa1' + ber.writeLength(messageLen + 16))
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(messageLen + 12))
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(messageLen + 8))
        stream.write(b'\xa0' + ber.writeLength(messageLen + 4))
        stream.write(ber.writeOctetString(message))

    def writePayload(self, stream: BytesIO, workstation: bytes, length: int):
        pairsLen = 0
        offset   = stream.tell()

        stream.seek(NTLMSSPChallengeType.WORKSTATION_BUFFER_OFFSET)
        stream.write(workstation)
        pairsLen += stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS_ID))
        pairsLen += stream.write(Uint16LE.pack(length))
        pairsLen += stream.write(workstation)
        pairsLen += stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS1_ID))
        pairsLen += stream.write(Uint16LE.pack(length))
        pairsLen += stream.write(workstation)
        pairsLen += stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS2_ID))
        pairsLen += stream.write(Uint16LE.pack(length))
        pairsLen += stream.write(workstation)
        pairsLen += stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS3_ID))
        pairsLen += stream.write(Uint16LE.pack(length))
        pairsLen += stream.write(workstation)
        pairsLen += stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS5_ID))
        pairsLen += stream.write(Uint16LE.pack(length))
        pairsLen += stream.write(workstation)
        pairsLen += stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS6_ID))
        pairsLen += stream.write(Uint16LE.pack(0))
        stream.seek(offset)

        return pairsLen

class NTLMSSPAuthenticatePDU(NTLMSSPPDU):
    def __init__(self, user: str, domain: str, proof: bytes, response: bytes):
        super().__init__(NTLMSSPMessageType.AUTHENTICATE_MESSAGE)
        self.user = user
        self.domain = domain
        self.proof = proof
        self.response = response
