#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO
from typing import Callable, Dict

from pyrdp.core import ber, Uint8, Uint16LE, Uint32LE, Uint64LE
from pyrdp.parser.parser import Parser
from pyrdp.pdu import NTLMSSPChallengePayloadPDU, NTLMSSPTSRequestPDU, NTLMSSPChallengePDU, NTLMSSPAuthenticatePDU, \
    NTLMSSPNegotiatePDU, NTLMSSPPDU
from pyrdp.enum import NTLMSSPMessageType, NTLMSSPChallengeType, NTLMSSPChallengeVersion


class NTLMSSPParser(Parser):
    """
    Parser for NLA/NTLMSSP
    TODO: Add other fields to PDUs if necessary
    TODO: Implement write if necessary
    """

    def __init__(self):
        self.handlers: Dict[int, Callable[[bytes, BytesIO], NTLMSSPPDU]] = {
            1: self.parseNTLMSSPNegotiate,
            2: self.parseNTLMSSPChallenge,
            3: self.parseNTLMSSPAuthenticate
        }

    def findMessage(self, data: bytes) -> int:
        """
        Check if data contains an NTLMSSP message.
        Returns the offset in data of the start of the message or -1 otherwise.
        """
        return data.find(b"NTLMSSP\x00")

    def doParse(self, data: bytes) -> NTLMSSPPDU:
        sigOffset = self.findMessage(data)
        stream    = BytesIO(data[sigOffset:])
        signature = stream.read(8)
        messageType = Uint32LE.unpack(stream)
        return self.handlers[messageType](stream.getvalue(), stream)

    def parseField(self, data: bytes, fields: bytes) -> bytes:
        length = Uint16LE.unpack(fields[0: 2])
        offset = Uint32LE.unpack(fields[4: 8])

        if length != 0:
            return data[offset : offset + length]
        else:
            return b""

    def parseNTLMSSPNegotiate(self, data: bytes, stream: BytesIO) -> NTLMSSPNegotiatePDU:
        return NTLMSSPNegotiatePDU()

    def parseNTLMSSPChallenge(self, data: bytes, stream: BytesIO) -> NTLMSSPChallengePDU:
        workstationLen = stream.read(2)
        workstationMaxLen = stream.read(2)
        workstationBufferOffset = stream.read(4)
        negotiateFlags = stream.read(4)
        serverChallenge = stream.read(8)
        reserved = stream.read(8)
        targetInfoLen = stream.read(2)
        targetInfoMaxLen = stream.read(2)
        targetInfoBufferOffset = stream.read(4)
        version = stream.read(4)
        reserved = stream.read(3)
        revisionCurrent = stream.read(1)

        return NTLMSSPChallengePDU(serverChallenge)

    def parseNTLMSSPAuthenticate(self, data: bytes, stream: BytesIO) -> NTLMSSPAuthenticatePDU:
        lmChallengeResponseFields = stream.read(8)
        ntChallengeResponseFields = stream.read(8)
        domainNameFields = stream.read(8)
        userNameFields = stream.read(8)
        workstationFields = stream.read(8)
        encryptedRandomSessionKeyFields = stream.read(8)
        negotiationFlags = stream.read(4)
        version = stream.read(8)
        mic = stream.read(16)

        lmChallengeResponse = self.parseField(data, lmChallengeResponseFields)
        ntChallengeResponse = self.parseField(data, ntChallengeResponseFields)
        domain = self.parseField(data, domainNameFields).decode("utf-16le")
        user = self.parseField(data, userNameFields).decode("utf-16le")
        workstation = self.parseField(data, workstationFields)
        encryptedRandomSessionKey = self.parseField(data, encryptedRandomSessionKeyFields)

        proof = ntChallengeResponse[: 16]
        response = ntChallengeResponse[16 :]

        return NTLMSSPAuthenticatePDU(user, domain, proof, response)

    def parseNTLMSSPTSRequest(self, data: bytes, stream: BytesIO) -> NTLMSSPTSRequestPDU:
        if not ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True):
            raise UnknownPDUTypeError("Invalid BER tag (%d expected)" % ber.Tag.BER_TAG_SEQUENCE)

        length = ber.readLength(stream)
        if length > len(stream.getvalue()):
            raise ParsingError("Invalid size for TSRequest (got %d, %d bytes left)" % (length, len(stream.getvalue())))
        
        version = None
        negoTokens = None
        
        # [0] version
        if not ber.readContextualTag(stream, 0, True):
            return NTLMSSPTSRequestPDU(version, negoTokens, data)
        version = ber.readInteger(stream)
        
        # [1] negoTokens
        if not ber.readContextualTag(stream, 1, True):
            return NTLMSSPTSRequestPDU(version, negoTokens, data)
        ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True) # SEQUENCE OF NegoDataItem
        ber.readLength(stream)
        ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True) # NegoDataItem
        ber.readLength(stream)
        ber.readContextualTag(stream, 0, True)
        
        negoTokens = BytesIO(ber.readOctetString(stream))            # NegoData
        return NTLMSSPTSRequestPDU(version, negoTokens)

    def parseNTLMSSPChallengePayload(self, data: bytes, stream: BytesIO, workstationLen: int) -> NTLMSSPChallengePayloadPDU:
        stream.read(workstationLen)
        return NTLMSSPChallengePayloadPDU(workstation)

    def writeNTLMSSPChallenge(self, workstation: str, serverChallenge: bytes) -> bytes:
        stream = BytesIO()
        substream = BytesIO()
        
        workstation = workstation.encode('utf-16le')
        nameLen = len(workstation)
        pairsLen = self.writeNTLMSSPChallengePayload(substream, workstation)
        
        substream.write(b'NTLMSSP\x00')                                                    # signature
        substream.write(Uint32LE.pack(NTLMSSPMessageType.CHALLENGE_MESSAGE))               # message type
        substream.write(Uint16LE.pack(nameLen))                                            # workstation length
        substream.write(Uint16LE.pack(nameLen))                                            # workstation max length
        substream.write(Uint32LE.pack(NTLMSSPChallengeType.WORKSTATION_BUFFER_OFFSET))     # workstation buffer offset
        substream.write(Uint32LE.pack(NTLMSSPChallengeType.NEGOTIATE_FLAGS))               # negotiate flags
        substream.write(serverChallenge)                                                   # server challenge
        substream.write(Uint64LE.pack(0))                                                  # reserved
        substream.write(Uint16LE.pack(pairsLen))                                           # target info len
        substream.write(Uint16LE.pack(pairsLen))                                           # target info max len
        substream.write(Uint32LE.pack(NTLMSSPChallengeType.WORKSTATION_BUFFER_OFFSET + nameLen)) # target info buffer offset
        substream.write(Uint8.pack(NTLMSSPChallengeVersion.NEG_PROD_MAJOR_VERSION_HIGH))   # product major version
        substream.write(Uint8.pack(NTLMSSPChallengeVersion.NEG_PROD_MINOR_VERSION_LOW))    # product minor version
        substream.write(Uint16LE.pack(NTLMSSPChallengeVersion.NEG_PROD_VERSION_BUILT))     # product build
        substream.write(Uint8.pack(0))                                                     # reserved
        substream.write(Uint8.pack(0))                                                     # reserved
        substream.write(Uint8.pack(0))                                                     # reserved
        substream.write(Uint8.pack(NTLMSSPChallengeVersion.NEG_NTLM_REVISION_CURRENT))     # NTLM revision current
        
        self.writeNTLMSSPTSRequest(stream, NTLMSSPChallengeVersion.CREDSSP_VERSION, substream.getvalue())
        return stream.getvalue()

    def writeNTLMSSPTSRequest(self, stream: BytesIO, version: int, negoTokens: bytes):
        negoLen = len(negoTokens)
        
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(negoLen + 25))
        stream.write(ber.writeContextualTag(0, 3))
        stream.write(ber.writeInteger(version)) # CredSSP version
        stream.write(ber.writeContextualTag(1, negoLen + 16))
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(negoLen + 12))
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(negoLen + 8))
        stream.write(ber.writeContextualTag(0, negoLen + 4))
        stream.write(ber.writeOctetString(negoTokens))

    def writeNTLMSSPChallengePayload(self, stream: BytesIO, workstation: str) -> int:
        length   = len(workstation)

        stream.seek(NTLMSSPChallengeType.WORKSTATION_BUFFER_OFFSET)
        stream.write(workstation)

        pairsLen = stream.tell()
        stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS_ID))
        stream.write(Uint16LE.pack(length))
        stream.write(workstation)
        stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS1_ID))
        stream.write(Uint16LE.pack(length))
        stream.write(workstation)
        stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS2_ID))
        stream.write(Uint16LE.pack(length))
        stream.write(workstation)
        stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS3_ID))
        stream.write(Uint16LE.pack(length))
        stream.write(workstation)
        stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS5_ID))
        stream.write(Uint16LE.pack(length))
        stream.write(workstation)
        stream.write(Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS6_ID))
        stream.write(Uint16LE.pack(0))
        pairsLen = stream.tell() - pairsLen
        stream.seek(0)
        
        return pairsLen
