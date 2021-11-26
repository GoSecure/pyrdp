#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO
from typing import Callable, Dict

from pyrdp.core import ber, Uint8, Uint16LE, Uint32LE, Uint64LE
from pyrdp.exceptions import UnknownPDUTypeError, ParsingError
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
        workstationLen = Uint16LE.unpack(stream)
        workstationMaxLen = Uint16LE.unpack(stream)
        workstationBufferOffset = Uint32LE.unpack(stream)
        negotiateFlags = Uint32LE.unpack(stream)
        serverChallenge = stream.read(8)
        reserved = Uint64LE.unpack(stream)
        targetInfoLen = Uint16LE.unpack(stream)
        targetInfoMaxLen = Uint16LE.unpack(stream)
        targetInfoBufferOffset = Uint32LE.unpack(stream)
        version = Uint32LE.unpack(stream)
        reserved = stream.read(3)
        revisionCurrent = Uint8.unpack(stream)

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
        ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True)  # SEQUENCE OF NegoDataItem
        ber.readLength(stream)
        ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True)  # NegoDataItem
        ber.readLength(stream)
        ber.readContextualTag(stream, 0, True)

        negoTokens = BytesIO(ber.readOctetString(stream))  # NegoData
        return NTLMSSPTSRequestPDU(version, negoTokens)

    def parseNTLMSSPChallengePayload(self, data: bytes, stream: BytesIO, workstationLen: int) -> NTLMSSPChallengePayloadPDU:
        workstation = stream.read(workstationLen)
        return NTLMSSPChallengePayloadPDU(workstation)

    def writeNTLMSSPChallenge(self, workstation: str, serverChallenge: bytes) -> bytes:
        stream = BytesIO()
        substream = BytesIO()

        workstation = workstation.encode('utf-16le')
        nameLen = len(workstation)
        pairsLen = self.writeNTLMSSPChallengePayload(substream, workstation)

        """
        CHALLENGE_MESSAGE structure
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
        """
        substream.write(b'NTLMSSP\x00')
        Uint32LE.pack(NTLMSSPMessageType.CHALLENGE_MESSAGE, substream)
        Uint16LE.pack(nameLen, substream)
        Uint16LE.pack(nameLen, substream)
        Uint32LE.pack(NTLMSSPChallengeType.WORKSTATION_BUFFER_OFFSET, substream)
        Uint32LE.pack(NTLMSSPChallengeType.NEGOTIATE_FLAGS, substream)
        substream.write(serverChallenge)
        Uint64LE.pack(0, substream)
        Uint16LE.pack(pairsLen, substream)
        Uint16LE.pack(pairsLen, substream)
        Uint32LE.pack(NTLMSSPChallengeType.WORKSTATION_BUFFER_OFFSET + nameLen, substream)
        Uint8.pack(NTLMSSPChallengeVersion.NEG_PROD_MAJOR_VERSION_HIGH, substream)
        Uint8.pack(NTLMSSPChallengeVersion.NEG_PROD_MINOR_VERSION_LOW, substream)
        Uint16LE.pack(NTLMSSPChallengeVersion.NEG_PROD_VERSION_BUILT, substream)
        Uint8.pack(0, substream)
        Uint8.pack(0, substream)
        Uint8.pack(0, substream)
        Uint8.pack(NTLMSSPChallengeVersion.NEG_NTLM_REVISION_CURRENT, substream)

        self.writeNTLMSSPTSRequest(stream, NTLMSSPChallengeVersion.CREDSSP_VERSION, substream.getvalue())
        return stream.getvalue()

    def writeNTLMSSPTSRequest(self, stream: BytesIO, version: int, negoTokens: bytes):
        """
        Write NTLMSSP TSRequest for NEGOTIATION/CHALLENGE/AUTHENTICATION messages
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685
        """
        negoLen = len(negoTokens)

        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(negoLen + 25))
        stream.write(ber.writeContextualTag(0, 3))
        stream.write(ber.writeInteger(version))  # CredSSP version
        stream.write(ber.writeContextualTag(1, negoLen + 16))
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(negoLen + 12))
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(negoLen + 8))
        stream.write(ber.writeContextualTag(0, negoLen + 4))
        stream.write(ber.writeOctetString(negoTokens))

    def writeNTLMSSPChallengePayload(self, stream: BytesIO, workstation: str) -> int:
        """
        Write CHALLENGE message payload and AV_PAIRS
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
        """
        length = len(workstation)

        stream.seek(NTLMSSPChallengeType.WORKSTATION_BUFFER_OFFSET)
        stream.write(workstation)

        pairsLen = stream.tell()
        Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS_ID, stream)
        Uint16LE.pack(length, stream)
        stream.write(workstation)
        Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS1_ID, stream)
        Uint16LE.pack(length, stream)
        stream.write(workstation)
        Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS2_ID, stream)
        Uint16LE.pack(length, stream)
        stream.write(workstation)
        Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS3_ID, stream)
        Uint16LE.pack(length, stream)
        stream.write(workstation)
        Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS5_ID, stream)
        Uint16LE.pack(length, stream)
        stream.write(workstation)
        Uint16LE.pack(NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS6_ID, stream)
        Uint16LE.pack(0, stream)
        pairsLen = stream.tell() - pairsLen
        stream.seek(0)

        return pairsLen

