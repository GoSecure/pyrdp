#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO
from typing import Callable, Dict

from pyrdp.core import Uint16LE, Uint32LE
from pyrdp.parser.parser import Parser
from pyrdp.pdu import NTLMSSPChallengePDU, NTLMSSPAuthenticatePDU, NTLMSSPNegotiatePDU, NTLMSSPPDU


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
        stream = BytesIO(data)
        signature = stream.read(8)
        messageType = Uint32LE.unpack(stream)

        return self.handlers[messageType](data, stream)

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
        targetNameFields = stream.read(8)
        negotiateFlags = stream.read(4)
        serverChallenge = stream.read(8)
        reserved = stream.read(8)
        targetInfoFields = stream.read(8)
        version = stream.read(8)

        targetName = self.parseField(data, targetNameFields)
        targetInfo = self.parseField(data, targetInfoFields)
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
