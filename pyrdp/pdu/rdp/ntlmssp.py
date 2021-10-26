#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import NTLMSSPMessageType, NTLMSSPChallengeType
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
        NULL = '\x00'
        workstationName = 'WINNT'.encode('utf-16le').decode('latin-1') # default Workstation Name to be used during challenge

        self.serverChallenge = serverChallenge
        self.fields = {}
        self.fields['packetStartASN'] =                            '\x30'
        self.fields['packetStartASNLenOfLen'] =                    '\x81'
        self.fields['packetStartASNStr'] =                         NULL
        self.fields['packetStartASNTag0'] =                        NTLMSSPChallengeType.PARSER_ASN_TAG.to_bytes(1,'little').decode('latin-1')
        self.fields['packetStartASNTag0Len'] =                     '\x03'
        self.fields['packetStartASNTag0Len2'] =                    '\x02'
        self.fields['packetStartASNTag0Len3'] =                    '\x01'
        self.fields['packetStartASNTag0CredSSPVersion'] =          NTLMSSPChallengeType.CREDSSP_VERSION.to_bytes(1,'little').decode('latin-1')
        self.fields['parserHeadASNID1'] =                          NTLMSSPChallengeType.PARSER_ASN_ID.to_bytes(1,'little').decode('latin-1')
        self.fields['parserHeadASNLenOfLen1'] =                    '\x81'
        self.fields['parserHeadASNLen1'] =                         NULL
        self.fields['messageIDASNID'] =                            '\x30'
        self.fields['messageIDASNLen'] =                           '\x81'
        self.fields['messageIDASNLen2'] =                          NULL
        self.fields['opHeadASNID'] =                               '\x30'
        self.fields['opHeadASNIDLenOfLen'] =                       '\x81'
        self.fields['opHeadASNIDLen'] =                            NULL
        self.fields['statusASNID'] =                               NTLMSSPChallengeType.STATUS_ASN_ID.to_bytes(1,'little').decode('latin-1')
        self.fields['matchedDN'] =                                 '\x81'
        self.fields['asnLen01'] =                                  NULL
        self.fields['sequenceHeader'] =                            NTLMSSPChallengeType.SEQUENCE_HEADER.to_bytes(1,'little').decode('latin-1')
        self.fields['sequenceHeaderLenOfLen'] =                    '\x81'
        self.fields['sequenceHeaderLen'] =                         NULL
        self.fields['signature'] =                                 'NTLMSSP' + NULL
        self.fields['messageType'] =                               self.messageType.to_bytes(4,'little').decode('latin-1')
        self.fields['workstationLen'] =                            NULL * 2
        self.fields['workstationMaxLen'] =                         NULL * 2
        self.fields['workstationBuffOffset'] =                     NULL * 4
        self.fields['negotiateFlags'] =                            NTLMSSPChallengeType.NEGOTIATE_FLAGS.to_bytes(4,'little').decode('latin-1')
        self.fields['serverChallenge'] =                           serverChallenge.decode('latin-1')
        self.fields['reserved'] =                                  NULL * 8
        self.fields['targetInfoLen'] =                             NULL * 2
        self.fields['targetInfoMaxLen'] =                          NULL * 2
        self.fields['targetInfoBuffOffset'] =                      NULL * 4
        self.fields['negTokenInitSeqMechMessageVersionHigh'] =     NTLMSSPChallengeType.NEG_TOKEN_INIT_SEQ_MECH_MESSAGE_VERSION_HIGH.to_bytes(1,'little').decode('latin-1')
        self.fields['negTokenInitSeqMechMessageVersionLow'] =      NTLMSSPChallengeType.NEG_TOKEN_INIT_SEQ_MECH_MESSAGE_VERSION_LOW.to_bytes(1,'little').decode('latin-1')
        self.fields['negTokenInitSeqMechMessageVersionBuilt'] =    NTLMSSPChallengeType.NEG_TOKEN_INIT_SEQ_MECH_MESSAGE_VERSION_BUILT.to_bytes(2,'little').decode('latin-1')
        self.fields['negTokenInitSeqMechMessageVersionReserved'] = NTLMSSPChallengeType.NEG_TOKEN_INIT_SEQ_MECH_MESSAGE_VERSION_RESERVED.to_bytes(3,'little').decode('latin-1')
        self.fields['negTokenInitSeqMechMessageVersionNTLMType'] = NTLMSSPChallengeType.NEG_TOKEN_INIT_SEQ_MECH_MESSAGE_VERSION_NTLM_TYPE.to_bytes(1,'little').decode('latin-1')
        self.fields['workstationName'] =                           workstationName
        self.fields['ntlmsspNTLMChallengeAVPairsId'] =             NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS_ID.to_bytes(2,'little').decode('latin-1')
        self.fields['ntlmsspNTLMChallengeAVPairsLen'] =            NULL * 2
        self.fields['ntlmsspNTLMChallengeAVPairsUnicodeStr'] =     workstationName
        self.fields['ntlmsspNTLMChallengeAVPairs1Id'] =            NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS1_ID.to_bytes(2,'little').decode('latin-1')
        self.fields['ntlmsspNTLMChallengeAVPairs1Len'] =           NULL * 2
        self.fields['ntlmsspNTLMChallengeAVPairs1UnicodeStr'] =    workstationName
        self.fields['ntlmsspNTLMChallengeAVPairs2Id'] =            NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS2_ID.to_bytes(2,'little').decode('latin-1')
        self.fields['ntlmsspNTLMChallengeAVPairs2Len'] =           NULL * 2
        self.fields['ntlmsspNTLMChallengeAVPairs2UnicodeStr'] =    workstationName
        self.fields['ntlmsspNTLMChallengeAVPairs3Id'] =            NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS3_ID.to_bytes(2,'little').decode('latin-1')
        self.fields['ntlmsspNTLMChallengeAVPairs3Len'] =           NULL * 2
        self.fields['ntlmsspNTLMChallengeAVPairs3UnicodeStr'] =    workstationName
        self.fields['ntlmsspNTLMChallengeAVPairs5Id'] =            NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS5_ID.to_bytes(2,'little').decode('latin-1')
        self.fields['ntlmsspNTLMChallengeAVPairs5Len'] =           NULL * 2
        self.fields['ntlmsspNTLMChallengeAVPairs5UnicodeStr'] =    workstationName
        self.fields['ntlmsspNTLMChallengeAVPairs6Id'] =            NTLMSSPChallengeType.NTLMSSP_NTLM_CHALLENGE_AV_PAIRS6_ID.to_bytes(2,'little').decode('latin-1')
        self.fields['ntlmsspNTLMChallengeAVPairs6Len'] =           NULL * 2

        calculateOffsetWorkstation = self.fields['signature'] + \
            self.fields['messageType'] + \
            self.fields["workstationLen"] + \
            self.fields["workstationMaxLen"] + \
            self.fields["workstationBuffOffset"] + \
            self.fields["negotiateFlags"] + \
            self.fields["serverChallenge"] + \
            self.fields["reserved"] + \
            self.fields["targetInfoLen"] + \
            self.fields["targetInfoMaxLen"] + \
            self.fields["targetInfoBuffOffset"] + \
            self.fields["negTokenInitSeqMechMessageVersionHigh"] + \
            self.fields["negTokenInitSeqMechMessageVersionLow"] + \
            self.fields["negTokenInitSeqMechMessageVersionBuilt"] + \
            self.fields["negTokenInitSeqMechMessageVersionReserved"] + \
            self.fields["negTokenInitSeqMechMessageVersionNTLMType"]
        calculateLenAvpairs = self.fields["ntlmsspNTLMChallengeAVPairsId"] + \
            self.fields["ntlmsspNTLMChallengeAVPairsLen"] + \
            self.fields["ntlmsspNTLMChallengeAVPairsUnicodeStr"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs1Id"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs1Len"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs1UnicodeStr"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs2Id"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs2Len"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs2UnicodeStr"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs3Id"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs3Len"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs3UnicodeStr"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs5Id"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs5Len"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs5UnicodeStr"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs6Id"] + \
            self.fields["ntlmsspNTLMChallengeAVPairs6Len"]

        # Length and offset calculation
        NTLMMessageLen = calculateOffsetWorkstation + workstationName + calculateLenAvpairs
        self.fields["sequenceHeaderLen"]    = len(NTLMMessageLen).to_bytes(1,'big')
        self.fields["asnLen01"]             = (len(NTLMMessageLen) + 3).to_bytes(1,'big')
        self.fields["opHeadASNIDLen"]       = (len(NTLMMessageLen) + 6).to_bytes(1,'big')
        self.fields["messageIDASNLen2"]     = (len(NTLMMessageLen) + 9).to_bytes(1,'big')
        self.fields["parserHeadASNLen1"]    = (len(NTLMMessageLen) + 12).to_bytes(1,'big')
        self.fields["packetStartASNStr"]    = (len(NTLMMessageLen) + 20).to_bytes(1,'big')

        self.fields["workstationBuffOffset"]= len(calculateOffsetWorkstation).to_bytes(4,'little')
        self.fields["workstationLen"]       = len(workstationName).to_bytes(2,'little')
        self.fields["workstationMaxLen"]    = len(workstationName).to_bytes(2,'little')

        self.fields["targetInfoLen"]        = len(calculateLenAvpairs).to_bytes(2,'little')
        self.fields["targetInfoMaxLen"]     = len(calculateLenAvpairs).to_bytes(2,'little')
        self.fields["targetInfoBuffOffset"] = len(calculateOffsetWorkstation + workstationName).to_bytes(4,'little')

        self.fields["ntlmsspNTLMChallengeAVPairs5Len"] = len(self.fields["ntlmsspNTLMChallengeAVPairs5UnicodeStr"]).to_bytes(2,'little')
        self.fields["ntlmsspNTLMChallengeAVPairs3Len"] = len(self.fields["ntlmsspNTLMChallengeAVPairs3UnicodeStr"]).to_bytes(2,'little')
        self.fields["ntlmsspNTLMChallengeAVPairs2Len"] = len(self.fields["ntlmsspNTLMChallengeAVPairs2UnicodeStr"]).to_bytes(2,'little')
        self.fields["ntlmsspNTLMChallengeAVPairs1Len"] = len(self.fields["ntlmsspNTLMChallengeAVPairs1UnicodeStr"]).to_bytes(2,'little')
        self.fields["ntlmsspNTLMChallengeAVPairsLen"]  = len(self.fields["ntlmsspNTLMChallengeAVPairsUnicodeStr"]).to_bytes(2,'little')

    def __bytes__(self):
        data = bytes()
        for _,v in self.fields.items():
            b = v
            if type(b) == str:
                b = b.encode('latin-1')
            data += b
        return data

class NTLMSSPAuthenticatePDU(NTLMSSPPDU):
    def __init__(self, user: str, domain: str, proof: bytes, response: bytes):
        super().__init__(NTLMSSPMessageType.AUTHENTICATE_MESSAGE)
        self.user = user
        self.domain = domain
        self.proof = proof
        self.response = response
