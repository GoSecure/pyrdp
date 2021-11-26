#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import IntEnum

class NTLMSSPMessageType(IntEnum):
    NEGOTIATE_MESSAGE = 1
    CHALLENGE_MESSAGE = 2
    AUTHENTICATE_MESSAGE = 3

class NTLMSSPChallengeType(IntEnum):
    WORKSTATION_BUFFER_OFFSET = 0x38
    
    # http://davenport.sourceforge.net/ntlm.html#theNtlmFlags
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832
    # Flags: (
    # NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_NTLM |
    # NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_TARGET_TYPE_SERVER | NTLMSSP_NEGOTIATE_LM_KEY |
    # NTLMSSP_NEGOTIATE_TARGET_INFO | r | NTLMSSP_NEGOTIATE_128 |
    # NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_56
    # )
    NEGOTIATE_FLAGS = 0xE28A8215

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS_ID  = 0x0002 # MsvAvNbDomainName
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS1_ID = 0x0001 # MsvAvNbComputerName
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS2_ID = 0x0004 # MsvAvDnsDomainName
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS3_ID = 0x0003 # MsvAvDnsComputerName
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS5_ID = 0x0005 # MsvAvDnsTreeName
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS6_ID = 0x0000 # MsvAvEOL


class NTLMSSPChallengeVersion(IntEnum):
    CREDSSP_VERSION = 0x05

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175
    NEG_PROD_MAJOR_VERSION_HIGH = 0x06
    NEG_PROD_MINOR_VERSION_LOW  = 0x02
    NEG_PROD_VERSION_BUILT      = 0x0ECE
    NEG_NTLM_REVISION_CURRENT   = 0x0F      # NTLMSSP_REVISION_W2K3
