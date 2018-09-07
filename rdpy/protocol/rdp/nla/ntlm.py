#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
@summary: NTLM Authentication
@see: https://msdn.microsoft.com/en-us/library/cc236621.aspx
"""

import hashlib, hmac, struct, datetime
import sspi
import rdpy.security.pyDes as pyDes
import rdpy.security.rc4 as rc4
from rdpy.security.rsa_wrapper import random
from rdpy.core.type import CompositeType, CallableValue, String, UInt8, UInt16Le, UInt24Le, UInt32Le, sizeof, StringStream
from rdpy.core import filetimes, error

class MajorVersion(object):
    """
    @see: https://msdn.microsoft.com/en-us/library/cc236654.aspx
    @see: https://msdn.microsoft.com/en-us/library/a211d894-21bc-4b8b-86ba-b83d0c167b00#id29
    """
    WINDOWS_MAJOR_VERSION_5 = 0x05
    WINDOWS_MAJOR_VERSION_6 = 0x06
    
class MinorVersion(object):
    """
    @see: https://msdn.microsoft.com/en-us/library/cc236654.aspx
    @see: https://msdn.microsoft.com/en-us/library/a211d894-21bc-4b8b-86ba-b83d0c167b00#id30
    """
    WINDOWS_MINOR_VERSION_0 = 0x00
    WINDOWS_MINOR_VERSION_1 = 0x01
    WINDOWS_MINOR_VERSION_2 = 0x02
    WINDOWS_MINOR_VERSION_3 = 0x03
    
class NTLMRevision(object):
    """
    @see: https://msdn.microsoft.com/en-us/library/cc236654.aspx
    """
    NTLMSSP_REVISION_W2K3 = 0x0F
    
class Negotiate(object):
    """
    @see: https://msdn.microsoft.com/en-us/library/cc236650.aspx
    """
    NTLMSSP_NEGOTIATE_56 = 0x80000000
    NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
    NTLMSSP_NEGOTIATE_128 = 0x20000000
    NTLMSSP_NEGOTIATE_VERSION = 0x02000000
    NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
    NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
    NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
    NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
    NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
    NTLMSSP_NEGOTIATE_NTLM = 0x00000200
    NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
    NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
    NTLMSSP_NEGOTIATE_SEAL = 0x00000020
    NTLMSSP_NEGOTIATE_SIGN = 0x00000010
    NTLMSSP_REQUEST_TARGET = 0x00000004
    NTLM_NEGOTIATE_OEM = 0x00000002
    NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
    
class AvId(object):
    """
    @see: https://msdn.microsoft.com/en-us/library/cc236646.aspx
    """
    MsvAvEOL = 0x0000
    MsvAvNbComputerName = 0x0001
    MsvAvNbDomainName = 0x0002
    MsvAvDnsComputerName = 0x0003
    MsvAvDnsDomainName = 0x0004
    MsvAvDnsTreeName = 0x0005
    MsvAvFlags = 0x0006
    MsvAvTimestamp = 0x0007
    MsvAvSingleHost = 0x0008
    MsvAvTargetName = 0x0009
    MsvChannelBindings = 0x000A
    
def getPayLoadField(message, length, bufferOffset):
        if length == 0:
            return None
        offset = sizeof(message) - sizeof(message.Payload)
        start = bufferOffset - offset
        end = start + length
        return message.Payload.value[start:end]

class Version(CompositeType):
    """
    @summary: Version structure as describe in NTLM spec
    @see: https://msdn.microsoft.com/en-us/library/cc236654.aspx
    """
    def __init__(self, conditional):
        CompositeType.__init__(self, conditional = conditional)
        self.ProductMajorVersion = UInt8(MajorVersion.WINDOWS_MAJOR_VERSION_6)
        self.ProductMinorVersion = UInt8(MinorVersion.WINDOWS_MINOR_VERSION_0)
        self.ProductBuild = UInt16Le(6002)
        self.Reserved = UInt24Le()
        self.NTLMRevisionCurrent = UInt8(NTLMRevision.NTLMSSP_REVISION_W2K3)
        
class AvPair(CompositeType):
    """
    @see: https://msdn.microsoft.com/en-us/library/cc236646.aspx
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.AvId = UInt16Le()
        self.AvLen = UInt16Le(lambda:sizeof(self.Value))
        self.Value = String(readLen = self.AvLen)
        
class MessageSignatureEx(CompositeType):
    """
    @summary: Signature for message
    @see: https://msdn.microsoft.com/en-us/library/cc422952.aspx
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.Version = UInt32Le(0x00000001, constant = True)
        self.Checksum = String(readLen = CallableValue(8))
        self.SeqNum = UInt32Le()

class NegotiateMessage(CompositeType):
    """
    @summary: Message send from client to server to negotiate capability of NTLM Authentication
    @see: https://msdn.microsoft.com/en-us/library/cc236641.aspx
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.Signature = String("NTLMSSP\x00", readLen = CallableValue(8), constant = True)
        self.MessageType = UInt32Le(0x00000001, constant = True)
        
        self.NegotiateFlags = UInt32Le()
        
        self.DomainNameLen = UInt16Le()
        self.DomainNameMaxLen = UInt16Le(lambda:self.DomainNameLen.value)
        self.DomainNameBufferOffset = UInt32Le()
        
        self.WorkstationLen = UInt16Le()
        self.WorkstationMaxLen = UInt16Le(lambda:self.WorkstationLen.value)
        self.WorkstationBufferOffset = UInt32Le()
        
        self.Version = Version(conditional = lambda:(self.NegotiateFlags.value & Negotiate.NTLMSSP_NEGOTIATE_VERSION))
        
        self.Payload = String()

class ChallengeMessage(CompositeType):
    """
    @summary: Message send from server to client contains server challenge
    @see: https://msdn.microsoft.com/en-us/library/cc236642.aspx
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.Signature = String("NTLMSSP\x00", readLen = CallableValue(8), constant = True)
        self.MessageType = UInt32Le(0x00000002, constant = True)
        
        self.TargetNameLen = UInt16Le()
        self.TargetNameMaxLen = UInt16Le(lambda:self.TargetNameLen.value)
        self.TargetNameBufferOffset = UInt32Le()
        
        self.NegotiateFlags = UInt32Le()
        
        self.ServerChallenge = String(readLen = CallableValue(8))
        self.Reserved = String("\x00" * 8, readLen = CallableValue(8))
        
        self.TargetInfoLen = UInt16Le()
        self.TargetInfoMaxLen = UInt16Le(lambda:self.TargetInfoLen.value)
        self.TargetInfoBufferOffset = UInt32Le()
        
        self.Version = Version(conditional = lambda:(self.NegotiateFlags.value & Negotiate.NTLMSSP_NEGOTIATE_VERSION))
        self.Payload = String()
        
    def getTargetName(self):
        return getPayLoadField(self, self.TargetNameLen.value, self.TargetNameBufferOffset.value)
    
    def getTargetInfo(self):
        return getPayLoadField(self, self.TargetInfoLen.value, self.TargetInfoBufferOffset.value)
    
    def getTargetInfoAsAvPairArray(self):
        """
        @summary: Parse Target info field to retrieve array of AvPair
        @return: {map(AvId, str)}
        """
        result = {}
        s = StringStream(self.getTargetInfo())
        while(True):
            avPair = AvPair()
            s.readType(avPair)
            if avPair.AvId.value == AvId.MsvAvEOL:
                return result
            result[avPair.AvId.value] = avPair.Value.value
            
        
class AuthenticateMessage(CompositeType):
    """
    @summary: Last message in ntlm authentication
    @see: https://msdn.microsoft.com/en-us/library/cc236643.aspx
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.Signature = String("NTLMSSP\x00", readLen = CallableValue(8), constant = True)
        self.MessageType = UInt32Le(0x00000003, constant = True)
        
        self.LmChallengeResponseLen = UInt16Le()
        self.LmChallengeResponseMaxLen = UInt16Le(lambda:self.LmChallengeResponseLen.value)
        self.LmChallengeResponseBufferOffset = UInt32Le()
        
        self.NtChallengeResponseLen = UInt16Le()
        self.NtChallengeResponseMaxLen = UInt16Le(lambda:self.NtChallengeResponseLen.value)
        self.NtChallengeResponseBufferOffset = UInt32Le()
        
        self.DomainNameLen = UInt16Le()
        self.DomainNameMaxLen = UInt16Le(lambda:self.DomainNameLen.value)
        self.DomainNameBufferOffset = UInt32Le()
        
        self.UserNameLen = UInt16Le()
        self.UserNameMaxLen = UInt16Le(lambda:self.UserNameLen.value)
        self.UserNameBufferOffset = UInt32Le()
        
        self.WorkstationLen = UInt16Le()
        self.WorkstationMaxLen = UInt16Le(lambda:self.WorkstationLen.value)
        self.WorkstationBufferOffset = UInt32Le()
        
        self.EncryptedRandomSessionLen = UInt16Le()
        self.EncryptedRandomSessionMaxLen = UInt16Le(lambda:self.EncryptedRandomSessionLen.value)
        self.EncryptedRandomSessionBufferOffset = UInt32Le()
        
        self.NegotiateFlags = UInt32Le()
        self.Version = Version(conditional = lambda:(self.NegotiateFlags.value & Negotiate.NTLMSSP_NEGOTIATE_VERSION))
        
        self.MIC = String("\x00" * 16, readLen = CallableValue(16))
        self.Payload = String()
        
    def getUserName(self):
        return getPayLoadField(self, self.UserNameLen.value, self.UserNameBufferOffset.value)
    
    def getDomainName(self):
        return getPayLoadField(self, self.DomainNameLen.value, self.DomainNameBufferOffset.value)
    
    def getLmChallengeResponse(self):
        return getPayLoadField(self, self.LmChallengeResponseLen.value, self.LmChallengeResponseBufferOffset.value)
    
    def getNtChallengeResponse(self):
        return getPayLoadField(self, self.NtChallengeResponseLen.value, self.NtChallengeResponseBufferOffset.value)
    
    def getEncryptedRandomSession(self):
        return getPayLoadField(self, self.EncryptedRandomSessionLen.value, self.EncryptedRandomSessionBufferOffset.value)

def createAuthenticationMessage(NegFlag, domain, user, NtChallengeResponse, LmChallengeResponse, EncryptedRandomSessionKey, Workstation):
    """
    @summary: Create an Authenticate Message
    @param domain: {str} domain microsoft
    @param user: {str} user microsoft
    @param NtChallengeResponse: {str} Challenge response
    @param LmChallengeResponse: {str} domain microsoft
    @param EncryptedRandomSessionKey: {str} EncryptedRandomSessionKey
    """
    message = AuthenticateMessage()
    message.NegotiateFlags.value = NegFlag
    #fill message
    offset = sizeof(message)
    
    message.DomainNameLen.value = len(domain)
    message.DomainNameBufferOffset.value = offset
    message.Payload.value += domain
    offset += len(domain)
    
    message.UserNameLen.value = len(user)
    message.UserNameBufferOffset.value = offset
    message.Payload.value += user
    offset += len(user)
    
    message.WorkstationLen.value = len(Workstation)
    message.WorkstationBufferOffset.value = offset
    message.Payload.value += Workstation
    offset += len(Workstation)
    
    message.LmChallengeResponseLen.value = len(LmChallengeResponse)
    message.LmChallengeResponseBufferOffset.value = offset
    message.Payload.value += LmChallengeResponse
    offset += len(LmChallengeResponse)
    
    message.NtChallengeResponseLen.value = len(NtChallengeResponse)
    message.NtChallengeResponseBufferOffset.value = offset
    message.Payload.value += NtChallengeResponse
    offset += len(NtChallengeResponse)
    
    message.EncryptedRandomSessionLen.value = len(EncryptedRandomSessionKey)
    message.EncryptedRandomSessionBufferOffset.value = offset
    message.Payload.value += EncryptedRandomSessionKey
    offset += len(EncryptedRandomSessionKey)
    
    return message

def expandDesKey(key):
    """
    @summary: Expand the key from a 7-byte password key into a 8-byte DES key
    """
    s = chr(((ord(key[0]) >> 1) & 0x7f) << 1)
    s = s + chr(((ord(key[0]) & 0x01) << 6 | ((ord(key[1]) >> 2) & 0x3f)) << 1)
    s = s + chr(((ord(key[1]) & 0x03) << 5 | ((ord(key[2]) >> 3) & 0x1f)) << 1)
    s = s + chr(((ord(key[2]) & 0x07) << 4 | ((ord(key[3]) >> 4) & 0x0f)) << 1)
    s = s + chr(((ord(key[3]) & 0x0f) << 3 | ((ord(key[4]) >> 5) & 0x07)) << 1)
    s = s + chr(((ord(key[4]) & 0x1f) << 2 | ((ord(key[5]) >> 6) & 0x03)) << 1)
    s = s + chr(((ord(key[5]) & 0x3f) << 1 | ((ord(key[6]) >> 7) & 0x01)) << 1)
    s = s + chr((ord(key[6]) & 0x7f) << 1)
    return s

def CurrentFileTimes():
    """
    @summary: Current File times in 64 bits
    @return  : {str[8]}
    """
    return struct.pack("Q", filetimes.dt_to_filetime(datetime.datetime.now()))

def DES(key, data):
    """
    @summary: DES use in microsoft specification
    @param key: {str}    Des key on 56 bits or 7 bytes
    @param data: {str}    data to encrypt
    """
    return pyDes.des(expandDesKey(key)).encrypt(data)

def DESL(key, data):
    """
    @summary: an krosoft security function (triple des = des + des + des ;-))
    @param key: {str} Des key
    @param data: {str} encrypted data
    """
    return DES(key[0:7], data) + DES(key[7:14], data) + DES(key[14:16] + "\x00" * 5, data)

def UNICODE(s):
    """
    @param s: source
    @return: {str} encoded in unicode
    """
    return s.encode('utf-16le')

def MD4(s):
    """
    @summary: compute the md4 sum
    @param s: {str} input data
    @return: {str} MD4(s)
    """
    return hashlib.new('md4', s).digest()

def MD5(s):
    """
    @summary: compute the md5 sum
    @param s: {str} input data
    @return: {str} MD5(s)
    """
    return hashlib.new('md5', s).digest()

def Z(m):
    """
    @summary: fill m zero in string
    @param m: {int} size of string
    @return: \x00 * m 
    """
    return "\x00" * m

def RC4K(key, plaintext):
    """
    @summary: Context free of rc4 encoding
    @param key: {str} key
    @param plaintext: {str} plaintext
    @return {str} encrypted text
    """
    return rc4.crypt(rc4.RC4Key(key), plaintext)

def KXKEYv2(SessionBaseKey, LmChallengeResponse, ServerChallenge):
    """
    @summary: Key eXchange Key for NTLMv2
    @param SessionBaseKey: {str} computed by NTLMv1Anthentication or NTLMv2Authenticate function
    @param LmChallengeResponse : {str} computed by NTLMv1Anthentication or NTLMv2Authenticate function
    @param ServerChallenge : {str} Server chanllenge come from ChallengeMessage
    @see: https://msdn.microsoft.com/en-us/library/cc236710.aspx
    """
    return SessionBaseKey

def SEALKEY(ExportedSessionKey, client):
    if client:
        return MD5(ExportedSessionKey + "session key to client-to-server sealing key magic constant\0")
    else:
        return MD5(ExportedSessionKey + "session key to server-to-client sealing key magic constant\0")

def SIGNKEY(ExportedSessionKey, client):
    if client:
        return MD5(ExportedSessionKey + "session key to client-to-server signing key magic constant\0")
    else:
        return MD5(ExportedSessionKey + "session key to server-to-client signing key magic constant\0")

def HMAC_MD5(key, data):
    """
    @summary: classic HMAC algorithm with MD5 sum
    @param key: {str} key
    @param data: {str} data
    """
    return hmac.new(key, data, hashlib.md5).digest()

def NTOWFv2(Passwd, User, UserDom):
    """
    @summary: Version 2 of NTLM hash function
    @param Passwd: {str} Password
    @param User: {str} Username
    @param UserDom: {str} microsoft domain
    @see: https://msdn.microsoft.com/en-us/library/cc236700.aspx
    """
    return HMAC_MD5(MD4(UNICODE(Passwd)), UNICODE(User.upper() + UserDom))

def LMOWFv2(Passwd, User, UserDom):
    """
    @summary: Same as NTOWFv2
    @param Passwd: {str} Password
    @param User: {str} Username
    @param UserDom: {str} microsoft domain
    @see: https://msdn.microsoft.com/en-us/library/cc236700.aspx
    """
    return NTOWFv2(Passwd, User, UserDom)

def ComputeResponsev2(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ClientChallenge, Time, ServerName):
    """
    @summary: process NTLMv2 Authenticate hash
    @param NegFlg: {int} Negotiation flags come from challenge message
    @see: https://msdn.microsoft.com/en-us/library/cc236700.aspx
    """
    Responserversion = "\x01"
    HiResponserversion = "\x01"

    temp = Responserversion + HiResponserversion + Z(6) + Time + ClientChallenge + Z(4) + ServerName
    NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge + temp)
    NtChallengeResponse = NTProofStr + temp
    LmChallengeResponse = HMAC_MD5(ResponseKeyLM, ServerChallenge + ClientChallenge) + ClientChallenge
    
    SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
    
    return NtChallengeResponse, LmChallengeResponse, SessionBaseKey

def MAC(handle, SigningKey, SeqNum, Message):
    """
    @summary: generate signature for application message
    @param handle: {rc4.RC4Key} handle on crypt
    @param SigningKey: {str} Signing key
    @param SeqNum: {int} Sequence number
    @param Message: Message to sign
    @see: https://msdn.microsoft.com/en-us/library/cc422952.aspx
    """
    signature = MessageSignatureEx()
    signature.SeqNum.value = SeqNum
    
    #write the SeqNum
    s = StringStream()
    s.writeType(signature.SeqNum)
    
    signature.Checksum.value = rc4.crypt(handle, HMAC_MD5(SigningKey, s.getvalue() + Message)[:8])
    
    return signature

def MIC(ExportedSessionKey, negotiateMessage, challengeMessage, authenticateMessage):
    """
    @summary: Compute MIC signature
    @param negotiateMessage: {NegotiateMessage}
    @param challengeMessage: {ChallengeMessage}
    @param authenticateMessage: {AuthenticateMessage}
    @return: {str} signature
    @see: https://msdn.microsoft.com/en-us/library/cc236676.aspx 
    """
    s = StringStream()
    s.writeType((negotiateMessage, challengeMessage, authenticateMessage))
    return HMAC_MD5(ExportedSessionKey, s.getvalue())
    
class NTLMv2(sspi.IAuthenticationProtocol):
    """
    @summary: Handle NTLMv2 Authentication
    """
    def __init__(self, domain, user, password):
        self._domain = domain
        self._user = user
        self._password = password
        self._enableUnicode = False
        #https://msdn.microsoft.com/en-us/library/cc236700.aspx
        self._ResponseKeyNT = NTOWFv2(password, user, domain)
        self._ResponseKeyLM = LMOWFv2(password, user, domain)
        
        #For MIC computation
        self._negotiateMessage = None
        self._challengeMessage = None
        self._authenticateMessage = None
    
    def getNegotiateMessage(self):
        """
        @summary: generate first handshake messgae
        """
        self._negotiateMessage = NegotiateMessage()
        self._negotiateMessage.NegotiateFlags.value = (Negotiate.NTLMSSP_NEGOTIATE_KEY_EXCH |
                                        Negotiate.NTLMSSP_NEGOTIATE_128 |
                                        Negotiate.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
                                        Negotiate.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
                                        Negotiate.NTLMSSP_NEGOTIATE_NTLM |
                                        Negotiate.NTLMSSP_NEGOTIATE_SEAL |
                                        Negotiate.NTLMSSP_NEGOTIATE_SIGN |
                                        Negotiate.NTLMSSP_REQUEST_TARGET |
                                        Negotiate.NTLMSSP_NEGOTIATE_UNICODE)
        return self._negotiateMessage
    
    def getAuthenticateMessage(self, s):
        """
        @summary: Client last handshake message
        @param s: {Stream} challenge message stream
        @return: {(AuthenticateMessage, NTLMv2SecurityInterface)} Last handshake message and security interface use to encrypt
        @see: https://msdn.microsoft.com/en-us/library/cc236676.aspx
        """
        self._challengeMessage = ChallengeMessage()
        s.readType(self._challengeMessage)
        
        ServerChallenge = self._challengeMessage.ServerChallenge.value
        ClientChallenge = random(64)
        
        computeMIC = False
        ServerName = self._challengeMessage.getTargetInfo()
        infos = self._challengeMessage.getTargetInfoAsAvPairArray()
        if infos.has_key(AvId.MsvAvTimestamp):
            Timestamp = infos[AvId.MsvAvTimestamp]
            computeMIC = True
        else:
            Timestamp = CurrentFileTimes()
    
        
        NtChallengeResponse, LmChallengeResponse, SessionBaseKey = ComputeResponsev2(self._ResponseKeyNT, self._ResponseKeyLM, ServerChallenge, ClientChallenge, Timestamp, ServerName)
        KeyExchangeKey = KXKEYv2(SessionBaseKey, LmChallengeResponse, ServerChallenge)
        ExportedSessionKey = random(128)
        EncryptedRandomSessionKey = RC4K(KeyExchangeKey, ExportedSessionKey)
        
        domain, user = self._domain, self._user
        if self._challengeMessage.NegotiateFlags.value & Negotiate.NTLMSSP_NEGOTIATE_UNICODE:
            self._enableUnicode = True
            domain, user = UNICODE(domain), UNICODE(user)
        self._authenticateMessage = createAuthenticationMessage(self._challengeMessage.NegotiateFlags.value, domain, user, NtChallengeResponse, LmChallengeResponse, EncryptedRandomSessionKey, "")
        
        if computeMIC:
            self._authenticateMessage.MIC.value = MIC(ExportedSessionKey, self._negotiateMessage, self._challengeMessage, self._authenticateMessage)
        else:
            self._authenticateMessage.MIC._conditional = lambda:False
        
        ClientSigningKey = SIGNKEY(ExportedSessionKey, True)
        ServerSigningKey = SIGNKEY(ExportedSessionKey, False)
        ClientSealingKey = SEALKEY(ExportedSessionKey, True)
        ServerSealingKey = SEALKEY(ExportedSessionKey, False)
        
        interface = NTLMv2SecurityInterface(rc4.RC4Key(ClientSealingKey), rc4.RC4Key(ServerSealingKey), ClientSigningKey, ServerSigningKey)
        
        return self._authenticateMessage, interface
    
    def getEncodedCredentials(self):
        """
        @summary: return encoded credentials accorded with authentication protocol nego
        @return: (domain, username, password)
        """
        if self._enableUnicode:
            return UNICODE(self._domain), UNICODE(self._user), UNICODE(self._password)
        else:
            return self._domain, self._user, self._password
        

class NTLMv2SecurityInterface(sspi.IGenericSecurityService):
    """
    @summary: Generic Security Service for NTLM session
    """
    def __init__(self, encryptHandle, decryptHandle, signingKey, verifyKey):
        """
        @param encryptHandle: {rc4.RC4Key} rc4 keystream for encrypt phase
        @param decryptHandle: {rc4.RC4Key} rc4 keystream for decrypt phase
        @param signingKey: {str} signingKey
        @param verifyKey: {str} verifyKey
        """
        self._encryptHandle = encryptHandle
        self._decryptHandle = decryptHandle
        self._signingKey = signingKey
        self._verifyKey = verifyKey
        self._seqNum = 0
        
    def GSS_WrapEx(self, data):
        """
        @summary: Encrypt function for NTLMv2 security service
        @param data: data to encrypt
        @return: {str} encrypted data
        """
        encryptedData = rc4.crypt(self._encryptHandle, data)
        signature = MAC(self._encryptHandle, self._signingKey, self._seqNum, data)
        self._seqNum += 1
        s = StringStream()
        s.writeType(signature)
        return s.getvalue() + encryptedData
    
    def GSS_UnWrapEx(self, data):
        """
        @summary: decrypt data with key exchange in Authentication protocol
        @param data: {str}
        """
        signature = MessageSignatureEx()
        message = String()
        s = StringStream(data)
        s.readType((signature, message))
        
        #decrypt message
        plaintextMessage = rc4.crypt(self._decryptHandle, message.value)
        checksum = rc4.crypt(self._decryptHandle, signature.Checksum.value)
        
        #recompute checksum
        t = StringStream()
        t.writeType(signature.SeqNum)
        verify = HMAC_MD5(self._verifyKey, t.getvalue() + plaintextMessage)[:8]
        if verify != checksum:
            raise error.InvalidExpectedDataException("NTLMv2SecurityInterface : Invalid checksum")
        
        return plaintextMessage