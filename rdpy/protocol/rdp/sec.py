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
RDP Standard security layer
"""

import sha, md5
import lic, tpkt
from t125 import gcc, mcs
from rdpy.core.type import CompositeType, CallableValue, Stream, UInt32Le, UInt16Le, String, sizeof, UInt8
from rdpy.core.layer import LayerAutomata, IStreamSender
from rdpy.core.error import InvalidExpectedDataException
from rdpy.core import log
from rdpy.security import rc4
import rdpy.security.rsa_wrapper as rsa

class SecurityFlag(object):
    """
    @summary: Microsoft security flags
    @see: http://msdn.microsoft.com/en-us/library/cc240579.aspx
    """
    SEC_EXCHANGE_PKT = 0x0001
    SEC_TRANSPORT_REQ = 0x0002
    RDP_SEC_TRANSPORT_RSP = 0x0004
    SEC_ENCRYPT = 0x0008
    SEC_RESET_SEQNO = 0x0010
    SEC_IGNORE_SEQNO = 0x0020
    SEC_INFO_PKT = 0x0040
    SEC_LICENSE_PKT = 0x0080
    SEC_LICENSE_ENCRYPT_CS = 0x0200
    SEC_LICENSE_ENCRYPT_SC = 0x0200
    SEC_REDIRECTION_PKT = 0x0400
    SEC_SECURE_CHECKSUM = 0x0800
    SEC_AUTODETECT_REQ = 0x1000
    SEC_AUTODETECT_RSP = 0x2000
    SEC_HEARTBEAT = 0x4000
    SEC_FLAGSHI_VALID = 0x8000
    
class InfoFlag(object):
    """
    Client capabilities informations
    """
    INFO_MOUSE = 0x00000001
    INFO_DISABLECTRLALTDEL = 0x00000002
    INFO_AUTOLOGON = 0x00000008
    INFO_UNICODE = 0x00000010
    INFO_MAXIMIZESHELL = 0x00000020
    INFO_LOGONNOTIFY = 0x00000040
    INFO_COMPRESSION = 0x00000080
    INFO_ENABLEWINDOWSKEY = 0x00000100
    INFO_REMOTECONSOLEAUDIO = 0x00002000
    INFO_FORCE_ENCRYPTED_CS_PDU = 0x00004000
    INFO_RAIL = 0x00008000
    INFO_LOGONERRORS = 0x00010000
    INFO_MOUSE_HAS_WHEEL = 0x00020000
    INFO_PASSWORD_IS_SC_PIN = 0x00040000
    INFO_NOAUDIOPLAYBACK = 0x00080000
    INFO_USING_SAVED_CREDS = 0x00100000
    INFO_AUDIOCAPTURE = 0x00200000
    INFO_VIDEO_DISABLE = 0x00400000
    INFO_CompressionTypeMask = 0x00001E00

class PerfFlag(object):
    """
    Network performances flag
    """
    PERF_DISABLE_WALLPAPER = 0x00000001
    PERF_DISABLE_FULLWINDOWDRAG = 0x00000002
    PERF_DISABLE_MENUANIMATIONS = 0x00000004
    PERF_DISABLE_THEMING = 0x00000008
    PERF_DISABLE_CURSOR_SHADOW = 0x00000020
    PERF_DISABLE_CURSORSETTINGS = 0x00000040
    PERF_ENABLE_FONT_SMOOTHING = 0x00000080
    PERF_ENABLE_DESKTOP_COMPOSITION = 0x00000100
    
class AfInet(object):
    """
    IPv4 or IPv6 address style
    """
    AF_INET = 0x00002
    AF_INET6 = 0x0017
       
def saltedHash(inputData, salt, salt1, salt2):
    """
    @summary: Generate particular signature from combination of sha1 and md5
    @see: http://msdn.microsoft.com/en-us/library/cc241992.aspx
    @param inputData: strange input (see doc)
    @param salt: salt for context call
    @param salt1: another salt (ex : client random)
    @param salt2: another another salt (ex: server random)
    @return : MD5(Salt + SHA1(Input + Salt + Salt1 + Salt2))
    """
    sha1Digest = sha.new()
    md5Digest = md5.new()
    
    sha1Digest.update(inputData)
    sha1Digest.update(salt[:48])
    sha1Digest.update(salt1)
    sha1Digest.update(salt2)
    sha1Sig = sha1Digest.digest()
    
    md5Digest.update(salt[:48])
    md5Digest.update(sha1Sig)
    
    return md5Digest.digest()

def finalHash(key, random1, random2):
    """
    @summary: MD5(in0[:16] + in1[:32] + in2[:32])
    @param key: in 16
    @param random1: in 32
    @param random2: in 32
    @return MD5(in0[:16] + in1[:32] + in2[:32])
    """
    md5Digest = md5.new()
    md5Digest.update(key)
    md5Digest.update(random1)
    md5Digest.update(random2)
    return md5Digest.digest()

def masterSecret(secret, random1, random2):
    """
    @summary: Generate master secret
    @param secret: {str} secret
    @param clientRandom : {str} client random
    @param serverRandom : {str} server random
    @see: http://msdn.microsoft.com/en-us/library/cc241992.aspx
    """
    return saltedHash("A", secret, random1, random2) + saltedHash("BB", secret, random1, random2) + saltedHash("CCC", secret, random1, random2)

def sessionKeyBlob(secret, random1, random2):
    """
    @summary: Generate master secret
    @param secret: secret
    @param clientRandom : client random
    @param serverRandom : server random
    """
    return saltedHash("X", secret, random1, random2) + saltedHash("YY", secret, random1, random2) + saltedHash("ZZZ", secret, random1, random2)

def macData(macSaltKey, data):
    """
    @see: http://msdn.microsoft.com/en-us/library/cc241995.aspx
    @param macSaltKey: {str} mac key
    @param data: {str} data to sign
    @return: {str} signature
    """
    sha1Digest = sha.new()
    md5Digest = md5.new()
    
    #encode length
    dataLength = Stream()
    dataLength.writeType(UInt32Le(len(data)))
    
    sha1Digest.update(macSaltKey)
    sha1Digest.update("\x36" * 40)
    sha1Digest.update(dataLength.getvalue())
    sha1Digest.update(data)
    
    sha1Sig = sha1Digest.digest()
    
    md5Digest.update(macSaltKey)
    md5Digest.update("\x5c" * 48)
    md5Digest.update(sha1Sig)
    
    return md5Digest.digest()

def macSaltedData(macSaltKey, data, encryptionCount):
    """
    @see: https://msdn.microsoft.com/en-us/library/cc240789.aspx
    @param macSaltKey: {str} mac key
    @param data: {str} data to sign
    @param encryptionCount: nb encrypted packet
    @return: {str} signature
    """
    sha1Digest = sha.new()
    md5Digest = md5.new()
    
    #encode length
    dataLengthS = Stream()
    dataLengthS.writeType(UInt32Le(len(data)))
    
    encryptionCountS = Stream()
    encryptionCountS.writeType(UInt32Le(encryptionCount))
    
    sha1Digest.update(macSaltKey)
    sha1Digest.update("\x36" * 40)
    sha1Digest.update(dataLengthS.getvalue())
    sha1Digest.update(data)
    sha1Digest.update(encryptionCountS.getvalue())
    
    sha1Sig = sha1Digest.digest()
    
    md5Digest.update(macSaltKey)
    md5Digest.update("\x5c" * 48)
    md5Digest.update(sha1Sig)
    
    return md5Digest.digest()

def tempKey(initialKey, currentKey):
    """
    @see: http://msdn.microsoft.com/en-us/library/cc240792.aspx
    @param initialKey: {str} key computed first time
    @param currentKey: {str} key actually used
    @return: {str} temp key
    """
    sha1Digest = sha.new()
    md5Digest = md5.new()
    
    sha1Digest.update(initialKey)
    sha1Digest.update("\x36" * 40)
    sha1Digest.update(currentKey)
    
    sha1Sig = sha1Digest.digest()
    
    md5Digest.update(initialKey)
    md5Digest.update("\x5c" * 48)
    md5Digest.update(sha1Sig)
    
    return md5Digest.digest()

def gen40bits(data):
    """
    @summary: generate 40 bits data from 128 bits data
    @param data: {str} 128 bits data
    @return: {str} 40 bits data
    @see: http://msdn.microsoft.com/en-us/library/cc240785.aspx
    """
    return "\xd1\x26\x9e" + data[:8][-5:]

def gen56bits(data):
    """
    @summary: generate 56 bits data from 128 bits data
    @param data: {str} 128 bits data
    @return: {str} 56 bits data
    @see: http://msdn.microsoft.com/en-us/library/cc240785.aspx
    """
    return "\xd1" + data[:8][-7:]

def generateKeys(clientRandom, serverRandom, method):
    """
    @param method: {gcc.Encryption}
    @param clientRandom: {str[32]} client random
    @param serverRandom: {str[32]} server random
    @see: http://msdn.microsoft.com/en-us/library/cc240785.aspx
    @return: MACKey, initialFirstKey128(ClientdecryptKey, serverEncryptKey), initialSecondKey128(ServerDecryptKey, ClientEncryptKey)
    """
    preMasterHash = clientRandom[:24] + serverRandom[:24]
    masterHash = masterSecret(preMasterHash, clientRandom, serverRandom)
    sessionKey = sessionKeyBlob(masterHash, clientRandom, serverRandom)
    macKey128 = sessionKey[:16]
    initialFirstKey128 = finalHash(sessionKey[16:32], clientRandom, serverRandom)
    initialSecondKey128 = finalHash(sessionKey[32:48], clientRandom, serverRandom)
    
    #generate valid key
    if method == gcc.EncryptionMethod.ENCRYPTION_FLAG_40BIT:
        return gen40bits(macKey128), gen40bits(initialFirstKey128), gen40bits(initialSecondKey128)
    
    elif method == gcc.EncryptionMethod.ENCRYPTION_FLAG_56BIT:
        return gen56bits(macKey128), gen56bits(initialFirstKey128), gen56bits(initialSecondKey128)
    
    elif method == gcc.EncryptionMethod.ENCRYPTION_FLAG_128BIT:
        return macKey128, initialFirstKey128, initialSecondKey128
    
    raise InvalidExpectedDataException("Bad encryption method")

def updateKey(initialKey, currentKey, method):
    """
    @summary: update session key
    @param initialKey: {str} Initial key
    @param currentKey: {str} Current key
    @return newKey: {str} key to use
    @see: http://msdn.microsoft.com/en-us/library/cc240792.aspx
    """
    #generate valid key
    if method == gcc.EncryptionMethod.ENCRYPTION_FLAG_40BIT:
        tempKey128 = tempKey(initialKey[:8], currentKey[:8])
        return gen40bits(rc4.crypt(rc4.RC4Key(tempKey128[:8]), tempKey128[:8]))
    
    elif method == gcc.EncryptionMethod.ENCRYPTION_FLAG_56BIT:
        tempKey128 = tempKey(initialKey[:8], currentKey[:8])
        return gen56bits(rc4.crypt(rc4.RC4Key(tempKey128[:8]), tempKey128[:8]))
    
    elif method == gcc.EncryptionMethod.ENCRYPTION_FLAG_128BIT:
        tempKey128 = tempKey(initialKey, currentKey)
        return rc4.crypt(rc4.RC4Key(tempKey128), tempKey128)
    
class ClientSecurityExchangePDU(CompositeType):
    """
    @summary: contain client random for basic security
    @see: http://msdn.microsoft.com/en-us/library/cc240472.aspx
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.length = UInt32Le(lambda:(sizeof(self) - 4))
        self.encryptedClientRandom = String(readLen = CallableValue(lambda:(self.length.value - 8)))
        self.padding = String("\x00" * 8, readLen = CallableValue(8))
        
class RDPInfo(CompositeType):
    """
    @summary: Client informations
    Contains credentials (very important packet)
    @see: http://msdn.microsoft.com/en-us/library/cc240475.aspx
    """
    def __init__(self, extendedInfoConditional):
        CompositeType.__init__(self)
        #code page
        self.codePage = UInt32Le()
        #support flag
        self.flag = UInt32Le(InfoFlag.INFO_MOUSE | InfoFlag.INFO_UNICODE | InfoFlag.INFO_LOGONNOTIFY | InfoFlag.INFO_LOGONERRORS | InfoFlag.INFO_DISABLECTRLALTDEL | InfoFlag.INFO_ENABLEWINDOWSKEY)
        self.cbDomain = UInt16Le(lambda:sizeof(self.domain) - 2)
        self.cbUserName = UInt16Le(lambda:sizeof(self.userName) - 2)
        self.cbPassword = UInt16Le(lambda:sizeof(self.password) - 2)
        self.cbAlternateShell = UInt16Le(lambda:sizeof(self.alternateShell) - 2)
        self.cbWorkingDir = UInt16Le(lambda:sizeof(self.workingDir) - 2)
        #microsoft domain
        self.domain = String(readLen = CallableValue(lambda:self.cbDomain.value + 2), unicode = True)
        self.userName = String(readLen = CallableValue(lambda:self.cbUserName.value + 2), unicode = True)
        self.password = String(readLen = CallableValue(lambda:self.cbPassword.value + 2), unicode = True)
        #shell execute at start of session
        self.alternateShell = String(readLen = CallableValue(lambda:self.cbAlternateShell.value + 2), unicode = True)
        #working directory for session
        self.workingDir = String(readLen = CallableValue(lambda:self.cbWorkingDir.value + 2), unicode = True)
        self.extendedInfo = RDPExtendedInfo(conditional = extendedInfoConditional)
    
    def __getitem__(self, item):
        return getattr(self, item).value
        
class RDPExtendedInfo(CompositeType):
    """
    @summary: Add more client informations
    """
    def __init__(self, conditional):
        CompositeType.__init__(self, conditional = conditional)
        self.clientAddressFamily = UInt16Le(AfInet.AF_INET)
        self.cbClientAddress = UInt16Le(lambda:sizeof(self.clientAddress))
        self.clientAddress = String(readLen = self.cbClientAddress, unicode = True)
        self.cbClientDir = UInt16Le(lambda:sizeof(self.clientDir))
        self.clientDir = String(readLen = self.cbClientDir, unicode = True)
        #TODO make tiomezone
        self.clientTimeZone = String("\x00" * 172)
        self.clientSessionId = UInt32Le()
        self.performanceFlags = UInt32Le()

    def __getitem__(self, item):
        return getattr(self, item).value

class SecLayer(LayerAutomata, IStreamSender, tpkt.IFastPathListener, tpkt.IFastPathSender, mcs.IGCCConfig):
    """
    @summary: Standard RDP security layer
    This layer is Transparent as possible for upper layer 
    """
    def __init__(self, presentation):
        """
        @param presentation: Layer (generally pdu layer)
        """
        LayerAutomata.__init__(self, presentation)
        #thios layer is like a fastpath proxy
        self._fastPathTransport = None
        self._fastPathPresentation = None
        
        #credentials
        self._info = RDPInfo(extendedInfoConditional = lambda:(self.getGCCServerSettings().SC_CORE.rdpVersion.value == gcc.Version.RDP_VERSION_5_PLUS))
        
        #True if classic encryption is enable
        self._enableEncryption = False
        
        #Enable Secure Mac generation
        self._enableSecureCheckSum = False
        
        #initialise decrypt and encrypt keys
        self._macKey = None
        self._initialDecrytKey = None
        self._initialEncryptKey = None
        self._currentDecrytKey = None
        self._currentEncryptKey = None
        
        #counter before update
        self._nbEncryptedPacket = 0
        self._nbDecryptedPacket = 0
        
        #current rc4 tab
        self._decryptRc4 = None
        self._encryptRc4 = None
        
    
    def readEncryptedPayload(self, s, saltedMacGeneration):
        """
        @summary: decrypt basic RDP security payload
        @param s: {Stream} encrypted stream
        @param saltedMacGeneration: {bool} use salted mac generation
        @return: {Stream} decrypted
        """
        #if update is needed
        if self._nbDecryptedPacket == 4096:
            log.debug("update decrypt key")
            self._currentDecrytKey = updateKey( self._initialDecrytKey, self._currentDecrytKey, 
                                                self.getGCCServerSettings().SC_SECURITY.encryptionMethod.value)
            self._decryptRc4 = rc4.RC4Key(self._currentDecrytKey)
            self._nbDecryptedPacket = 0
        
        signature = String(readLen = CallableValue(8))
        encryptedPayload = String()
        s.readType((signature, encryptedPayload))
        decrypted = rc4.crypt(self._decryptRc4, encryptedPayload.value)

        #ckeck signature
        if not saltedMacGeneration and macData(self._macKey, decrypted)[:8] != signature.value:
            raise InvalidExpectedDataException("bad signature")
        
        if saltedMacGeneration and macSaltedData(self._macKey, decrypted, self._nbDecryptedPacket)[:8] != signature.value:
            raise InvalidExpectedDataException("bad signature")
        
        #count
        self._nbDecryptedPacket += 1

        return Stream(decrypted)
    
    def writeEncryptedPayload(self, data, saltedMacGeneration):
        """
        @summary: sign and crypt data
        @param data: {Type} raw stream
        @param saltedMacGeneration: {bool} use salted mac generation
        @return: {Tuple} (signature, encryptedData)
        """
        if self._nbEncryptedPacket == 4096:
            log.debug("update encrypt key")
            self._currentEncryptKey = updateKey(    self._initialEncryptKey, self._currentEncryptKey, 
                                                    self.getGCCServerSettings().SC_SECURITY.encryptionMethod.value)
            self._encryptRc4 = rc4.RC4Key(self._currentEncryptKey)
            self._nbEncryptedPacket = 0
            
        self._nbEncryptedPacket += 1
        
        s = Stream()
        s.writeType(data)
        
        if saltedMacGeneration:
            return (String(macSaltedData(self._macKey, s.getvalue(), self._nbEncryptedPacket - 1)[:8]), String(rc4.crypt(self._encryptRc4, s.getvalue())))
        else:
            return (String(macData(self._macKey, s.getvalue())[:8]), String(rc4.crypt(self._encryptRc4, s.getvalue())))
    
    def recv(self, data):
        """
        @summary: if basic RDP security layer is activate decrypt
                    else pass to upper layer
        @param data : {Stream} input Stream
        """
        if not self._enableEncryption:
            self._presentation.recv(data)
            return
        
        securityFlag = UInt16Le()
        securityFlagHi = UInt16Le()
        data.readType((securityFlag, securityFlagHi))
        
        if securityFlag.value & SecurityFlag.SEC_ENCRYPT:
            data = self.readEncryptedPayload(data, securityFlag.value & SecurityFlag.SEC_SECURE_CHECKSUM)
            
        self._presentation.recv(data)
        
    def send(self, data):
        """
        @summary: if basic RDP security layer is activate encrypt
                    else pass to upper layer
        @param data: {Type | Tuple}
        """
        if not self._enableEncryption:
            self._transport.send(data)
            return
        
        flag = SecurityFlag.SEC_ENCRYPT
        
        if self._enableSecureCheckSum:
            flag |= SecurityFlag.SEC_SECURE_CHECKSUM
        
        self.sendFlagged(flag, data)
    
    def sendFlagged(self, flag, data):
        """
        @summary: explicit send flag method for particular packet
                    (info packet or license packet)
                    If encryption is enable apply it
        @param flag: {integer} security flag
        @param data: {Type | Tuple}
        """
        if flag & SecurityFlag.SEC_ENCRYPT:
            data = self.writeEncryptedPayload(data, flag & SecurityFlag.SEC_SECURE_CHECKSUM)
        self._transport.send((UInt16Le(flag), UInt16Le(), data))
        
    def recvFastPath(self, secFlag, fastPathS):
        """
        @summary: Call when fast path packet is received
        @param secFlag: {SecFlags}
        @param fastPathS: {Stream}
        """
        if self._enableEncryption and secFlag & tpkt.SecFlags.FASTPATH_OUTPUT_ENCRYPTED:
            fastPathS = self.readEncryptedPayload(fastPathS, secFlag & tpkt.SecFlags.FASTPATH_OUTPUT_SECURE_CHECKSUM)
        
        self._fastPathPresentation.recvFastPath(secFlag, fastPathS)
        
    def setFastPathListener(self, fastPathListener):
        """
        @param fastPathListener : {IFastPathListener}
        """
        self._fastPathPresentation = fastPathListener
        
    def sendFastPath(self, secFlag, fastPathS):
        """
        @summary: Send fastPathS Type as fast path packet
        @param secFlag: {SecFlags}
        @param fastPathS: {Stream} type transform to stream and send as fastpath
        """
        if self._enableEncryption:
            secFlag |= tpkt.SecFlags.FASTPATH_OUTPUT_ENCRYPTED
            
            if self._enableSecureCheckSum:
                secFlag |= tpkt.SecFlags.FASTPATH_OUTPUT_SECURE_CHECKSUM
                
            fastPathS = self.writeEncryptedPayload(fastPathS, self._enableSecureCheckSum)
        
        self._fastPathTransport.sendFastPath(secFlag, fastPathS)
        
    def setFastPathSender(self, fastPathSender):
        """
        @param fastPathSender: {tpkt.FastPathSender}
        """
        self._fastPathTransport = fastPathSender
        
    def getUserId(self):
        """
        @return: {integer} mcs user id
        @see: mcs.IGCCConfig
        """
        return self._transport.getUserId()
    
    def getChannelId(self):
        """
        @return: {integer} return channel id of proxy
        @see: mcs.IGCCConfig
        """
        return self._transport.getChannelId()
        
    def getGCCClientSettings(self):
        """
        @return: {gcc.Settings} mcs layer gcc client settings
        @see: mcs.IGCCConfig
        """
        return self._transport.getGCCClientSettings()
    
    def getGCCServerSettings(self):
        """
        @return: {gcc.Settings} mcs layer gcc server settings
        @see: mcs.IGCCConfig
        """
        return self._transport.getGCCServerSettings()
    
class Client(SecLayer):
    """
    @summary: Client side of security layer
    """
    def __init__(self, presentation):
        SecLayer.__init__(self, presentation)
        self._licenceManager = lic.LicenseManager(self)
        
    def connect(self):
        """
        @summary: send client random if needed and send info packet
        """
        self._enableEncryption = self.getGCCClientSettings().CS_CORE.serverSelectedProtocol == 0
        
        if self._enableEncryption:
            self.sendClientRandom()
        
        self.sendInfoPkt()
        
    def sendInfoPkt(self):
        """
        @summary: send information packet (with credentials)
                    next state -> recvLicenceInfo
        """
        secFlag = SecurityFlag.SEC_INFO_PKT
        if self._enableEncryption:
            secFlag |= SecurityFlag.SEC_ENCRYPT
        self.sendFlagged(secFlag, self._info)
        
        self.setNextState(self.recvLicenceInfo)
        
    def sendClientRandom(self):
        """
        @summary: generate and send client random and init session keys 
        """
        #generate client random
        clientRandom = rsa.random(256)
        self._macKey, self._initialDecrytKey, self._initialEncryptKey = generateKeys(   clientRandom, 
                                                                                        self.getGCCServerSettings().SC_SECURITY.serverRandom.value, 
                                                                                        self.getGCCServerSettings().SC_SECURITY.encryptionMethod.value)
        #initialize keys
        self._currentDecrytKey = self._initialDecrytKey
        self._currentEncryptKey = self._initialEncryptKey
        self._decryptRc4 = rc4.RC4Key(self._currentDecrytKey)
        self._encryptRc4 = rc4.RC4Key(self._currentEncryptKey)
        
        #verify certificate
        if not self.getGCCServerSettings().SC_SECURITY.serverCertificate.certData.verify():
            log.warning("cannot verify server identity")
        #send client random encrypted with
        serverPublicKey = self.getGCCServerSettings().SC_SECURITY.serverCertificate.certData.getPublicKey()
        message = ClientSecurityExchangePDU()
        #reverse because bignum in little endian
        message.encryptedClientRandom.value = rsa.encrypt(clientRandom[::-1], serverPublicKey)[::-1]
        self.sendFlagged(SecurityFlag.SEC_EXCHANGE_PKT, message)
        
    def recvLicenceInfo(self, s):
        """
        @summary: Read license info packet and check if is a valid client info
        Wait Demand Active PDU
        @param s: Stream
        """
        #packet preambule
        securityFlag = UInt16Le()
        securityFlagHi = UInt16Le()
        s.readType((securityFlag, securityFlagHi))
        
        if not (securityFlag.value & SecurityFlag.SEC_LICENSE_PKT):
            raise InvalidExpectedDataException("waiting license packet")
            
        if self._licenceManager.recv(s):
            self.setNextState()
            #end of connection step of 
            self._presentation.connect()

class Server(SecLayer):
    """
    @summary: Client side of security layer
    """
    def __init__(self, presentation):
        """
        @param presentation: {Layer}
        """
        SecLayer.__init__(self, presentation)
        self._rsaPublicKey, self._rsaPrivateKey = rsa.newkeys(512)
            
    def connect(self):
        """
        @summary: init automata to wait info packet
        """
        self._enableEncryption = self.getGCCClientSettings().CS_CORE.serverSelectedProtocol == 0
        if self._enableEncryption:
            self.setNextState(self.recvClientRandom)
        else:
            self.setNextState(self.recvInfoPkt)
            
    def getCertificate(self):
        """
        @summary: generate proprietary certificate from rsa public key
        """
        certificate = gcc.ProprietaryServerCertificate()
        certificate.PublicKeyBlob.modulus.value = rsa.int2bytes(self._rsaPublicKey.n)[::-1]
        certificate.PublicKeyBlob.pubExp.value = self._rsaPublicKey.e
        certificate.sign()
        return gcc.ServerCertificate(certificate)
        
    def recvClientRandom(self, s):
        """
        @summary: receive client random and generate session keys
        @param s: {Stream}
        """
        #packet preambule
        securityFlag = UInt16Le()
        securityFlagHi = UInt16Le()
        s.readType((securityFlag, securityFlagHi))
        
        if not (securityFlag.value & SecurityFlag.SEC_EXCHANGE_PKT):
            raise InvalidExpectedDataException("waiting client random")
        
        message = ClientSecurityExchangePDU()
        s.readType(message)
        clientRandom = rsa.decrypt(message.encryptedClientRandom.value[::-1], self._rsaPrivateKey)[::-1]
        
        self._macKey, self._initialEncryptKey, self._initialDecrytKey = generateKeys(   clientRandom, 
                                                                                        self.getGCCServerSettings().SC_SECURITY.serverRandom.value, 
                                                                                        self.getGCCServerSettings().SC_SECURITY.encryptionMethod.value)
        #initialize keys
        self._currentDecrytKey = self._initialDecrytKey
        self._currentEncryptKey = self._initialEncryptKey
        self._decryptRc4 = rc4.RC4Key(self._currentDecrytKey)
        self._encryptRc4 = rc4.RC4Key(self._currentEncryptKey)
        
        self.setNextState(self.recvInfoPkt)
        
    def recvInfoPkt(self, s):
        """
        @summary: receive info packet from client
        Client credentials
        Send License valid error message
        Send Demand Active PDU
        Wait Confirm Active PDU
        @param s: {Stream}
        """
        securityFlag = UInt16Le()
        securityFlagHi = UInt16Le()
        s.readType((securityFlag, securityFlagHi))
        
        if not (securityFlag.value & SecurityFlag.SEC_INFO_PKT):
            raise InvalidExpectedDataException("Waiting info packet")
        
        if securityFlag.value & SecurityFlag.SEC_ENCRYPT:
            s = self.readEncryptedPayload(s, securityFlag.value & SecurityFlag.SEC_SECURE_CHECKSUM)
        
        s.readType(self._info)
        #next state send error license
        self.sendLicensingErrorMessage()
        #reinit state
        self.setNextState()
        self._presentation.connect()
        
    def sendLicensingErrorMessage(self):
        """
        @summary: Send a licensing error data
        """
        self.sendFlagged(SecurityFlag.SEC_LICENSE_PKT, lic.createValidClientLicensingErrorMessage())