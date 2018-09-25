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
Implement GCC structure use in RDP protocol
http://msdn.microsoft.com/en-us/library/cc240508.aspx
"""

import md5
from rdpy.core.type import UInt8, UInt16Le, UInt32Le, CompositeType, CallableValue, String, StringStream, sizeof, FactoryType, ArrayType
import per, mcs
from rdpy.core.error import InvalidExpectedDataException
from rdpy.core import log
from rdpy.security import x509
import rdpy.security.rsa_wrapper as rsa

t124_02_98_oid = ( 0, 0, 20, 124, 0, 1 )

h221_cs_key = "Duca";
h221_sc_key = "McDn";

class MessageType(object):
    """
    @summary: Server to Client block 
    GCC conference messages
    @see: http://msdn.microsoft.com/en-us/library/cc240509.aspx
    """
    #server -> client
    SC_CORE = 0x0C01
    SC_SECURITY = 0x0C02
    SC_NET = 0x0C03
    #client -> server
    CS_CORE = 0xC001
    CS_SECURITY = 0xC002
    CS_NET = 0xC003
    CS_CLUSTER = 0xC004
    CS_MONITOR = 0xC005
    

class ColorDepth(object):
    """
    @summary: Depth color
    @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    """
    RNS_UD_COLOR_8BPP = 0xCA01
    RNS_UD_COLOR_16BPP_555 = 0xCA02
    RNS_UD_COLOR_16BPP_565 = 0xCA03
    RNS_UD_COLOR_24BPP = 0xCA04
    
class HighColor(object):
    """
    @summary: High color of client
    @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    """
    HIGH_COLOR_4BPP = 0x0004
    HIGH_COLOR_8BPP = 0x0008
    HIGH_COLOR_15BPP = 0x000f
    HIGH_COLOR_16BPP = 0x0010
    HIGH_COLOR_24BPP = 0x0018

class Support(object):
    """
    @summary: Supported depth flag
    @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    """
    RNS_UD_24BPP_SUPPORT = 0x0001
    RNS_UD_16BPP_SUPPORT = 0x0002
    RNS_UD_15BPP_SUPPORT = 0x0004
    RNS_UD_32BPP_SUPPORT = 0x0008

class CapabilityFlags(object):
    """
    @summary: For more details on each flags click above
    @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    """
    RNS_UD_CS_SUPPORT_ERRINFO_PDU = 0x0001
    RNS_UD_CS_WANT_32BPP_SESSION = 0x0002
    RNS_UD_CS_SUPPORT_STATUSINFO_PDU = 0x0004
    RNS_UD_CS_STRONG_ASYMMETRIC_KEYS = 0x0008
    RNS_UD_CS_UNUSED = 0x0010
    RNS_UD_CS_VALID_CONNECTION_TYPE = 0x0020
    RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU = 0x0040
    RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT = 0x0080
    RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL = 0x0100
    RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE = 0x0200
    RNS_UD_CS_SUPPORT_HEARTBEAT_PDU = 0x0400

class ConnectionType(object):
    """
    @summary: This information is correct if 
    RNS_UD_CS_VALID_CONNECTION_TYPE flag is set on capabilityFlag
    @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    """
    CONNECTION_TYPE_MODEM = 0x01
    CONNECTION_TYPE_BROADBAND_LOW = 0x02
    CONNECTION_TYPE_SATELLITE = 0x03
    CONNECTION_TYPE_BROADBAND_HIGH = 0x04
    CONNECTION_TYPE_WAN = 0x05
    CONNECTION_TYPE_LAN = 0x06
    CONNECTION_TYPE_AUTODETECT = 0x07

class Version(object):
    """
    @summary: Supported version of RDP
    @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    """
    RDP_VERSION_4 = 0x00080001
    RDP_VERSION_5_PLUS = 0x00080004

class Sequence(object):
    RNS_UD_SAS_DEL = 0xAA03
     
class EncryptionMethod(object):
    """
    @summary: Encryption methods supported
    @see: http://msdn.microsoft.com/en-us/library/cc240511.aspx
    """
    ENCRYPTION_FLAG_40BIT = 0x00000001
    ENCRYPTION_FLAG_128BIT = 0x00000002
    ENCRYPTION_FLAG_56BIT = 0x00000008
    FIPS_ENCRYPTION_FLAG = 0x00000010
    
class EncryptionLevel(object):
    """
    @summary: level of 'security'
    @see: http://msdn.microsoft.com/en-us/library/cc240518.aspx
    """
    ENCRYPTION_LEVEL_NONE = 0x00000000
    ENCRYPTION_LEVEL_LOW = 0x00000001
    ENCRYPTION_LEVEL_CLIENT_COMPATIBLE = 0x00000002
    ENCRYPTION_LEVEL_HIGH = 0x00000003
    ENCRYPTION_LEVEL_FIPS = 0x00000004
       
class ChannelOptions(object):
    """
    @summary: Channel options
    @see: http://msdn.microsoft.com/en-us/library/cc240513.aspx
    """
    CHANNEL_OPTION_INITIALIZED = 0x80000000
    CHANNEL_OPTION_ENCRYPT_RDP = 0x40000000
    CHANNEL_OPTION_ENCRYPT_SC = 0x20000000
    CHANNEL_OPTION_ENCRYPT_CS = 0x10000000
    CHANNEL_OPTION_PRI_HIGH = 0x08000000
    CHANNEL_OPTION_PRI_MED = 0x04000000
    CHANNEL_OPTION_PRI_LOW = 0x02000000
    CHANNEL_OPTION_COMPRESS_RDP = 0x00800000
    CHANNEL_OPTION_COMPRESS = 0x00400000
    CHANNEL_OPTION_SHOW_PROTOCOL = 0x00200000
    REMOTE_CONTROL_PERSISTENT = 0x00100000
 
class KeyboardType(object):
    """
    @summary: Keyboard type
    @see: IBM_101_102_KEYS is the most common keyboard type
    """
    IBM_PC_XT_83_KEY = 0x00000001
    OLIVETTI = 0x00000002
    IBM_PC_AT_84_KEY = 0x00000003
    IBM_101_102_KEYS = 0x00000004
    NOKIA_1050 = 0x00000005
    NOKIA_9140 = 0x00000006
    JAPANESE = 0x00000007
  
class KeyboardLayout(object):
    """
    @summary: Keyboard layout definition
    @see: http://technet.microsoft.com/en-us/library/cc766503%28WS.10%29.aspx
    """
    ARABIC = 0x00000401
    BULGARIAN = 0x00000402
    CHINESE_US_KEYBOARD = 0x00000404
    CZECH = 0x00000405
    DANISH = 0x00000406
    GERMAN = 0x00000407
    GREEK = 0x00000408
    US = 0x00000409
    SPANISH = 0x0000040a
    FINNISH = 0x0000040b
    FRENCH = 0x0000040c
    HEBREW = 0x0000040d
    HUNGARIAN = 0x0000040e
    ICELANDIC = 0x0000040f
    ITALIAN = 0x00000410
    JAPANESE = 0x00000411
    KOREAN = 0x00000412
    DUTCH = 0x00000413
    NORWEGIAN = 0x00000414
    
class CertificateType(object):
    """
    @see: http://msdn.microsoft.com/en-us/library/cc240521.aspx
    """
    CERT_CHAIN_VERSION_1 = 0x00000001
    CERT_CHAIN_VERSION_2 = 0x00000002
    
class DataBlock(CompositeType):
    """
    @summary: Block settings
    """
    def __init__(self, dataBlock = None):
        CompositeType.__init__(self)
        self.type = UInt16Le(lambda:self.dataBlock.__class__._TYPE_)
        self.length = UInt16Le(lambda:sizeof(self))
        
        def DataBlockFactory():
            """
            @summary: build settings in accordance of type self.type.value
            """
            for c in [ClientCoreData, ClientSecurityData, ClientNetworkData, ServerCoreData, ServerNetworkData, ServerSecurityData]:
                if self.type.value == c._TYPE_:
                    return c(readLen = self.length - 4)
            log.debug("unknown GCC block type : %s"%hex(self.type.value))
            #read entire packet
            return String(readLen = self.length - 4)
        
        if dataBlock is None:
            dataBlock = FactoryType(DataBlockFactory)
        elif not "_TYPE_" in dataBlock.__class__.__dict__:
            raise InvalidExpectedDataException("Try to send an invalid GCC blocks")
        
        self.dataBlock = dataBlock

class ClientCoreData(CompositeType):
    """
    @summary: Class that represent core setting of client
    @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    """
    _TYPE_ = MessageType.CS_CORE
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.rdpVersion = UInt32Le(Version.RDP_VERSION_5_PLUS)
        self.desktopWidth = UInt16Le(1280)
        self.desktopHeight = UInt16Le(800)
        self.colorDepth = UInt16Le(ColorDepth.RNS_UD_COLOR_8BPP)
        self.sasSequence = UInt16Le(Sequence.RNS_UD_SAS_DEL)
        self.kbdLayout = UInt32Le(KeyboardLayout.US)
        self.clientBuild = UInt32Le(3790)
        self.clientName = String("rdpy" + "\x00"*11, readLen = CallableValue(32), unicode = True)
        self.keyboardType = UInt32Le(KeyboardType.IBM_101_102_KEYS)
        self.keyboardSubType = UInt32Le(0)
        self.keyboardFnKeys = UInt32Le(12)
        self.imeFileName = String("\x00"*64, readLen = CallableValue(64), optional = True)
        self.postBeta2ColorDepth = UInt16Le(ColorDepth.RNS_UD_COLOR_8BPP, optional = True)
        self.clientProductId = UInt16Le(1, optional = True)
        self.serialNumber = UInt32Le(0, optional = True)
        self.highColorDepth = UInt16Le(HighColor.HIGH_COLOR_24BPP, optional = True)
        self.supportedColorDepths = UInt16Le(Support.RNS_UD_15BPP_SUPPORT | Support.RNS_UD_16BPP_SUPPORT | Support.RNS_UD_24BPP_SUPPORT | Support.RNS_UD_32BPP_SUPPORT, optional = True)
        self.earlyCapabilityFlags = UInt16Le(CapabilityFlags.RNS_UD_CS_SUPPORT_ERRINFO_PDU, optional = True)
        self.clientDigProductId = String("\x00"*64, readLen = CallableValue(64), optional = True)
        self.connectionType = UInt8(optional = True)
        self.pad1octet = UInt8(optional = True)
        self.serverSelectedProtocol = UInt32Le(optional = True)
    
    def __getitem__(self, item):
        return getattr(self, item).value

class ServerCoreData(CompositeType):
    """
    @summary: Server side core settings structure
    @see: http://msdn.microsoft.com/en-us/library/cc240517.aspx
    """
    _TYPE_ = MessageType.SC_CORE
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.rdpVersion = UInt32Le(Version.RDP_VERSION_5_PLUS)
        self.clientRequestedProtocol = UInt32Le(optional = True)
        self.earlyCapabilityFlags = UInt32Le(optional = True)
        
class ClientSecurityData(CompositeType):
    """
    @summary: Client security setting
    @see: http://msdn.microsoft.com/en-us/library/cc240511.aspx
    """
    _TYPE_ = MessageType.CS_SECURITY
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.encryptionMethods = UInt32Le(EncryptionMethod.ENCRYPTION_FLAG_40BIT | EncryptionMethod.ENCRYPTION_FLAG_56BIT | EncryptionMethod.ENCRYPTION_FLAG_128BIT)
        self.extEncryptionMethods = UInt32Le()
        
class ServerSecurityData(CompositeType):
    """
    @summary: Server security settings
    @see: http://msdn.microsoft.com/en-us/library/cc240518.aspx
    """
    _TYPE_ = MessageType.SC_SECURITY
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.encryptionMethod = UInt32Le()
        self.encryptionLevel = UInt32Le() 
        self.serverRandomLen = UInt32Le(0x00000020, constant = True, conditional = lambda:not(self.encryptionMethod.value == 0 and self.encryptionLevel == 0))
        self.serverCertLen = UInt32Le(lambda:sizeof(self.serverCertificate), conditional = lambda:not(self.encryptionMethod.value == 0 and self.encryptionLevel == 0))
        self.serverRandom = String(readLen = self.serverRandomLen, conditional = lambda:not(self.encryptionMethod.value == 0 and self.encryptionLevel == 0))
        self.serverCertificate = ServerCertificate(readLen = self.serverCertLen, conditional = lambda:not(self.encryptionMethod.value == 0 and self.encryptionLevel == 0))

class ServerCertificate(CompositeType):
    """
    @summary: Server certificate structure
    @see: http://msdn.microsoft.com/en-us/library/cc240521.aspx
    """
    def __init__(self, certData = None, readLen = None, conditional = lambda:True):
        CompositeType.__init__(self, readLen = readLen, conditional = conditional)
        self.dwVersion = UInt32Le(lambda:(self.certData.__class__._TYPE_))
        
        def CertificateFactory():
            """
            Closure for capability factory
            """
            for c in [ProprietaryServerCertificate, X509CertificateChain]:
                if self.dwVersion.value & 0x7fffffff == c._TYPE_:
                    return c()
            raise InvalidExpectedDataException("unknown certificate type : %s "%hex(self.dwVersion.value))
        
        if certData is None:
            certData = FactoryType(CertificateFactory)
        elif not "_TYPE_" in certData.__class__.__dict__:
            raise InvalidExpectedDataException("Try to send an invalid Certificate")
          
        self.certData = certData
        
class ProprietaryServerCertificate(CompositeType):
    """
    @summary: microsoft proprietary certificate
    @see: http://msdn.microsoft.com/en-us/library/cc240519.aspx
    """
    _TYPE_ = CertificateType.CERT_CHAIN_VERSION_1
    
    #http://msdn.microsoft.com/en-us/library/cc240776.aspx
    _TERMINAL_SERVICES_MODULUS_ = "\x3d\x3a\x5e\xbd\x72\x43\x3e\xc9\x4d\xbb\xc1\x1e\x4a\xba\x5f\xcb\x3e\x88\x20\x87\xef\xf5\xc1\xe2\xd7\xb7\x6b\x9a\xf2\x52\x45\x95\xce\x63\x65\x6b\x58\x3a\xfe\xef\x7c\xe7\xbf\xfe\x3d\xf6\x5c\x7d\x6c\x5e\x06\x09\x1a\xf5\x61\xbb\x20\x93\x09\x5f\x05\x6d\xea\x87"
    _TERMINAL_SERVICES_PRIVATE_EXPONENT_ = "\x87\xa7\x19\x32\xda\x11\x87\x55\x58\x00\x16\x16\x25\x65\x68\xf8\x24\x3e\xe6\xfa\xe9\x67\x49\x94\xcf\x92\xcc\x33\x99\xe8\x08\x60\x17\x9a\x12\x9f\x24\xdd\xb1\x24\x99\xc7\x3a\xb8\x0a\x7b\x0d\xdd\x35\x07\x79\x17\x0b\x51\x9b\xb3\xc7\x10\x01\x13\xe7\x3f\xf3\x5f"
    _TERMINAL_SERVICES_PUBLIC_EXPONENT_ = "\x5b\x7b\x88\xc0"
    
    def __init__(self):
        CompositeType.__init__(self)
        self.dwSigAlgId = UInt32Le(0x00000001, constant = True)
        self.dwKeyAlgId = UInt32Le(0x00000001, constant = True)
        self.wPublicKeyBlobType = UInt16Le(0x0006, constant = True)
        self.wPublicKeyBlobLen = UInt16Le(lambda:sizeof(self.PublicKeyBlob))
        self.PublicKeyBlob = RSAPublicKey(readLen = self.wPublicKeyBlobLen)
        self.wSignatureBlobType = UInt16Le(0x0008, constant = True)
        self.wSignatureBlobLen = UInt16Le(lambda:(sizeof(self.SignatureBlob) + sizeof(self.padding)))
        self.SignatureBlob = String(readLen = CallableValue(lambda:(self.wSignatureBlobLen.value - sizeof(self.padding))))
        self.padding = String(b"\x00" * 8, readLen = CallableValue(8))
        
    def getPublicKey(self):
        """
        @return: {Tuple} (modulus, publicExponent)
        """
        log.debug("read RSA public key from proprietary certificate")
        #reverse because bignum in little endian
        return rsa.PublicKey(self.PublicKeyBlob.pubExp.value, self.PublicKeyBlob.modulus.value[::-1])
    
    def computeSignatureHash(self):
        """
        @summary: compute hash
        """
        s = StringStream()
        s.writeType(UInt32Le(self.__class__._TYPE_))
        s.writeType(self.dwSigAlgId)
        s.writeType(self.dwKeyAlgId)
        s.writeType(self.wPublicKeyBlobType)
        s.writeType(self.wPublicKeyBlobLen)
        s.writeType(self.PublicKeyBlob)
    
        md5Digest = md5.new()
        md5Digest.update(s.getvalue())
        
        return md5Digest.digest() + "\x00" + "\xff" * 45 + "\x01"
        
    def sign(self):
        """
        @summary: sign proprietary certificate
        @see: http://msdn.microsoft.com/en-us/library/cc240778.aspx
        """
        self.SignatureBlob.value = rsa.sign(self.computeSignatureHash()[::-1], rsa.PrivateKey(d = ProprietaryServerCertificate._TERMINAL_SERVICES_PRIVATE_EXPONENT_[::-1], n = ProprietaryServerCertificate._TERMINAL_SERVICES_MODULUS_[::-1]))[::-1]
        
    def verify(self):
        """
        @summary: verify certificate signature
        """
        return rsa.verify(self.SignatureBlob.value[::-1], rsa.PublicKey(e = ProprietaryServerCertificate._TERMINAL_SERVICES_PUBLIC_EXPONENT_[::-1], n = ProprietaryServerCertificate._TERMINAL_SERVICES_MODULUS_[::-1]))[::-1] == self.computeSignatureHash()
        

class CertBlob(CompositeType):
    """
    @summary: certificate blob, contain x509 data
    @see: http://msdn.microsoft.com/en-us/library/cc241911.aspx
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.cbCert = UInt32Le(lambda:sizeof(self.abCert))
        self.abCert = String(readLen = self.cbCert)

class X509CertificateChain(CompositeType):
    """
    @summary: X509 certificate chain
    @see: http://msdn.microsoft.com/en-us/library/cc241910.aspx
    """
    _TYPE_ = CertificateType.CERT_CHAIN_VERSION_2
    
    def __init__(self):
        CompositeType.__init__(self)
        self.NumCertBlobs = UInt32Le()
        self.CertBlobArray = ArrayType(CertBlob, readLen = self.NumCertBlobs)
        self.padding = String(readLen = CallableValue(lambda:(8 + 4 * self.NumCertBlobs.value)))
        
    def getPublicKey(self):
        """
        @return: {Tuple} (modulus, publicExponent)
        """
        log.debug("read RSA public key from x509 certificate")
        #last certifcate contain public key
        n, e =  x509.extractRSAKey(x509.load(self.CertBlobArray[-1].abCert.value))
        return rsa.PublicKey(e, n)
    
    def verify(self):
        """
        @todo: verify x509 signature
        """
        return True
        
class RSAPublicKey(CompositeType):
    """
    @see: http://msdn.microsoft.com/en-us/library/cc240520.aspx
    """
    def __init__(self, readLen):
        CompositeType.__init__(self, readLen = readLen)
        #magic is RSA1(0x31415352)
        self.magic = UInt32Le(0x31415352, constant = True)
        self.keylen = UInt32Le(lambda:(sizeof(self.modulus) + sizeof(self.padding)))
        self.bitlen = UInt32Le(lambda:((self.keylen.value - 8) * 8))
        self.datalen = UInt32Le(lambda:((self.bitlen.value / 8) - 1))
        self.pubExp = UInt32Le()
        self.modulus = String(readLen = CallableValue(lambda:(self.keylen.value - 8)))
        self.padding = String("\x00" * 8, readLen = CallableValue(8))

class ChannelDef(CompositeType):
    """
    Channels structure share between client and server
    @see: http://msdn.microsoft.com/en-us/library/cc240513.aspx
    """
    def __init__(self, name = "", options = 0):
        CompositeType.__init__(self)
        #name of channel
        self.name = String(name[0:8] + "\x00" * (8 - len(name)), readLen = CallableValue(8))
        #unknown
        self.options = UInt32Le()
        
class ClientNetworkData(CompositeType):
    """
    @summary: GCC client network block
    All channels asked by client are listed here
    @see: http://msdn.microsoft.com/en-us/library/cc240512.aspx
    """
    _TYPE_ = MessageType.CS_NET
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.channelCount = UInt32Le(lambda:len(self.channelDefArray._array))
        self.channelDefArray = ArrayType(ChannelDef, readLen = self.channelCount)
        
class ServerNetworkData(CompositeType):
    """
    @summary: GCC server network block
    All channels asked by client are listed here
    @see: All channels asked by client are listed here
    """
    _TYPE_ = MessageType.SC_NET
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.MCSChannelId = UInt16Le(mcs.Channel.MCS_GLOBAL_CHANNEL)
        self.channelCount = UInt16Le(lambda:len(self.channelIdArray._array))
        self.channelIdArray = ArrayType(UInt16Le, readLen = self.channelCount)
        self.pad = UInt16Le(conditional = lambda:((self.channelCount.value % 2) == 1))
        
class Settings(CompositeType):
    """
    @summary: Class which group all clients settings supported by RDPY
    """
    def __init__(self, init = [], readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.settings = ArrayType(DataBlock, [DataBlock(i) for i in init])
    
    def getBlock(self, messageType):
        """
        @param messageType: type of block
        @return: specific block of type messageType
        """
        for i in self.settings._array:
            if i.type.value == messageType:
                return i.dataBlock
        return None
    
    def __getattr__(self, name):
        """
        @summary: Magic function for better access
        @return: _value parameter
        """
        if not name in MessageType.__dict__:
            return None
        return self.getBlock(MessageType.__dict__[name])
        
def clientSettings():
    """
    @summary: Build settings for client
    @return: Settings
    """
    return Settings([ClientCoreData(), ClientNetworkData(), ClientSecurityData()])

def serverSettings():
    """
    @summary: Build settings for server
    @return Settings
    """
    return Settings([ServerCoreData(), ServerSecurityData(), ServerNetworkData()])
        
def readConferenceCreateRequest(s):
    """
    @summary: Read a response from client
    GCC create request
    @param s: Stream
    @param client settings (Settings)
    """
    per.readChoice(s)
    per.readObjectIdentifier(s, t124_02_98_oid)
    per.readLength(s)
    per.readChoice(s)
    per.readSelection(s)
    per.readNumericString(s, 1)
    per.readPadding(s, 1)
    
    if per.readNumberOfSet(s) != 1:
        raise InvalidExpectedDataException("Invalid number of set in readConferenceCreateRequest")
    
    if per.readChoice(s) != 0xc0:
        raise InvalidExpectedDataException("Invalid choice in readConferenceCreateRequest")
    
    per.readOctetStream(s, h221_cs_key, 4)
    length = per.readLength(s)
    clientSettings = Settings(readLen = CallableValue(length))
    s.readType(clientSettings)
    return clientSettings
    
def readConferenceCreateResponse(s):
    """
    @summary: Read response from server
    and return server settings read from this response
    @param s: Stream
    @return: ServerSettings 
    """
    per.readChoice(s)
    per.readObjectIdentifier(s, t124_02_98_oid)
    per.readLength(s)
    per.readChoice(s)
    per.readInteger16(s, 1001)
    per.readInteger(s)
    per.readEnumerates(s)
    per.readNumberOfSet(s)
    per.readChoice(s)
    if not per.readOctetStream(s, h221_sc_key, 4):
        raise InvalidExpectedDataException("cannot read h221_sc_key")
    
    length = per.readLength(s)
    serverSettings = Settings(readLen = CallableValue(length))
    s.readType(serverSettings)
    return serverSettings

def writeConferenceCreateRequest(userData):
    """
    @summary: Write conference create request structure
    @param userData: Settings for client
    @return: GCC packet
    """
    userDataStream = StringStream()
    userDataStream.writeType(userData)
    
    return (per.writeChoice(0), per.writeObjectIdentifier(t124_02_98_oid),
            per.writeLength(len(userDataStream.getvalue()) + 14), per.writeChoice(0),
            per.writeSelection(0x08), per.writeNumericString("1", 1), per.writePadding(1),
            per.writeNumberOfSet(1), per.writeChoice(0xc0),
            per.writeOctetStream(h221_cs_key, 4), per.writeOctetStream(userDataStream.getvalue()))
    
def writeConferenceCreateResponse(serverData):
    """
    @summary: Write a conference create response packet
    @param serverData: Settings for server
    @return: gcc packet
    """
    serverDataStream = StringStream()
    serverDataStream.writeType(serverData)
    
    return (per.writeChoice(0), per.writeObjectIdentifier(t124_02_98_oid),
            per.writeLength(42), per.writeChoice(0x14),
            per.writeInteger16(0x79F3, 1001), per.writeInteger(1), per.writeEnumerates(0),
            per.writeNumberOfSet(1), per.writeChoice(0xc0),
            per.writeOctetStream(h221_sc_key, 4), per.writeOctetStream(serverDataStream.getvalue()))