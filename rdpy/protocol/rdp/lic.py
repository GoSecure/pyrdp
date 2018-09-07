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
@summary: RDP extended license
@see: http://msdn.microsoft.com/en-us/library/cc241880.aspx
"""

from rdpy.core.type import CompositeType, CallableValue, UInt8, UInt16Le, UInt32Le, String, sizeof, FactoryType, ArrayType, StringStream
from rdpy.core.error import InvalidExpectedDataException
import rdpy.core.log as log
import sec
from t125 import gcc
from rdpy.security import rc4
from rdpy.security import rsa_wrapper as rsa

class MessageType(object):
    """
    @summary: License packet message type
    """
    LICENSE_REQUEST = 0x01
    PLATFORM_CHALLENGE = 0x02
    NEW_LICENSE = 0x03
    UPGRADE_LICENSE = 0x04
    LICENSE_INFO = 0x12
    NEW_LICENSE_REQUEST = 0x13
    PLATFORM_CHALLENGE_RESPONSE = 0x15
    ERROR_ALERT = 0xFF
    
    
class ErrorCode(object):
    """
    @summary: License error message code
    @see: http://msdn.microsoft.com/en-us/library/cc240482.aspx
    """
    ERR_INVALID_SERVER_CERTIFICATE = 0x00000001
    ERR_NO_LICENSE = 0x00000002
    ERR_INVALID_SCOPE = 0x00000004
    ERR_NO_LICENSE_SERVER = 0x00000006
    STATUS_VALID_CLIENT = 0x00000007
    ERR_INVALID_CLIENT = 0x00000008
    ERR_INVALID_PRODUCTID = 0x0000000B
    ERR_INVALID_MESSAGE_LEN = 0x0000000C
    ERR_INVALID_MAC = 0x00000003
      
class StateTransition(object):
    """
    @summary: Automata state transition
    @see: http://msdn.microsoft.com/en-us/library/cc240482.aspx
    """
    ST_TOTAL_ABORT = 0x00000001
    ST_NO_TRANSITION = 0x00000002
    ST_RESET_PHASE_TO_START = 0x00000003
    ST_RESEND_LAST_MESSAGE = 0x00000004
    
class BinaryBlobType(object):
    """
    @summary: Binary blob data type
    @see: http://msdn.microsoft.com/en-us/library/cc240481.aspx
    """
    BB_ANY_BLOB = 0x0000
    BB_DATA_BLOB = 0x0001
    BB_RANDOM_BLOB = 0x0002
    BB_CERTIFICATE_BLOB = 0x0003
    BB_ERROR_BLOB = 0x0004
    BB_ENCRYPTED_DATA_BLOB = 0x0009
    BB_KEY_EXCHG_ALG_BLOB = 0x000D
    BB_SCOPE_BLOB = 0x000E
    BB_CLIENT_USER_NAME_BLOB = 0x000F
    BB_CLIENT_MACHINE_NAME_BLOB = 0x0010

class Preambule(object):
    """
    @summary: Preambule version
    """
    PREAMBLE_VERSION_2_0 = 0x2
    PREAMBLE_VERSION_3_0 = 0x3
    EXTENDED_ERROR_MSG_SUPPORTED = 0x80
    
class LicenseBinaryBlob(CompositeType):
    """
    @summary: Blob use by license manager to exchange security data
    @see: http://msdn.microsoft.com/en-us/library/cc240481.aspx
    """
    def __init__(self, blobType = BinaryBlobType.BB_ANY_BLOB, optional = False):
        CompositeType.__init__(self, optional = optional)
        self.wBlobType = UInt16Le(blobType, constant = True if blobType != BinaryBlobType.BB_ANY_BLOB else False)
        self.wBlobLen = UInt16Le(lambda:sizeof(self.blobData))
        self.blobData = String(readLen = self.wBlobLen)

class LicensingErrorMessage(CompositeType):
    """
    @summary: License error message
    @see: http://msdn.microsoft.com/en-us/library/cc240482.aspx
    """
    _MESSAGE_TYPE_ = MessageType.ERROR_ALERT
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.dwErrorCode = UInt32Le()
        self.dwStateTransition = UInt32Le()
        self.blob = LicenseBinaryBlob(BinaryBlobType.BB_ANY_BLOB)
        
class ProductInformation(CompositeType):
    """
    @summary: License server product information
    @see: http://msdn.microsoft.com/en-us/library/cc241915.aspx
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.dwVersion = UInt32Le()
        self.cbCompanyName = UInt32Le(lambda:sizeof(self.pbCompanyName))
        #may contain "Microsoft Corporation" from server microsoft
        self.pbCompanyName = String("Microsoft Corporation", readLen = self.cbCompanyName, unicode = True)
        self.cbProductId = UInt32Le(lambda:sizeof(self.pbProductId))
        #may contain "A02" from microsoft license server
        self.pbProductId = String("A02", readLen = self.cbProductId, unicode = True)


class Scope(CompositeType):
    """
    @summary: Use in license nego
    @see: http://msdn.microsoft.com/en-us/library/cc241917.aspx
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.scope = LicenseBinaryBlob(BinaryBlobType.BB_SCOPE_BLOB)
              
class ScopeList(CompositeType):
    """
    @summary: Use in license nego
    @see: http://msdn.microsoft.com/en-us/library/cc241916.aspx
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.scopeCount = UInt32Le(lambda:sizeof(self.scopeArray))
        self.scopeArray = ArrayType(Scope, readLen = self.scopeCount)
        
class ServerLicenseRequest(CompositeType):
    """
    @summary:  Send by server to signal license request
                server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc241914.aspx
    """
    _MESSAGE_TYPE_ = MessageType.LICENSE_REQUEST
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.serverRandom = String("\x00" * 32, readLen = CallableValue(32))
        self.productInfo = ProductInformation()
        self.keyExchangeList = LicenseBinaryBlob(BinaryBlobType.BB_KEY_EXCHG_ALG_BLOB)
        self.serverCertificate = LicenseBinaryBlob(BinaryBlobType.BB_CERTIFICATE_BLOB)
        self.scopeList = ScopeList()
        
class ClientNewLicenseRequest(CompositeType):
    """
    @summary:  Send by client to ask new license for client.
                RDPY doesn'support license reuse, need it in futur version
    @see: http://msdn.microsoft.com/en-us/library/cc241918.aspx
    """
    _MESSAGE_TYPE_ = MessageType.NEW_LICENSE_REQUEST
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        #RSA and must be only RSA
        self.preferredKeyExchangeAlg = UInt32Le(0x00000001, constant = True)
        #pure microsoft client ;-)
        #http://msdn.microsoft.com/en-us/library/1040af38-c733-4fb3-acd1-8db8cc979eda#id10
        self.platformId = UInt32Le(0x04000000 | 0x00010000)
        self.clientRandom = String("\x00" * 32, readLen = CallableValue(32))
        self.encryptedPreMasterSecret = LicenseBinaryBlob(BinaryBlobType.BB_RANDOM_BLOB)
        self.ClientUserName = LicenseBinaryBlob(BinaryBlobType.BB_CLIENT_USER_NAME_BLOB)
        self.ClientMachineName = LicenseBinaryBlob(BinaryBlobType.BB_CLIENT_MACHINE_NAME_BLOB)
        
class ServerPlatformChallenge(CompositeType):
    """
    @summary: challenge send from server to client
    @see: http://msdn.microsoft.com/en-us/library/cc241921.aspx
    """
    _MESSAGE_TYPE_ = MessageType.PLATFORM_CHALLENGE
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.connectFlags = UInt32Le()
        self.encryptedPlatformChallenge = LicenseBinaryBlob(BinaryBlobType.BB_ANY_BLOB)
        self.MACData = String(readLen = CallableValue(16))

class ClientPLatformChallengeResponse(CompositeType):
    """
    @summary: client challenge response
    @see: http://msdn.microsoft.com/en-us/library/cc241922.aspx
    """
    _MESSAGE_TYPE_ = MessageType.PLATFORM_CHALLENGE_RESPONSE
    
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.encryptedPlatformChallengeResponse = LicenseBinaryBlob(BinaryBlobType.BB_DATA_BLOB)
        self.encryptedHWID = LicenseBinaryBlob(BinaryBlobType.BB_DATA_BLOB)
        self.MACData = String(readLen = CallableValue(16))

class LicPacket(CompositeType):
    """
    @summary: A license packet
    """
    def __init__(self, message = None):
        CompositeType.__init__(self)
        #preambule
        self.bMsgtype = UInt8(lambda:self.licensingMessage.__class__._MESSAGE_TYPE_)
        self.flag = UInt8(Preambule.PREAMBLE_VERSION_3_0)
        self.wMsgSize = UInt16Le(lambda: sizeof(self))
        
        def LicensingMessageFactory():
            """
            @summary: factory for message nego
            Use in read mode
            """
            for c in [LicensingErrorMessage, ServerLicenseRequest, ClientNewLicenseRequest, ServerPlatformChallenge, ClientPLatformChallengeResponse]:
                if self.bMsgtype.value == c._MESSAGE_TYPE_:
                    return c(readLen = self.wMsgSize - 4)
            log.debug("unknown license message : %s"%self.bMsgtype.value)
            return String(readLen = self.wMsgSize - 4)
        
        if message is None:
            message = FactoryType(LicensingMessageFactory)
        elif not "_MESSAGE_TYPE_" in message.__class__.__dict__:
            raise InvalidExpectedDataException("Try to send an invalid license message")
            
        self.licensingMessage = message
        
def createValidClientLicensingErrorMessage():
        """
        @summary: Create a licensing error message that accept client
        server automata message
        """
        message = LicensingErrorMessage()
        message.dwErrorCode.value = ErrorCode.STATUS_VALID_CLIENT
        message.dwStateTransition.value = StateTransition.ST_NO_TRANSITION
        return LicPacket(message)
        
class LicenseManager(object):
    """
    @summary: handle license automata (client side)
    @see: http://msdn.microsoft.com/en-us/library/cc241890.aspx
    """
    def __init__(self, transport):
        """
        @param transport: layer use to send packet
        """
        self._transport = transport
        self._username = ""
        self._hostname = ""
 
    def recv(self, s):
        """
        @summary: receive license packet from PDU layer
        @return true when license automata is finish
        """            
        licPacket = LicPacket()
        s.readType(licPacket)
        
        #end of automata
        if licPacket.bMsgtype.value == MessageType.ERROR_ALERT and licPacket.licensingMessage.dwErrorCode.value == ErrorCode.STATUS_VALID_CLIENT and licPacket.licensingMessage.dwStateTransition.value == StateTransition.ST_NO_TRANSITION:
            return True
        
        elif licPacket.bMsgtype.value == MessageType.LICENSE_REQUEST:
            self.sendClientNewLicenseRequest(licPacket.licensingMessage)
            return False
            
        elif licPacket.bMsgtype.value == MessageType.PLATFORM_CHALLENGE:
            self.sendClientChallengeResponse(licPacket.licensingMessage)
            return False
        
        #yes get a new license
        elif licPacket.bMsgtype.value == MessageType.NEW_LICENSE:
            return True
        
        else:
            raise InvalidExpectedDataException("Not a valid license packet")
        
    
    def sendClientNewLicenseRequest(self, licenseRequest):
        """
        @summary: Create new license request in response to server license request
        @param licenseRequest: {ServerLicenseRequest}
        @see: http://msdn.microsoft.com/en-us/library/cc241989.aspx
        @see: http://msdn.microsoft.com/en-us/library/cc241918.aspx
        """
        #get server information
        serverRandom = licenseRequest.serverRandom.value
        if self._transport.getGCCServerSettings().SC_SECURITY.serverCertificate._is_readed:
            serverCertificate = self._transport.getGCCServerSettings().SC_SECURITY.serverCertificate
        else:
            s = StringStream(licenseRequest.serverCertificate.blobData.value)
            serverCertificate = gcc.ServerCertificate()
            s.readType(serverCertificate)
        
        #generate crypto values
        clientRandom = rsa.random(256)
        preMasterSecret = rsa.random(384)
        masterSecret = sec.masterSecret(preMasterSecret, clientRandom, serverRandom)
        sessionKeyBlob = sec.masterSecret(masterSecret, serverRandom, clientRandom)
        self._macSalt = sessionKeyBlob[:16]
        self._licenseKey = sec.finalHash(sessionKeyBlob[16:32], clientRandom, serverRandom)
        
        #format message
        message = ClientNewLicenseRequest()
        message.clientRandom.value = clientRandom
        message.encryptedPreMasterSecret.blobData.value = rsa.encrypt(preMasterSecret[::-1], serverCertificate.certData.getPublicKey())[::-1] + "\x00" * 8
        message.ClientMachineName.blobData.value = self._hostname + "\x00"
        message.ClientUserName.blobData.value = self._username + "\x00"
        self._transport.sendFlagged(sec.SecurityFlag.SEC_LICENSE_PKT, LicPacket(message))
        
    def sendClientChallengeResponse(self, platformChallenge):
        """
        @summary: generate valid challenge response
        @param platformChallenge: {ServerPlatformChallenge}
        """
        serverEncryptedChallenge = platformChallenge.encryptedPlatformChallenge.blobData.value
        #decrypt server challenge
        #it should be TEST word in unicode format
        serverChallenge = rc4.crypt(rc4.RC4Key(self._licenseKey), serverEncryptedChallenge)
        if serverChallenge != "T\x00E\x00S\x00T\x00\x00\x00":
            raise InvalidExpectedDataException("bad license server challenge")
        
        #generate hwid
        s = StringStream()
        s.writeType((UInt32Le(2), String(self._hostname + self._username + "\x00" * 16)))
        hwid = s.getvalue()[:20]
        
        message = ClientPLatformChallengeResponse()
        message.encryptedPlatformChallengeResponse.blobData.value = serverEncryptedChallenge
        message.encryptedHWID.blobData.value = rc4.crypt(rc4.RC4Key(self._licenseKey), hwid)
        message.MACData.value = sec.macData(self._macSalt, serverChallenge + hwid)
        
        self._transport.sendFlagged(sec.SecurityFlag.SEC_LICENSE_PKT, LicPacket(message))