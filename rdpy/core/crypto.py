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
import Crypto.Random
import md5
import sha
from enum import IntEnum

from rdpy.core import rc4
from rdpy.core.subject import Subject
from rdpy.core.type import StringStream, UInt32Le
from rdpy.enum.rdp import RDPSecurityFlags, EncryptionMethod
from rdpy.exceptions import StateError

"""
Cryptographic utility functions
"""


class SecuritySettingsObserver:
    def onCrypterGenerated(self, settings):
        pass

class SecuritySettings(Subject):
    class Mode(IntEnum):
        CLIENT = 0
        SERVER = 1

    def __init__(self, mode):
        """
        :type mode: SecuritySettings.Mode
        """
        Subject.__init__(self)
        self.mode = mode
        self.encryptionMethod = None
        self.clientRandom = None
        self.serverRandom = None
        self.publicKey = None
        self.crypter = None

    def generateCrypter(self):
        if self.mode == SecuritySettings.Mode.CLIENT:
            self.crypter = RC4Crypter.generateClient(self.clientRandom, self.serverRandom, self.encryptionMethod)
        else:
            self.crypter = RC4Crypter.generateServer(self.clientRandom, self.serverRandom, self.encryptionMethod)

        if self.observer:
            self.observer.onCrypterGenerated(self)

    def generateClientRandom(self):
        self.setClientRandom(Crypto.Random.get_random_bytes(32))

    def generateServerRandom(self):
        self.setServerRandom(Crypto.Random.get_random_bytes(32))

    def encryptClientRandom(self):
        # Client random is stored as little-endian but crypto functions expect it to be in big-endian format.
        return self.publicKey.encrypt(self.clientRandom[:: -1], 0)[0][:: -1]

    def serverSecurityReceived(self, security):
        self.encryptionMethod = security.encryptionMethod

        if security.serverCertificate:
            self.publicKey = security.serverCertificate.publicKey

        self.setServerRandom(security.serverRandom)

    def setServerRandom(self, random):
        self.serverRandom = random

        if self.clientRandom is not None and self.serverRandom is not None:
            self.generateCrypter()

    def setClientRandom(self, random):
        self.clientRandom = random

        if self.clientRandom is not None and self.serverRandom is not None:
            self.generateCrypter()

    def getCrypter(self):
        if self.crypter is None:
            raise StateError("The crypter was not generated. The crypter will be generated when the server random is received.")

        return self.crypter



class RC4:
    def __init__(self, encryptionMethod, macKey, key):
        self.encryptionMethod = encryptionMethod
        self.macKey = macKey
        self.initialBytes = key
        self.currentBytes = key
        self.key = rc4.RC4Key(key)
        self.operationCount = 0
    
    def encrypt(self, data):
        return rc4.crypt(self.key, data)
    
    def decrypt(self, data):
        return self.encrypt(data)
    
    def sign(self, data, salted):
        if salted:
            return macSaltedData(self.macKey, data, self.operationCount)[: 8]
        else:
            return macData(self.macKey, data)[: 8]
    
    def verify(self, data, signature, salted):
        return signature[: 8] == self.sign(data, salted)
    
    def verifyPDU(self, pdu):
        verified = self.verify(pdu.payload, pdu.signature, pdu.header & RDPSecurityFlags.SEC_SECURE_CHECKSUM != 0)
    
    def increment(self):
        self.operationCount += 1

        if self.operationCount == 4096:
            self.currentBytes = updateKey(self.initialBytes, self.currentBytes, self.encryptionMethod)
            self.key = rc4.RC4Key(self.currentBytes)
            self.operationCount = 0

class RC4Crypter:
    def __init__(self, encryptionMethod, macKey, encryptKey, decryptKey):
        self.encryptionMethod = encryptionMethod
        self.macKey = macKey
        self.encryptKey = RC4(encryptionMethod, macKey, encryptKey)
        self.decryptKey = RC4(encryptionMethod, macKey, decryptKey)

    @staticmethod
    def generateClient(clientRandom, serverRandom, encryptionMethod):
        macKey, decryptKey, encryptKey = generateKeys(clientRandom, serverRandom, encryptionMethod)
        return RC4Crypter(encryptionMethod, macKey, encryptKey, decryptKey)

    @staticmethod
    def generateServer(clientRandom, serverRandom, encryptionMethod):
        macKey, encryptKey, decryptKey = generateKeys(clientRandom, serverRandom, encryptionMethod)
        return RC4Crypter(encryptionMethod, macKey, encryptKey, decryptKey)

    def encrypt(self, data):
        return self.encryptKey.encrypt(data)
    
    def decrypt(self, data):
        return self.decryptKey.decrypt(data)
    
    def sign(self, data, salted):
        return self.encryptKey.sign(data, salted)
    
    def verify(self, data, signature, salted):
        return self.decryptKey.verify(data, signature, salted)
    
    def addEncryption(self):
        self.encryptKey.increment()
    
    def addDecryption(self):
        self.decryptKey.increment()

class RC4CrypterProxy:
    def __init__(self):
        self.crypter = None

    def onCrypterGenerated(self, settings):
        self.crypter = settings.getCrypter()
        self.encrypt = self.crypter.encrypt
        self.decrypt = self.crypter.decrypt
        self.sign = self.crypter.sign
        self.verify = self.crypter.verify
        self.addEncryption = self.crypter.addEncryption
        self.addDecryption = self.crypter.addDecryption


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
    dataLength = StringStream()
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
    dataLengthS = StringStream()
    dataLengthS.writeType(UInt32Le(len(data)))
    
    encryptionCountS = StringStream()
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
    Generate cryptographic keys based on client and server random values and a method.
    See: http://msdn.microsoft.com/en-us/library/cc240785.aspx
    :param method: the EncryptionMethod value.
    :param clientRandom: the client random
    :param serverRandom: the server random
    :return: the mac key, the server-client encryption key and the client-server encryption key
    """
    preMasterHash = clientRandom[:24] + serverRandom[:24]
    masterHash = masterSecret(preMasterHash, clientRandom, serverRandom)
    sessionKey = sessionKeyBlob(masterHash, clientRandom, serverRandom)
    macKey128 = sessionKey[:16]
    initialFirstKey128 = finalHash(sessionKey[16:32], clientRandom, serverRandom)
    initialSecondKey128 = finalHash(sessionKey[32:48], clientRandom, serverRandom)
    
    #generate valid key
    if method == EncryptionMethod.ENCRYPTION_40BIT:
        return gen40bits(macKey128), gen40bits(initialFirstKey128), gen40bits(initialSecondKey128)
    
    elif method == EncryptionMethod.ENCRYPTION_56BIT:
        return gen56bits(macKey128), gen56bits(initialFirstKey128), gen56bits(initialSecondKey128)
    
    elif method == EncryptionMethod.ENCRYPTION_128BIT:
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
    if method == EncryptionMethod.ENCRYPTION_40BIT:
        tempKey128 = tempKey(initialKey[:8], currentKey[:8])
        return gen40bits(rc4.crypt(rc4.RC4Key(tempKey128[:8]), tempKey128[:8]))
    
    elif method == EncryptionMethod.ENCRYPTION_56BIT:
        tempKey128 = tempKey(initialKey[:8], currentKey[:8])
        return gen56bits(rc4.crypt(rc4.RC4Key(tempKey128[:8]), tempKey128[:8]))
    
    elif method == EncryptionMethod.ENCRYPTION_128BIT:
        tempKey128 = tempKey(initialKey, currentKey)
        return rc4.crypt(rc4.RC4Key(tempKey128), tempKey128)