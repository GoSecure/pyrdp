import Crypto.Random

from enum import IntEnum

from rdpy.core.observer import Observer
from rdpy.core.subject import Subject, ObservedBy
from rdpy.crypto import rc4
from rdpy.crypto.key import macData, macSaltedData, generateKeys, updateKey
from rdpy.enum.rdp import EncryptionMethod
from rdpy.exceptions import StateError, CrypterUnavailableError
from rdpy.pdu.rdp.connection import ServerSecurityData

"""
Cryptographic utility functions
"""


class SecuritySettingsObserver(Observer):
    """
    Observer class for SecuritySettings.
    """

    def onCrypterGenerated(self, settings):
        """
        Called when the SecuritySettings crypter has been generated.
        :param settings: the security settings object.
        :type settings: SecuritySettings
        """
        pass

@ObservedBy(SecuritySettingsObserver)
class SecuritySettings(Subject):
    """
    Class containing RDP standard security settings.
    """

    class Mode(IntEnum):
        """
        SecuritySettings mode (client or server).
        """
        CLIENT = 0
        SERVER = 1

    def __init__(self, mode):
        """
        :param mode: the settings mode.
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
        """
        Generate a crypter with the current settings.
        """
        if self.mode == SecuritySettings.Mode.CLIENT:
            self.crypter = RC4Crypter.generateClient(self.clientRandom, self.serverRandom, self.encryptionMethod)
        else:
            self.crypter = RC4Crypter.generateServer(self.clientRandom, self.serverRandom, self.encryptionMethod)

        if self.observer:
            self.observer.onCrypterGenerated(self)

    def generateClientRandom(self):
        """
        Generate client random data.
        """
        self.setClientRandom(Crypto.Random.get_random_bytes(32))

    def generateServerRandom(self):
        """
        Generate server random data.
        """
        self.setServerRandom(Crypto.Random.get_random_bytes(32))

    def encryptClientRandom(self):
        """
        Encrypt the client random using the public key.
        :return: str
        """
        # Client random is stored as little-endian but crypto functions expect it to be in big-endian format.
        return self.publicKey.encrypt(self.clientRandom[:: -1], 0)[0][:: -1]

    def serverSecurityReceived(self, security):
        """
        Called when a ServerSecurityData is received.
        :param security: the RDP server's security data.
        :type security: ServerSecurityData
        """
        self.encryptionMethod = security.encryptionMethod

        if security.serverCertificate:
            self.publicKey = security.serverCertificate.publicKey

        self.setServerRandom(security.serverRandom)

    def setServerRandom(self, random):
        """
        Set the serverRandom attribute.
        :param random: server random data.
        :type random: str
        """
        self.serverRandom = random

        if self.clientRandom is not None and self.serverRandom is not None:
            self.generateCrypter()

    def setClientRandom(self, random):
        """
        Set the clientRandom attribute.
        :param random: client random data.
        :type random: str
        """
        self.clientRandom = random

        if self.clientRandom is not None and self.serverRandom is not None:
            self.generateCrypter()

    def getCrypter(self):
        """
        Get the current crypter object.
        :return: RC4Crypter
        """
        if self.crypter is None:
            raise StateError("The crypter was not generated. The crypter will be generated when the server random is received.")

        return self.crypter



class RC4:
    """
    Class for encrypting or decrypting data with RC4.
    """

    def __init__(self, encryptionMethod, macKey, key):
        """
        :param encryptionMethod: the encryption method
        :type encryptionMethod: EncryptionMethod
        :param macKey: the key used for salted signatures.
        :type macKey: str
        :param key: the initial encryption key.
        :type key: str
        """
        self.encryptionMethod = encryptionMethod
        self.macKey = macKey
        self.initialBytes = key
        self.currentBytes = key
        self.key = rc4.RC4Key(key)
        self.operationCount = 0
    
    def encrypt(self, data):
        """
        Encrypt data.
        :param data: plaintext data to encrypt.
        :type data: str
        :return: str
        """
        return rc4.crypt(self.key, data)
    
    def decrypt(self, data):
        """
        Decrypt data.
        :param data: ciphertext to decrypt.
        :type data: str
        :return: str
        """
        return self.encrypt(data)
    
    def sign(self, data, salted):
        """
        Generate a signature for a message.
        :param data: plaintext data to sign.
        :type data: str
        :param salted: True if the signature should be salted.
        :type salted: bool
        :return: str
        """
        if salted:
            return macSaltedData(self.macKey, data, self.operationCount)[: 8]
        else:
            return macData(self.macKey, data)[: 8]
    
    def verify(self, data, signature, salted):
        """
        Verify a signature.
        :param data: plaintext data to verify.
        :type data: str
        :param signature: the signature to verify.
        :type signature: str
        :param salted: True if the signature is salted.
        :type salted: bool
        :return: bool
        """
        return signature[: 8] == self.sign(data, salted)
    
    def increment(self):
        """
        Increment the operation count and update the key if necessary.
        """
        self.operationCount += 1

        if self.operationCount == 4096:
            self.currentBytes = updateKey(self.initialBytes, self.currentBytes, self.encryptionMethod)
            self.key = rc4.RC4Key(self.currentBytes)
            self.operationCount = 0

class RC4Crypter:
    """
    Class containing RC4 keys for both sides of a communication. Chooses the correct key based on the operation.
    """

    def __init__(self, encryptionMethod, macKey, encryptKey, decryptKey):
        """
        :param encryptionMethod: the encryption method.
        :type encryptionMethod: EncryptionMethod
        :param macKey: the signing key.
        :type macKey: str
        :param encryptKey: the encryption key.
        :type encryptKey: str
        :param decryptKey: the decryption key.
        :type decryptKey: str
        """
        self.encryptionMethod = encryptionMethod
        self.macKey = macKey
        self.encryptKey = RC4(encryptionMethod, macKey, encryptKey)
        self.decryptKey = RC4(encryptionMethod, macKey, decryptKey)

    @staticmethod
    def generateClient(clientRandom, serverRandom, encryptionMethod):
        """
        Generate an RC4Crypter instance for RDP clients.
        :param clientRandom: the client random data.
        :type clientRandom: str
        :param serverRandom: the server random data.
        :type serverRandom: str
        :param encryptionMethod: the encryption method.
        :type encryptionMethod: EncryptionMethod
        :return: RC4Crypter
        """
        macKey, decryptKey, encryptKey = generateKeys(clientRandom, serverRandom, encryptionMethod)
        return RC4Crypter(encryptionMethod, macKey, encryptKey, decryptKey)

    @staticmethod
    def generateServer(clientRandom, serverRandom, encryptionMethod):
        """
        Generate an RC4Crypter instance for RDP servers.
        :param clientRandom: the client random data.
        :type clientRandom: str
        :param serverRandom: the server random data.
        :type serverRandom: str
        :param encryptionMethod: the encryption method.
        :type encryptionMethod: EncryptionMethod
        :return: RC4Crypter
        """
        macKey, encryptKey, decryptKey = generateKeys(clientRandom, serverRandom, encryptionMethod)
        return RC4Crypter(encryptionMethod, macKey, encryptKey, decryptKey)

    def encrypt(self, data):
        """
        Encrypt data. The addEncryption method should be called before the next encryption.
        :param data: plaintext to encrypt.
        :type data: str
        :return: str
        """
        return self.encryptKey.encrypt(data)
    
    def decrypt(self, data):
        """
        Decrypt data. The addDecryption method should be called before the next decryption.
        :param data: plaintext to decrypt.
        :type data: str
        :return: str
        """
        return self.decryptKey.decrypt(data)
    
    def sign(self, data, salted):
        """
        Generate a signature for a message.
        :param data: plaintext to sign.
        :type data: str
        :param salted: True if the signature should be salted.
        :type salted: bool
        :return: str
        """
        return self.encryptKey.sign(data, salted)
    
    def verify(self, data, signature, salted):
        """
        Verify a signature for a message.
        :param data: plaintext that was signed.
        :type data: str
        :param signature: signature to verify.
        :type signature: str
        :param salted: True if the signature is salted.
        :type salted: bool
        :return: bool
        """
        return self.decryptKey.verify(data, signature, salted)
    
    def addEncryption(self):
        """
        Increment the operation count for the encryption key.
        Should be called after each encryption.
        """
        self.encryptKey.increment()
    
    def addDecryption(self):
        """
        Increment the operation count for the decryption key.
        Should be called after each decryption.
        """
        self.decryptKey.increment()

    def getPadLength(self, plaintext):
        """
        Get padding length for FIPS. Currently not implemented.
        :param plaintext: plaintext.
        :return: int
        """
        raise NotImplementedError("FIPS is not implemented")

class RC4CrypterProxy(SecuritySettingsObserver):
    """
    SecuritySettingsObserver that can be used like an RC4Crypter once the crypter has been generated.
    """
    def __init__(self):
        SecuritySettingsObserver.__init__(self)
        self.crypter = None
        self.encrypt = self.decrypt = self.sign = self.verify = self.addEncryption = self.addDecryption = self.raiseCrypterUnavailableError

    def raiseCrypterUnavailableError(self):
        raise CrypterUnavailableError("The crypter proxy instance was used before the crypter was generated.")

    def onCrypterGenerated(self, settings):
        """
        Called when the crypter has been generated.
        From this point on, the proxy can be used like a normal RC4Crypter.
        :param settings: the event source.
        :type settings: SecuritySettings
        """
        self.crypter = settings.getCrypter()
        self.encrypt = self.crypter.encrypt
        self.decrypt = self.crypter.decrypt
        self.sign = self.crypter.sign
        self.verify = self.crypter.verify
        self.addEncryption = self.crypter.addEncryption
        self.addDecryption = self.crypter.addDecryption


