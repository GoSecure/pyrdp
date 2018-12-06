from pyrdp.security import rc4
from pyrdp.security.key import macData, macSaltedData, generateKeys, updateKey
from pyrdp.enum.rdp import EncryptionMethod

"""
Cryptographic utility functions
"""


class RC4:
    """
    Class for encrypting or decrypting data with RC4.
    """

    def __init__(self, encryptionMethod, macKey, key):
        """
        :param encryptionMethod: the encryption method
        :type encryptionMethod: EncryptionMethod
        :param macKey: the key used for salted signatures.
        :type macKey: bytes
        :param key: the initial encryption key.
        :type key: bytes
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
        :type data: bytes
        :return: str
        """
        return rc4.crypt(self.key, data)
    
    def decrypt(self, data):
        """
        Decrypt data.
        :param data: ciphertext to decrypt.
        :type data: bytes
        :return: str
        """
        return self.encrypt(data)
    
    def sign(self, data, salted):
        """
        Generate a signature for a message.
        :param data: plaintext data to sign.
        :type data: bytes
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
        :type data: bytes
        :param signature: the signature to verify.
        :type signature: bytes
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
        :type macKey: bytes
        :param encryptKey: the encryption key.
        :type encryptKey: bytes
        :param decryptKey: the decryption key.
        :type decryptKey: bytes
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
        :type clientRandom: bytes
        :param serverRandom: the server random data.
        :type serverRandom: bytes
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
        :type clientRandom: bytes
        :param serverRandom: the server random data.
        :type serverRandom: bytes
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
        :type data: bytes
        :return: str
        """
        return self.encryptKey.encrypt(data)
    
    def decrypt(self, data):
        """
        Decrypt data. The addDecryption method should be called before the next decryption.
        :param data: plaintext to decrypt.
        :type data: bytes
        :return: str
        """
        return self.decryptKey.decrypt(data)
    
    def sign(self, data, salted):
        """
        Generate a signature for a message.
        :param data: plaintext to sign.
        :type data: bytes
        :param salted: True if the signature should be salted.
        :type salted: bool
        :return: str
        """
        return self.encryptKey.sign(data, salted)
    
    def verify(self, data, signature, salted):
        """
        Verify a signature for a message.
        :param data: plaintext that was signed.
        :type data: bytes
        :param signature: signature to verify.
        :type signature: bytes
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


