#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.number import bytes_to_long, long_to_bytes

from pyrdp.security import rc4
from pyrdp.security.key import macData, macSaltedData, generateKeys, updateKey
from pyrdp.enum import EncryptionMethod

"""
Cryptographic utility functions
"""

# Adapted from https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/_slowmath.py
class RSA:
    """
    Class for encrypting or decrypting data with RSA
    Not meant to be a safe implementation. We only need raw RSA without padding.
    """

    def __init__(self, key: RsaKey):
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        m = bytes_to_long(plaintext)
        ciphertext = pow(m, self.key.e, self.key.n)
        return long_to_bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        c = bytes_to_long(ciphertext)

        # compute c**d (mod n)
        if (hasattr(self.key, 'p') and hasattr(self.key, 'q') and hasattr(self.key, 'u')):
            m1 = pow(c, self.key.d % (self.key.p - 1), self.key.p)
            m2 = pow(c, self.key.d % (self.key.q - 1), self.key.q)
            h = m2 - m1

            if (h < 0):
                h = h + self.key.q
            h = h * self.key.u % self.key.q

            plaintext = h * self.key.p + m1
        else:
            plaintext = pow(c, self.key.d, self.key.n)

        return long_to_bytes(plaintext)

class RC4:
    """
    Class for encrypting or decrypting data with RC4.
    """

    def __init__(self, encryptionMethod: EncryptionMethod, macKey: bytes, key: bytes):
        """
        :param encryptionMethod: the encryption method
        :param macKey: the key used for salted signatures.
        :param key: the initial encryption key.
        """
        self.encryptionMethod = encryptionMethod
        self.macKey = macKey
        self.initialBytes = key
        self.currentBytes = key
        self.key = rc4.RC4Key(key)
        self.cipherCount = 0
        self.macCount = 0
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data.
        :param data: plaintext data to encrypt.
        :return: encrypted data.
        """
        return rc4.crypt(self.key, data)
    
    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data.
        :param data: ciphertext to decrypt.
        :return: decrypted data.
        """
        return self.encrypt(data)
    
    def sign(self, data: bytes, salted: bool) -> bytes:
        """
        Generate a signature for a message.
        :param data: plaintext data to sign.
        :param salted: True if the signature should be salted.
        :return: The signature bytes.
        """
        if salted:
            return macSaltedData(self.macKey, data, self.macCount)[: 8]
        else:
            return macData(self.macKey, data)[: 8]
    
    def verify(self, data: bytes, signature: bytes, salted: bool) -> bool:
        """
        Verify a signature.
        :param data: plaintext data to verify.
        :param signature: the signature to verify.
        :param salted: True if the signature is salted.
        :return: True if the signature is valid.
        """
        return signature[: 8] == self.sign(data, salted)
    
    def increment(self):
        """
        Increment the operation count and update the key if necessary.
        """
        self.cipherCount += 1
        self.macCount += 1

        if self.cipherCount == 4096:
            self.currentBytes = updateKey(self.initialBytes, self.currentBytes, self.encryptionMethod)
            self.key = rc4.RC4Key(self.currentBytes)
            self.cipherCount = 0

class RC4Crypter:
    """
    Class containing RC4 keys for both sides of a communication. Chooses the correct key based on the operation.
    """

    def __init__(self, encryptionMethod: EncryptionMethod, macKey: bytes, encryptKey: bytes, decryptKey: bytes):
        """
        :param encryptionMethod: the encryption method.
        :param macKey: the signing key.
        :param encryptKey: the encryption key.
        :param decryptKey: the decryption key.
        """
        self.encryptionMethod = encryptionMethod
        self.macKey = macKey
        self.encryptKey = RC4(encryptionMethod, macKey, encryptKey)
        self.decryptKey = RC4(encryptionMethod, macKey, decryptKey)

    @staticmethod
    def generateClient(clientRandom: bytes, serverRandom: bytes, encryptionMethod: EncryptionMethod) -> 'RC4Crypter':
        """
        Generate an RC4Crypter instance for RDP clients.
        :param clientRandom: the client random data.
        :param serverRandom: the server random data.
        :param encryptionMethod: the encryption method.
        :return: RC4Crypter
        """
        macKey, decryptKey, encryptKey = generateKeys(clientRandom, serverRandom, encryptionMethod)
        return RC4Crypter(encryptionMethod, macKey, encryptKey, decryptKey)

    @staticmethod
    def generateServer(clientRandom: bytes, serverRandom: bytes, encryptionMethod: EncryptionMethod) -> 'RC4Crypter':
        """
        Generate an RC4Crypter instance for RDP servers.
        :param clientRandom: the client random data.
        :param serverRandom: the server random data.
        :param encryptionMethod: the encryption method.
        :return: RC4Crypter
        """
        macKey, encryptKey, decryptKey = generateKeys(clientRandom, serverRandom, encryptionMethod)
        return RC4Crypter(encryptionMethod, macKey, encryptKey, decryptKey)

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data. The addEncryption method should be called before the next encryption.
        :param data: plaintext to encrypt.
        :return: encrypted data.
        """
        return self.encryptKey.encrypt(data)
    
    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data. The addDecryption method should be called before the next decryption.
        :param data: plaintext to decrypt.
        :return: decrypted data.
        """
        return self.decryptKey.decrypt(data)
    
    def sign(self, data: bytes, salted: bool) -> bytes:
        """
        Generate a signature for a message.
        :param data: plaintext to sign.
        :param salted: True if the signature should be salted.
        :return: signature bytes.
        """
        return self.encryptKey.sign(data, salted)
    
    def verify(self, data: bytes, signature: bytes, salted: bool) -> bool:
        """
        Verify a signature for a message.
        :param data: plaintext that was signed.
        :param signature: signature to verify.
        :param salted: True if the signature is salted.
        :return: True if the signature is valid.
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

    def getPadLength(self, plaintext: bytes) -> int:
        """
        Get padding length for FIPS. Currently not implemented.
        :param plaintext: plaintext.
        :return: length of padding.
        """
        raise NotImplementedError("FIPS is not implemented")


