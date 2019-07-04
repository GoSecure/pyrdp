#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import Crypto.Random
from Crypto.PublicKey.RSA import RsaKey

from pyrdp.core import ObservedBy, Observer, Subject
from pyrdp.enum import EncryptionMethod
from pyrdp.exceptions import StateError
from pyrdp.security.crypto import RC4Crypter, RSA


class SecuritySettingsObserver(Observer):
    """
    Observer class for SecuritySettings.
    """

    def onCrypterGenerated(self, settings: 'SecuritySettings'):
        """
        Called when the SecuritySettings crypter has been generated.
        :param settings: the security settings object.
        """
        pass


@ObservedBy(SecuritySettingsObserver)
class SecuritySettings(Subject):
    """
    Class containing RDP standard security settings.
    """

    def __init__(self):
        Subject.__init__(self)
        self.encryptionMethod = None
        self.clientRandom = None
        self.serverRandom = None
        self.serverPublicKey = None
        self.clientCrypter = None
        self.serverCrypter = None

    def generateCrypters(self):
        """
        Generate a crypter with the current settings.
        """
        self.clientCrypter = RC4Crypter.generateClient(self.clientRandom, self.serverRandom, self.encryptionMethod)
        self.serverCrypter = RC4Crypter.generateServer(self.clientRandom, self.serverRandom, self.encryptionMethod)

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

    def encryptClientRandom(self) -> bytes:
        """
        Encrypt the client random using the public key.
        """
        # plaintext is stored as little-endian but crypto functions expect it to be in big-endian format.
        return RSA(self.serverPublicKey).encrypt(self.clientRandom[:: -1])[:: -1]


    def setEncryptionMethod(self, encryptionMethod: EncryptionMethod):
        """
        Set the encryption method attribute.
        :param encryptionMethod: the encryption method.
        """
        self.encryptionMethod = encryptionMethod

    def setServerPublicKey(self, serverPublicKey: RsaKey):
        """
        Set the server's public key.
        :param serverPublicKey: the server's public key.
        """
        self.serverPublicKey = serverPublicKey

    def setServerRandom(self, random: bytes):
        """
        Set the serverRandom attribute.
        :param random: server random data.
        """
        self.serverRandom = random

        if self.clientRandom is not None and self.serverRandom is not None:
            self.generateCrypters()

    def setClientRandom(self, random: bytes):
        """
        Set the clientRandom attribute.
        :param random: client random data.
        """
        self.clientRandom = random

        if self.clientRandom is not None and self.serverRandom is not None:
            self.generateCrypters()

    def getClientCrypter(self) -> RC4Crypter:
        """
        Get the client crypter.
        """
        if self.clientCrypter is None:
            raise StateError("The crypters were not generated. The crypters will be generated when both the client and server random are received.")

        return self.clientCrypter

    def getServerCrypter(self) -> RC4Crypter:
        """
        Get the server crypter.
        """
        if self.serverCrypter is None:
            raise StateError("The crypters were not generated. The crypters will be generated when both the client and server random are received.")

        return self.serverCrypter


