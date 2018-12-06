from enum import IntEnum

import Crypto.Random

from pyrdp.core.observer import Observer
from pyrdp.core.subject import ObservedBy, Subject
from pyrdp.security.crypto import RC4Crypter

from pyrdp.exceptions import StateError


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
        :type random: bytes
        """
        self.serverRandom = random

        if self.clientRandom is not None and self.serverRandom is not None:
            self.generateCrypter()

    def setClientRandom(self, random):
        """
        Set the clientRandom attribute.
        :param random: client random data.
        :type random: bytes
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


