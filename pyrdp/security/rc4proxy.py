#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from enum import IntEnum

from pyrdp.exceptions import CrypterUnavailableError
from pyrdp.security.settings import SecuritySettings, SecuritySettingsObserver


class RC4CrypterProxy(SecuritySettingsObserver):
    """
    SecuritySettingsObserver that can be used like an RC4Crypter once the crypter has been generated.
    """

    class Mode(IntEnum):
        """
        RC4CrypterProxy mode (client or server).
        """
        CLIENT = 0
        SERVER = 1

    def __init__(self, mode: 'RC4CrypterProxy.Mode'):
        SecuritySettingsObserver.__init__(self)
        self.mode = mode
        self.crypter = None
        self.encrypt = self.decrypt = self.sign = self.verify = self.addEncryption = self.addDecryption = self.raiseCrypterUnavailableError

    def raiseCrypterUnavailableError(self):
        raise CrypterUnavailableError("The crypter proxy instance was used before the crypter was generated.")

    def onCrypterGenerated(self, settings: SecuritySettings):
        """
        Called when the crypter has been generated.
        From this point on, the proxy can be used like a normal RC4Crypter.
        :param settings: the event source.
        """

        if self.mode == RC4CrypterProxy.Mode.CLIENT:
            self.crypter = settings.getClientCrypter()
        else:
            self.crypter = settings.getServerCrypter()

        self.encrypt = self.crypter.encrypt
        self.decrypt = self.crypter.decrypt
        self.sign = self.crypter.sign
        self.verify = self.crypter.verify
        self.addEncryption = self.crypter.addEncryption
        self.addDecryption = self.crypter.addDecryption