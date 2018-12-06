from pyrdp.exceptions import CrypterUnavailableError
from pyrdp.security.settings import SecuritySettingsObserver


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
        :type settings: pyrdp.security.SecuritySettings
        """
        self.crypter = settings.getCrypter()
        self.encrypt = self.crypter.encrypt
        self.decrypt = self.crypter.decrypt
        self.sign = self.crypter.sign
        self.verify = self.crypter.verify
        self.addEncryption = self.crypter.addEncryption
        self.addDecryption = self.crypter.addDecryption