import logging
from binascii import hexlify

from rdpy.core.observer import Observer


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


class RC4LoggingObserver(SecuritySettingsObserver):
    def __init__(self, log: logging.Logger):
        super().__init__()
        self.log = log

    def onCrypterGenerated(self, settings):
        self.log.info("RC4 client/server random: %(rc4ClientRandom)s %(rc4ServerRandom)s",
                      {"rc4ClientRandom": hexlify(settings.clientRandom).decode(),
                       "rc4ServerRandom": hexlify(settings.serverRandom).decode()})