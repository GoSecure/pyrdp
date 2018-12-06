import logging
from binascii import hexlify

from pyrdp.security import SecuritySettingsObserver


class RC4LoggingObserver(SecuritySettingsObserver):
    def __init__(self, log: logging.Logger):
        super().__init__()
        self.log = log

    def onCrypterGenerated(self, settings):
        self.log.info("RC4 client/server random: %(rc4ClientRandom)s %(rc4ServerRandom)s",
                      {"rc4ClientRandom": hexlify(settings.clientRandom).decode(),
                       "rc4ServerRandom": hexlify(settings.serverRandom).decode()})