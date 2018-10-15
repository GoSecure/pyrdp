from rdpy.core import log
from rdpy.core.newlayer import Layer


class IOChannel(Layer):
    def __init__(self, security):
        Layer.__init__(self)
        self.security = security

    def recv(self, data):
        log.info("Security Exchange result: %s" % data.encode('hex'))
        pass