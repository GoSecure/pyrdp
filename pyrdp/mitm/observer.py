#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from binascii import hexlify
from logging import Logger

from pyrdp.core import Observer
from pyrdp.layer import FastPathObserver, Layer, RDPDataObserver, SlowPathObserver
from pyrdp.pdu import SlowPathPDU


class MITMChannelObserver(Observer):
    def __init__(self, log: Logger, layer: Layer, innerObserver: RDPDataObserver, **kwargs):
        Observer.__init__(self, **kwargs)
        self.log = log
        self.layer = layer
        self.innerObserver = innerObserver
        self.peer = None

        self.setDataHandler = self.innerObserver.setDataHandler
        self.setDefaultDataHandler = self.innerObserver.setDefaultDataHandler

    def onPDUReceived(self, pdu):
        self.log.debug("Received %(arg1)s", {"arg1": str(self.getEffectiveType(pdu))})
        self.innerObserver.onPDUReceived(pdu)
        self.peer.sendPDU(pdu)

    def onUnparsedData(self, data):
        self.log.debug("Received unparsed data: %(arg1)s", {"arg1": hexlify(data)})
        self.peer.sendData(data)

    def sendPDU(self, pdu):
        self.log.debug("Sending %(arg1)s", {"arg1": str(self.getEffectiveType(pdu))})
        self.layer.sendPDU(pdu)

    def sendData(self, data):
        self.log.debug("Sending data: %(arg1)s", {"arg1": hexlify(data)})
        self.layer.sendData(data)

    def getEffectiveType(self, pdu):
        return NotImplementedError("getEffectiveType must be overridden")


class MITMSlowPathObserver(MITMChannelObserver):
    def __init__(self, log: Logger, layer: Layer, **kwargs):
        MITMChannelObserver.__init__(self, log, layer, SlowPathObserver(**kwargs))

    def getEffectiveType(self, pdu: SlowPathPDU):
        if hasattr(pdu.header, "subtype"):
            if hasattr(pdu, "errorInfo"):
                return pdu.errorInfo
            else:
                return pdu.header.subtype
        else:
            return pdu.header.pduType


class MITMFastPathObserver(MITMChannelObserver):
    def __init__(self, log: Logger, layer: Layer):
        MITMChannelObserver.__init__(self, log, layer, FastPathObserver())

    def getEffectiveType(self, pdu):
        return str(pdu)