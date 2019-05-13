#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import LoggerAdapter

from pyrdp.enum import DeviceRedirectionPacketID, ErrorInfo, MCSPDUType, X224PDUType
from pyrdp.layer import FastPathObserver, LayerObserver, MCSObserver, SecurityObserver, SlowPathObserver, X224Observer
from pyrdp.parser import ClientInfoParser
from pyrdp.pdu import DeviceRedirectionPDU, FastPathPDU, FastPathScanCodeEvent, MCSAttachUserConfirmPDU, MCSChannelJoinConfirmPDU, MCSConnectResponsePDU, MCSPDU, \
    SecurityExchangePDU, SlowPathPDU, X224PDU
from pyrdp.player.keyboard import getKeyName


class LoggingObserver:
    """
    Base class for logging observers. Logs the string representation of PDUs.
    """
    def __init__(self, log: LoggerAdapter, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.log = log

    def logPDU(self, pdu):
        if isinstance(pdu, DeviceRedirectionPDU):
            if pdu.packetID == DeviceRedirectionPacketID.PAKID_CORE_USER_LOGGEDON:
                # User has logged on
                CredentialLogger.instance.printCandidate()
        self.log.debug("Received %(pdu)s", {"pdu": pdu})


class X224Logger(LoggingObserver, X224Observer):
    """
    Logging observer for X224 layers.
    """
    def __init__(self, log: LoggerAdapter):
        super().__init__(log)
        self.log = log

    def onPDUReceived(self, pdu: X224PDU):
        if pdu.header in [X224PDUType.X224_TPDU_DATA]:
            self.log.debug("Received %(type)s", {"type": pdu.header})
        else:
            self.logPDU(pdu)

        super().onPDUReceived(pdu)


class MCSLogger(LoggingObserver, MCSObserver):
    """
    Logging observer for MCS layers.
    """
    def __init__(self, log: LoggerAdapter):
        super().__init__(log)
        self.log = log

    def onPDUReceived(self, pdu: MCSPDU):
        if pdu.header in [MCSPDUType.SEND_DATA_REQUEST, MCSPDUType.SEND_DATA_INDICATION]:
            self.log.debug("Received %(type)s", {"type": pdu.header})
        else:
            self.logPDU(pdu)

        super().onPDUReceived(pdu)

    def onConnectResponse(self, pdu: MCSConnectResponsePDU):
        if pdu.result == 0:
            self.log.debug("MCS Connection successful")
        else:
            self.log.debug("MCS Connection failed")

    def onAttachUserConfirm(self, pdu: MCSAttachUserConfirmPDU):
        if pdu.result == 0:
            self.log.debug("Attach User successful")
        else:
            self.log.debug("Attach User failed")

    def onChannelJoinConfirm(self, pdu: MCSChannelJoinConfirmPDU):
        if pdu.result == 0:
            self.log.debug("Channel Join #%(channelID)s successful", {"channelID": pdu.channelID})
        else:
            self.log.debug("Channel Join #%(channelID)s failed", {"channelID": pdu.channelID})


class SecurityLogger(LoggingObserver, SecurityObserver):
    """
    Logging observer for security layers.
    """
    def __init__(self, log: LoggerAdapter):
        super().__init__(log)
        self.log = log

    def onSecurityExchangeReceived(self, pdu: SecurityExchangePDU):
        self.logPDU(pdu)

    def onClientInfoReceived(self, data: bytes):
        pdu = ClientInfoParser().parse(data)
        self.logPDU(pdu)

    def onLicensingDataReceived(self, data: bytes):
        self.log.debug("Received licensing data")


class SlowPathLogger(LoggingObserver, SlowPathObserver):
    """
    Logging observer for slow-path layers.
    """
    def __init__(self, log: LoggerAdapter):
        super().__init__(log)

    def onPDUReceived(self, pdu: SlowPathPDU):
        self.logPDU(pdu)

    def logPDU(self, pdu):
        if hasattr(pdu.header, "subtype"):
            if hasattr(pdu, "errorInfo"):
                description = pdu.errorInfo

                if pdu.errorInfo != ErrorInfo.ERRINFO_NONE:
                    errorInfoText = ErrorInfo.getText(pdu.errorInfo)

                    if pdu.errorInfo in [ErrorInfo.ERRINFO_LOGOFF_BY_USER]:
                        self.log.info("%(description)s", {"description": errorInfoText})
                    else:
                        self.log.error("RDP Error Info: %(description)s", {"description": errorInfoText})
            else:
                description = pdu.header.subtype
        else:
            description = pdu.header.pduType

        self.log.debug("Received %(description)s", {"description": description})


class FastPathLogger(LoggingObserver, FastPathObserver):
    """
    Logging observer for fast-path layers.
    """
    def __init__(self, log: LoggerAdapter):
        super().__init__(log)

    def onPDUReceived(self, pdu: FastPathPDU):
        self.logPDU(pdu)


class LayerLogger(LoggingObserver, LayerObserver):
    """
    Generic logging observer for all layer types.
    """
    def __init__(self, log: LoggerAdapter):
        super().__init__(log)

    def onPDUReceived(self, pdu):
        self.logPDU(pdu)

# Singleton
class CredentialLogger(LoggingObserver):
    """
    Logging observer for credentials going through the fast-path layers.
    Credentials gets printed whenever RDPDR receives a "loggon" type packet
    """
    instance = None

    class __CredentialLogger:
        def __init__(self, log: LoggerAdapter):
            self.log = log
            self.shiftPressed = False
            self.capsLockOn = False
            self.candidate = ""
            self.buffer = ""

        def onPDUReceived(self, pdu: FastPathPDU):
            self.logPDU(pdu)

        def logPDU(self, pdu):
            for event in pdu.events:
                if isinstance(event, FastPathScanCodeEvent):
                    self.onScanCode(event.scanCode, event.isReleased, event.rawHeaderByte & 2 != 0)

        def onScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
            """
            Handle scan code.
            """
            keyName = getKeyName(scanCode, isExtended, self.shiftPressed, self.capsLockOn)

            if len(keyName) == 1:
                if not isReleased:
                    self.buffer += keyName

            # Left or right shift
            if scanCode in [0x2A, 0x36]:
                self.shiftPressed = not isReleased

            # Caps lock
            elif scanCode == 0x3A and not isReleased:
                self.capsLockOn = not self.capsLockOn

            # Return
            elif scanCode == 0x1C and not isReleased:
                self.candidate = self.buffer
                self.buffer = ""

        # Print the last entered crendential
        def printCandidate(self):
            # If form is submitted with a click, print the buffer instead
            # If the RDP client sends the credentials, both will be empty
            if self.candidate or self.buffer:
                self.log.info("Credentials candidate: %(candidate)s", {"candidate" : (self.candidate or self.buffer) })

    def __new__(self, log: LoggerAdapter):
        if not CredentialLogger.instance:
            CredentialLogger.instance = CredentialLogger.__CredentialLogger(log)
        return CredentialLogger.instance

    def __init__(self, log: LoggerAdapter):
        super().__init__(log)

    # Forward getters/setters to the instance
    def __getattr__(self, name):
        return getattr(self.instance, name)
    def __setattr__(self, name):
        return setattr(self.instance, name)