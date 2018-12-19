#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.pdu.pdu import PDU


class ClientExtraInfo(PDU):
    def __init__(self, clientAddressFamily: int, clientAddress: bytes, clientDir: bytes):
        PDU.__init__(self, b"")
        self.clientAddressFamily = clientAddressFamily
        self.clientAddress = clientAddress
        self.clientDir = clientDir
        self.clientTimeZone = None
        self.clientSessionID = None
        self.performanceFlags = None
        self.autoReconnectCookie = None
        self.dynamicDSTTimeZoneKeyName = None
        self.dynamicDaylightTimeDisabled = None

class ClientInfoPDU(PDU):
    def __init__(self, codePage: int, flags: int, domain: str, username: str, password: str, alternateShell: str, workingDir: str, extraInfo: ClientExtraInfo):
        PDU.__init__(self)
        self.codePage = codePage
        self.flags = flags
        self.domain = domain
        self.username = username
        self.password = password
        self.alternateShell = alternateShell
        self.workingDir = workingDir
        self.extraInfo = extraInfo