#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import LicensingPDUType
from pyrdp.pdu.pdu import PDU


class LicensingPDU(PDU):
    def __init__(self, header, flags):
        PDU.__init__(self)
        self.header = header
        self.flags = flags


class LicenseErrorAlertPDU(LicensingPDU):
    def __init__(self, flags, errorCode, stateTransition, blob):
        LicensingPDU.__init__(self, LicensingPDUType.ERROR_ALERT, flags)
        self.errorCode = errorCode
        self.stateTransition = stateTransition
        self.blob = blob


class LicenseBinaryBlob(PDU):
    def __init__(self, type, data):
        super().__init__()
        self.type = type
        self.data = data

