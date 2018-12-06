from pyrdp.enum.rdp import LicensingPDUType
from pyrdp.pdu.base_pdu import PDU


class RDPLicensingPDU(PDU):
    def __init__(self, header, flags):
        PDU.__init__(self)
        self.header = header
        self.flags = flags


class RDPLicenseErrorAlertPDU(RDPLicensingPDU):
    def __init__(self, flags, errorCode, stateTransition, blob):
        RDPLicensingPDU.__init__(self, LicensingPDUType.ERROR_ALERT, flags)
        self.errorCode = errorCode
        self.stateTransition = stateTransition
        self.blob = blob


class RDPLicenseBinaryBlob(PDU):
    def __init__(self, type, data):
        super().__init__()
        self.type = type
        self.data = data
