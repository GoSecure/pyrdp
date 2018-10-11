from StringIO import StringIO
from rdpy.core.packing import Uint8, Uint16LE, Uint32LE

class RDPLicensingPDUType:
    LICENSE_REQUEST = 0x01
    PLATFORM_CHALLENGE = 0x02
    NEW_LICENSE = 0x03
    UPGRADE_LICENSE = 0x04
    LICENSE_INFO = 0x12
    NEW_LICENSE_REQUEST = 0x13
    PLATFORM_CHALLENGE_RESPONSE = 0x15
    ERROR_ALERT = 0xFF

class RDPLicenseBinaryBlobType:
    """
    License blob data type
    See http://msdn.microsoft.com/en-us/library/cc240481.aspx
    """
    BB_ANY_BLOB = 0x0000
    BB_DATA_BLOB = 0x0001
    BB_RANDOM_BLOB = 0x0002
    BB_CERTIFICATE_BLOB = 0x0003
    BB_ERROR_BLOB = 0x0004
    BB_ENCRYPTED_DATA_BLOB = 0x0009
    BB_KEY_EXCHG_ALG_BLOB = 0x000D
    BB_SCOPE_BLOB = 0x000E
    BB_CLIENT_USER_NAME_BLOB = 0x000F
    BB_CLIENT_MACHINE_NAME_BLOB = 0x0010

class RDPStateTransition:
    """
    Automata state transition
    See http://msdn.microsoft.com/en-us/library/cc240482.aspx
    """
    ST_TOTAL_ABORT = 0x00000001
    ST_NO_TRANSITION = 0x00000002
    ST_RESET_PHASE_TO_START = 0x00000003
    ST_RESEND_LAST_MESSAGE = 0x00000004

class RDPLicensingPDU:
    def __init__(self, header, flags):
        self.header = msgType
        self.flags = flags

class RDPLicenseErrorAlertPDU(RDPLicensingPDU):
    def __init__(self, flags, errorCode, stateTransition, blob):
        RDPLicensingPDU.__init__(self, RDPLicensingPDUType.ERROR_ALERT, flags)
        self.errorCode = errorCode
        self.stateTransition = stateTransition
        self.blob = blob

class RDPLicenseBinaryBlob:
    def __init__(self, type, data):
        self.type = type
        self.data = data

class RDPLicensingParser:
    def __init__(self):
        self.parsers = {
            RDPLicensingPDUType.ERROR_ALERT: self.parseErrorAlert,
        }

    def parse(self, data):
        stream = StringIO(data)
        header = Uint8.unpack(stream)
        flags = Uint8.unpack(stream)
        size = Uint16LE.unpack(stream)

        if header not in self.parsers:
            raise Exception("Trying to parse unknown license PDU")
        
        self.parsers[header](stream, flags)
    
    def parseLicenseBlob(self, stream):
        type = Uint16LE.unpack(stream)
        length = Uint16LE.unpack(stream)
        data = stream.read(length)
        return RDPLicenseBinaryBlob(type, data)

    def parseErrorAlert(self, stream, flags):
        errorCode = Uint32LE.unpack(stream)
        stateTransition = Uint32LE.unpack(stream)
        blob = self.parseLicenseBlob(stream)
        return RDPLicenseErrorAlertPDU(flags, errorCode, stateTransition, blob)