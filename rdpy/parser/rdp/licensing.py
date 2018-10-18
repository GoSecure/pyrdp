from StringIO import StringIO

from rdpy.core.packing import Uint8, Uint16LE, Uint32LE
from rdpy.enum.rdp import RDPLicensingPDUType
from rdpy.exceptions import UnknownPDUTypeError
from rdpy.pdu.rdp.licensing import RDPLicenseBinaryBlob, RDPLicenseErrorAlertPDU


class RDPLicensingParser:
    """
    Parse the RDP Licensing part of the RDP connection sequence
    """

    def __init__(self):
        self.parsers = {
            RDPLicensingPDUType.ERROR_ALERT: self.parseErrorAlert,
        }

    def parse(self, data):
        """
        Read the provided byte stream and return the corresponding RDPLicensingPDU.
        :type data: str
        :return: RDPLicensingPDU
        """

        stream = StringIO(data)
        header = Uint8.unpack(stream)
        flags = Uint8.unpack(stream)
        size = Uint16LE.unpack(stream)

        if header not in self.parsers:
            raise UnknownPDUTypeError("Trying to parse unknown license PDU")

        return self.parsers[header](stream, flags)

    def parseLicenseBlob(self, stream):
        """
        Parse the provided byte stream and return the corresponding RDPLicenseBinaryBlob
        :type stream: StringIO
        :return: RDPLicenseBinaryBlob
        """
        type = Uint16LE.unpack(stream)
        length = Uint16LE.unpack(stream)
        data = stream.read(length)
        return RDPLicenseBinaryBlob(type, data)

    def parseErrorAlert(self, stream, flags):
        """
        Parse the provided byte stream and return the corresponding RDPLicenseErrorAlertPDU
        :type stream: StringIO
        :param flags: The flags of the Licencing PDU.
        :return: RDPLicenseErrorAlertPDU
        """
        errorCode = Uint32LE.unpack(stream)
        stateTransition = Uint32LE.unpack(stream)
        blob = self.parseLicenseBlob(stream)
        return RDPLicenseErrorAlertPDU(flags, errorCode, stateTransition, blob)

    def write(self, pdu):
        """
        Encode a RDPLicensingPDU into a byte stream to send to the previous layer.
        :type pdu: rdpy.pdu.rdp.licensing.RDPLicensingPDU
        :return: RDPLicensingPDU
        """
        stream = StringIO()
        stream.write(Uint8.pack(pdu.header))
        stream.write(Uint8.pack(pdu.flags))
        substream = StringIO()

        if isinstance(pdu, RDPLicenseErrorAlertPDU):
            self.writeErrorAlert(substream, pdu)
        else:
            raise UnknownPDUTypeError("Trying to write unknown RDP Licensing PDU: {}".format(pdu.header), pdu.header)

        stream.write(Uint16LE.pack(len(substream.getvalue()) + 4))
        stream.write(substream.getvalue())
        return stream.getvalue()

    def writeErrorAlert(self, stream, pdu):
        """
        Writes LicenceErrorAlertPDU-specific fields to stream
        :type stream: StringIO
        :type pdu: RDPLicenseErrorAlertPDU
        """
        stream.write(Uint32LE.pack(pdu.errorCode))
        stream.write(Uint32LE.pack(pdu.stateTransition))
        stream.write(Uint16LE.pack(pdu.blob.type))
        stream.write(Uint16LE.pack(0))