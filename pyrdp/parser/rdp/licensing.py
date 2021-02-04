#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import Uint16LE, Uint32LE, Uint8
from pyrdp.enum import LicenseBinaryBlobType, LicenseErrorCode, LicensingPDUType, RDPStateTransition
from pyrdp.exceptions import UnknownPDUTypeError
from pyrdp.parser.parser import Parser
from pyrdp.pdu import LicenseBinaryBlob, LicenseErrorAlertPDU, LicensingPDU


class LicensingParser(Parser):
    """
    Parse the RDP Licensing part of the RDP connection sequence
    """

    def __init__(self):
        super().__init__()

        self.parsers = {
            LicensingPDUType.LICENSE_REQUEST: self.parseLicenseRequest,
            LicensingPDUType.PLATFORM_CHALLENGE: self.parsePlatformChallenge,
            LicensingPDUType.NEW_LICENSE: self.parseNewLicense,
            LicensingPDUType.UPGRADE_LICENSE: self.parseUpgradeLicense,
            LicensingPDUType.LICENSE_INFO: self.parseLicenseInfo,
            LicensingPDUType.NEW_LICENSE_REQUEST: self.parseNewLicenseRequest,
            LicensingPDUType.PLATFORM_CHALLENGE_RESPONSE: self.parsePlatformChallengeResponse,
            LicensingPDUType.ERROR_ALERT: self.parseErrorAlert,
        }

    def doParse(self, data):
        """
        Read the provided byte stream and return the corresponding RDPLicensingPDU.
        :type data: bytes
        :return: RDPLicensingPDU
        """

        stream = BytesIO(data)
        header = Uint8.unpack(stream)
        flags = Uint8.unpack(stream)
        size = Uint16LE.unpack(stream)

        if header not in self.parsers:
            raise UnknownPDUTypeError("Trying to parse unknown license PDU", header)

        return self.parsers[header](stream, flags)

    def parseLicenseBlob(self, stream):
        """
        Parse the provided byte stream and return the corresponding RDPLicenseBinaryBlob
        :type stream: BytesIO
        :return: RDPLicenseBinaryBlob
        """
        type = LicenseBinaryBlobType(Uint16LE.unpack(stream))
        length = Uint16LE.unpack(stream)
        data = stream.read(length)
        return LicenseBinaryBlob(type, data)

    def parseLicenseRequest(self, stream, flags):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/a870d76a-639b-4757-9370-a9bdfbfd6961
        raise ("parseLicenseRequest isn't implemented yet")

    def parsePlatformChallenge(self, stream, flags):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/3e78e067-83a8-42b5-b5b3-054679ade7c7
        raise ("parsePlatformChallenge isn't implemented yet")

    def parseNewLicense(self, stream, flags):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/73c596f1-9550-4649-b880-2947c36c1bb6
        raise ("parseNewLicense isn't implemented yet")

    def parseUpgradeLicense(self, stream, flags):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/94f9f260-fe9d-4429-b3b5-228bef28bc5d
        raise ("parseUpgradeLicense isn't implemented yet")

    def parseLicenseInfo(self, stream, flags):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/9fea482b-f9e5-4175-9350-ac540a804eba
        raise ("parseLicenseInfo isn't implemented yet")

    def parseNewLicenseRequest(self, stream, flags):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/9b4e7ee7-9e85-46f0-9583-77cfd397864e
        raise ("parseNewLicenseRequest isn't implemented yet")

    def parsePlatformChallengeResponse(self, stream, flags):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/58e79794-58f8-4607-a510-c0b5fef49c40
        raise ("parsePlatformChallengeResponse isn't implemented yet")

    def parseErrorAlert(self, stream, flags):
        """
        Parse the provided byte stream and return the corresponding RDPLicenseErrorAlertPDU
        :type stream: BytesIO
        :param flags: The flags of the Licencing PDU.
        :return: RDPLicenseErrorAlertPDU
        """
        errorCode = LicenseErrorCode(Uint32LE.unpack(stream))
        stateTransition = RDPStateTransition(Uint32LE.unpack(stream))
        blob = self.parseLicenseBlob(stream)
        return LicenseErrorAlertPDU(flags, errorCode, stateTransition, blob)

    def write(self, pdu: LicensingPDU) -> bytes:
        """
        Encode a RDPLicensingPDU into a byte stream to send to the previous layer.
        """
        stream = BytesIO()
        stream.write(Uint8.pack(pdu.header))
        stream.write(Uint8.pack(pdu.flags))
        substream = BytesIO()

        if isinstance(pdu, LicenseErrorAlertPDU):
            self.writeErrorAlert(substream, pdu)
        else:
            raise UnknownPDUTypeError("Trying to write unknown RDP Licensing PDU: {}".format(pdu.header), pdu.header)

        stream.write(Uint16LE.pack(len(substream.getvalue()) + 4))
        stream.write(substream.getvalue())
        return stream.getvalue()

    def writeErrorAlert(self, stream, pdu):
        """
        Writes LicenceErrorAlertPDU-specific fields to stream
        :type stream: BytesIO
        :type pdu: LicenseErrorAlertPDU
        """
        stream.write(Uint32LE.pack(pdu.errorCode))
        stream.write(Uint32LE.pack(pdu.stateTransition))
        stream.write(Uint16LE.pack(pdu.blob.type))
        stream.write(Uint16LE.pack(0))
