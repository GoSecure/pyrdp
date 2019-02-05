#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Dict, List

from pyrdp.enum import DeviceRedirectionComponent, DeviceRedirectionPacketID, DeviceType, MajorFunction, RDPDRCapabilityType
from pyrdp.pdu.pdu import PDU


class DeviceRedirectionPDU(PDU):
    """
    Also called Shared Header: https://msdn.microsoft.com/en-us/library/cc241324.aspx
    """

    def __init__(self, component: int, packetID: int, payload=b""):
        super().__init__(payload)
        self.component = component
        self.packetID: DeviceRedirectionPacketID = DeviceRedirectionPacketID(packetID)


class DeviceIOResponsePDU(DeviceRedirectionPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241334.aspx
    """

    def __init__(self, deviceID: int, completionID: int, ioStatus: int, payload=b""):
        super().__init__(DeviceRedirectionComponent.RDPDR_CTYP_CORE,
                         DeviceRedirectionPacketID.PAKID_CORE_DEVICE_IOCOMPLETION)
        self.deviceID = deviceID
        self.completionID = completionID
        self.ioStatus = ioStatus
        self.payload = payload


class DeviceIORequestPDU(DeviceRedirectionPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241327.aspx
    """

    def __init__(self, deviceID: int, fileID: int, completionID: int, majorFunction: int, minorFunction: int, payload=b""):
        super().__init__(DeviceRedirectionComponent.RDPDR_CTYP_CORE, DeviceRedirectionPacketID.PAKID_CORE_DEVICE_IOREQUEST, payload)
        self.deviceID = deviceID
        self.fileID = fileID
        self.completionID = completionID
        self.majorFunction = majorFunction
        self.minorFunction = minorFunction


class DeviceReadResponsePDU(DeviceIOResponsePDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241337.aspx
    """

    def __init__(self, deviceID: int, completionID: int, ioStatus: int, readData: bytes):
        super().__init__(deviceID, completionID, ioStatus)
        self.readData = readData


class DeviceReadRequestPDU(DeviceIORequestPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241330.aspx
    """

    def __init__(self, deviceID: int, fileID: int, completionID: int, minorFunction: int,
                 length: int, offset: int):
        super().__init__(deviceID, fileID, completionID, MajorFunction.IRP_MJ_READ, minorFunction)
        self.length = length
        self.offset = offset


class DeviceCreateRequestPDU(DeviceIORequestPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241328.aspx
    """

    def __init__(self, deviceID: int, fileID: int, completionID: int, minorFunction: int,
                 desiredAccess: int, allocationSize: int, fileAttributes: int, sharedAccess: int,
                 createDisposition: int, createOptions: int, path: bytes):
        super().__init__(deviceID, fileID, completionID, MajorFunction.IRP_MJ_CREATE, minorFunction)
        self.desiredAccess = desiredAccess
        self.allocationSize = allocationSize
        self.fileAttributes = fileAttributes
        self.sharedAccess = sharedAccess
        self.createDisposition = createDisposition
        self.createOptions = createOptions
        self.path = path


class DeviceCreateResponsePDU(DeviceIOResponsePDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241335.aspx
    """

    def __init__(self, deviceID: int, completionID: int, ioStatus: int, fileID: int, information: bytes= b""):
        super().__init__(deviceID, completionID, ioStatus)
        self.fileID = fileID
        self.information = information


class DeviceCloseRequestPDU(DeviceIORequestPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241329.aspx
    """

    def __init__(self, deviceID: int, fileID: int, completionID: int, minorFunction: int):
        super().__init__(deviceID, fileID, completionID, MajorFunction.IRP_MJ_CLOSE, minorFunction)


class DeviceCloseResponsePDU(DeviceIOResponsePDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241336.aspx
    """

    def __init__(self, deviceID: int, completionID: int, ioStatus: int):
        super().__init__(deviceID, completionID, ioStatus)


class DeviceAnnounce(PDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241326.aspx
    """

    def __init__(self, deviceType: DeviceType, deviceID: int, preferredDosName: bytes, deviceData: bytes):
        super().__init__()
        self.deviceID = deviceID
        self.deviceType = deviceType
        self.preferredDosName = preferredDosName
        self.deviceData = deviceData


class DeviceListAnnounceRequest(DeviceRedirectionPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241355.aspx
    """

    def __init__(self, deviceList: List[DeviceAnnounce]):
        super().__init__(DeviceRedirectionComponent.RDPDR_CTYP_CORE, DeviceRedirectionPacketID.PAKID_CORE_DEVICELIST_ANNOUNCE)
        self.deviceList = deviceList


class DeviceRedirectionCapability(PDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241325.aspx
    """
    def __init__(self, capabilityType: RDPDRCapabilityType, version: int, payload=b""):
        super().__init__(payload=payload)
        self.capabilityType = capabilityType
        self.version = version


class DeviceRedirectionGeneralCapability(DeviceRedirectionCapability):
    """
    https://msdn.microsoft.com/en-us/library/cc241349.aspx
    """

    def __init__(self, version: int, osType: int, osVersion: int, protocolMajorVersion: int,
                 protocolMinorVersion: int, ioCode1: int, ioCode2: int, extendedPDU: int, extraFlags1: int,
                 extraFlags2: int, specialTypeDeviceCap: int):
        super().__init__(RDPDRCapabilityType.CAP_GENERAL_TYPE, version)
        self.osType = osType
        self.osVersion = osVersion
        self.protocolMajorVersion = protocolMajorVersion
        self.protocolMinorVersion = protocolMinorVersion
        self.ioCode1 = ioCode1
        self.ioCode2 = ioCode2
        self.extendedPDU = extendedPDU
        self.extraFlags1 = extraFlags1
        self.extraFlags2 = extraFlags2
        self.specialTypeDeviceCap = specialTypeDeviceCap


class DeviceRedirectionCapabilitiesPDU(DeviceRedirectionPDU):
    """
    Base class for capability PDU (client and server) because they're pretty much the same
    """
    def __init__(self, packetID: DeviceRedirectionPacketID, capabilities: Dict[RDPDRCapabilityType, DeviceRedirectionCapability]):
        super().__init__(DeviceRedirectionComponent.RDPDR_CTYP_CORE, packetID)
        self.capabilities = capabilities


class DeviceRedirectionServerCapabilitiesPDU(DeviceRedirectionCapabilitiesPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241348.aspx
    """
    def __init__(self, capabilities: Dict[RDPDRCapabilityType, DeviceRedirectionCapability]):
        super().__init__(DeviceRedirectionPacketID.PAKID_CORE_SERVER_CAPABILITY, capabilities)
        self.capabilities: Dict[RDPDRCapabilityType, DeviceRedirectionCapability] = capabilities


class DeviceRedirectionClientCapabilitiesPDU(DeviceRedirectionCapabilitiesPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241354.aspx
    """
    def __init__(self, capabilities: Dict[RDPDRCapabilityType, DeviceRedirectionCapability]):
        super().__init__(DeviceRedirectionPacketID.PAKID_CORE_CLIENT_CAPABILITY, capabilities)
        self.capabilities = capabilities
