#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2019, 2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Dict, List, Optional

from pyrdp.enum import DeviceRedirectionComponent, DeviceRedirectionPacketID, \
    DeviceType, FileAccessMask, FileAttributes, FileCreateDisposition, \
    FileCreateOptions, FileShareAccess, FileSystemInformationClass, \
    MajorFunction, MinorFunction, RDPDRCapabilityType
from pyrdp.pdu import PDU


class DeviceRedirectionPDU(PDU):
    """
    Also called Shared Header: https://msdn.microsoft.com/en-us/library/cc241324.aspx
    """

    def __init__(self, component: int, packetID: int, payload=b""):
        super().__init__(payload)
        self.component = component
        self.packetID: DeviceRedirectionPacketID = DeviceRedirectionPacketID(packetID)


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


class DeviceIOResponsePDU(DeviceRedirectionPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241334.aspx
    """

    def __init__(self, majorFunction: Optional[MajorFunction], deviceID: int, completionID: int, ioStatus: int, payload=b""):
        super().__init__(DeviceRedirectionComponent.RDPDR_CTYP_CORE, DeviceRedirectionPacketID.PAKID_CORE_DEVICE_IOCOMPLETION)
        self.majorFunction = majorFunction
        self.deviceID = deviceID
        self.completionID = completionID
        self.ioStatus = ioStatus
        self.payload = payload


class DeviceCreateRequestPDU(DeviceIORequestPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241328.aspx
    """

    def __init__(self, deviceID: int, fileID: int, completionID: int, minorFunction: int,
                 desiredAccess: FileAccessMask, allocationSize: int, fileAttributes: FileAttributes, sharedAccess: FileShareAccess,
                 createDisposition: FileCreateDisposition, createOptions: FileCreateOptions, path: str):
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

    def __init__(self, deviceID: int, completionID: int, ioStatus: int, fileID: int, information: int):
        super().__init__(MajorFunction.IRP_MJ_CREATE, deviceID, completionID, ioStatus)
        self.fileID = fileID
        self.information = information


class DeviceReadRequestPDU(DeviceIORequestPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241330.aspx
    """

    def __init__(self, deviceID: int, fileID: int, completionID: int, minorFunction: int,
                 length: int, offset: int):
        super().__init__(deviceID, fileID, completionID, MajorFunction.IRP_MJ_READ, minorFunction)
        self.length = length
        self.offset = offset


class DeviceReadResponsePDU(DeviceIOResponsePDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241337.aspx
    """

    def __init__(self, deviceID: int, completionID: int, ioStatus: int, readData: bytes):
        super().__init__(MajorFunction.IRP_MJ_READ, deviceID, completionID, ioStatus, readData)


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
        super().__init__(MajorFunction.IRP_MJ_CLOSE, deviceID, completionID, ioStatus)


class FileInformationBase(PDU):
    def __init__(self, informationClass: FileSystemInformationClass, fileName: str):
        super().__init__(b"")
        self.informationClass = informationClass
        self.fileName = fileName


class FileDirectoryInformation(FileInformationBase):
    def __init__(self, fileIndex: int, creationTime: int, lastAccessTime: int, lastWriteTime: int, lastChangeTime: int, endOfFilePosition: int, allocationSize: int, fileAttributes: FileAttributes, fileName: str):
        super().__init__(FileSystemInformationClass.FileDirectoryInformation, fileName)
        self.fileIndex = fileIndex
        self.creationTime = creationTime
        self.lastAccessTime = lastAccessTime
        self.lastWriteTime = lastWriteTime
        self.lastChangeTime = lastChangeTime
        self.endOfFilePosition = endOfFilePosition
        self.allocationSize = allocationSize
        self.fileAttributes = fileAttributes


class FileFullDirectoryInformation(FileInformationBase):
    def __init__(self, fileIndex: int, creationTime: int, lastAccessTime: int, lastWriteTime: int, lastChangeTime: int, endOfFilePosition: int, allocationSize: int, fileAttributes: FileAttributes, eaSize: int, fileName: str):
        super().__init__(FileSystemInformationClass.FileFullDirectoryInformation, fileName)
        self.fileIndex = fileIndex
        self.creationTime = creationTime
        self.lastAccessTime = lastAccessTime
        self.lastWriteTime = lastWriteTime
        self.lastChangeTime = lastChangeTime
        self.endOfFilePosition = endOfFilePosition
        self.allocationSize = allocationSize
        self.fileAttributes = fileAttributes
        self.eaSize = eaSize


class FileBothDirectoryInformation(FileInformationBase):
    def __init__(self, fileIndex: int, creationTime: int, lastAccessTime: int, lastWriteTime: int, lastChangeTime: int, endOfFilePosition: int, allocationSize: int, fileAttributes: FileAttributes, eaSize: int, shortName: str, fileName: str):
        super().__init__(FileSystemInformationClass.FileBothDirectoryInformation, fileName)
        self.fileIndex = fileIndex
        self.creationTime = creationTime
        self.lastAccessTime = lastAccessTime
        self.lastWriteTime = lastWriteTime
        self.lastChangeTime = lastChangeTime
        self.endOfFilePosition = endOfFilePosition
        self.allocationSize = allocationSize
        self.fileAttributes = fileAttributes
        self.eaSize = eaSize
        self.shortName = shortName


class FileNamesInformation(FileInformationBase):
    def __init__(self, fileIndex: int, fileName: str):
        super().__init__(FileSystemInformationClass.FileNamesInformation, fileName)
        self.fileIndex = fileIndex


class DeviceQueryDirectoryRequestPDU(DeviceIORequestPDU):
    def __init__(self, deviceID: int, fileID: int, completionID: int, informationClass: FileSystemInformationClass, initialQuery: int, path: str):
        super().__init__(deviceID, fileID, completionID, MajorFunction.IRP_MJ_DIRECTORY_CONTROL, MinorFunction.IRP_MN_QUERY_DIRECTORY)
        self.informationClass = informationClass
        self.initialQuery = initialQuery
        self.path = path


class DeviceDirectoryControlResponsePDU(DeviceIOResponsePDU):
    def __init__(self, minorFunction: MinorFunction, deviceID: int, completionID: int, ioStatus: int, payload: bytes = b""):
        super().__init__(MajorFunction.IRP_MJ_DIRECTORY_CONTROL, deviceID, completionID, ioStatus, payload)
        self.minorFunction = minorFunction


class DeviceQueryDirectoryResponsePDU(DeviceDirectoryControlResponsePDU):
    def __init__(self, deviceID: int, completionID: int, ioStatus: int, informationClass: FileSystemInformationClass, fileInformation: List[FileInformationBase], endByte: bytes):
        super().__init__(MinorFunction.IRP_MN_QUERY_DIRECTORY, deviceID, completionID, ioStatus)
        self.informationClass = informationClass
        self.fileInformation = fileInformation

        # Named "padding" in the documentation.
        # This byte is actually important, for some reason Windows uses it even though the documentation says
        # it should be ignored.
        # See MS-RDPEFS 2.2.3.4.10
        self.endByte = endByte


class DeviceAnnounce(PDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241326.aspx
    """

    def __init__(self, deviceType: DeviceType, deviceID: int, preferredDOSName: str, deviceData: bytes):
        super().__init__()
        self.deviceID = deviceID
        self.deviceType = deviceType
        self.preferredDOSName = preferredDOSName
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
                 extraFlags2: int, specialTypeDeviceCap: Optional[int]):
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
