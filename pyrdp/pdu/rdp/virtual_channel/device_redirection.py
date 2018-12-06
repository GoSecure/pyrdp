from typing import List

from pyrdp.enum import DeviceRedirectionComponent, DeviceRedirectionPacketId, \
    MajorFunction, DeviceType
from pyrdp.pdu.pdu import PDU


class DeviceRedirectionPDU(PDU):
    """
    Also called Shared Header: https://msdn.microsoft.com/en-us/library/cc241324.aspx
    """

    def __init__(self, component: int, packetId: int, payload=b""):
        super().__init__(payload)
        self.component = component
        self.packetId: DeviceRedirectionPacketId = DeviceRedirectionPacketId(packetId)


class DeviceIOResponsePDU(DeviceRedirectionPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241334.aspx
    """

    def __init__(self, deviceId: int, completionId: int, ioStatus: int, payload=None):
        super().__init__(DeviceRedirectionComponent.RDPDR_CTYP_CORE,
                         DeviceRedirectionPacketId.PAKID_CORE_DEVICE_IOCOMPLETION)
        self.deviceId = deviceId
        self.completionId = completionId
        self.ioStatus = ioStatus
        self.payload = payload


class DeviceIORequestPDU(DeviceRedirectionPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241327.aspx
    """

    def __init__(self, deviceId: int, fileId: int, completionId: int, majorFunction: int, minorFunction: int, payload=b""):
        super().__init__(DeviceRedirectionComponent.RDPDR_CTYP_CORE,
                         DeviceRedirectionPacketId.PAKID_CORE_DEVICE_IOREQUEST, payload)
        self.deviceId = deviceId
        self.fileId = fileId
        self.completionId = completionId
        self.majorFunction = majorFunction
        self.minorFunction = minorFunction


class DeviceReadResponsePDU(DeviceIOResponsePDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241337.aspx
    """

    def __init__(self, deviceId: int, completionId: int, ioStatus: int, readData: bytes):
        super().__init__(deviceId, completionId, ioStatus)
        self.readData = readData


class DeviceReadRequestPDU(DeviceIORequestPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241330.aspx
    """

    def __init__(self, deviceId: int, fileId: int, completionId: int, minorFunction: int,
                 length: int, offset: int):
        super().__init__(deviceId, fileId, completionId, MajorFunction.IRP_MJ_READ, minorFunction)
        self.length = length
        self.offset = offset


class DeviceCreateRequestPDU(DeviceIORequestPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241328.aspx
    """

    def __init__(self, deviceId: int, fileId: int, completionId: int, minorFunction: int,
                 desiredAccess: int, allocationSize: int, fileAttributes: int, sharedAccess: int,
                 createDisposition: int, createOptions: int, path: bytes):
        super().__init__(deviceId, fileId, completionId, MajorFunction.IRP_MJ_CREATE, minorFunction)
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

    def __init__(self, deviceId: int, completionId: int, ioStatus: int, fileId: int, information: bytes=b""):
        super().__init__(deviceId, completionId, ioStatus)
        self.fileId = fileId
        self.information = information


class DeviceCloseRequestPDU(DeviceIORequestPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241329.aspx
    """

    def __init__(self, deviceId: int, fileId: int, completionId: int, minorFunction: int):
        super().__init__(deviceId, fileId, completionId, MajorFunction.IRP_MJ_CLOSE, minorFunction)


class DeviceCloseResponsePDU(DeviceIOResponsePDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241336.aspx
    """

    def __init__(self, deviceId: int, completionId: int, ioStatus: int):
        super().__init__(deviceId, completionId, ioStatus)


class DeviceAnnounce(PDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241326.aspx
    """

    def __init__(self, deviceType: DeviceType, deviceId: int, preferredDosName: bytes, deviceData: bytes):
        super().__init__()
        self.deviceId = deviceId
        self.deviceType = deviceType
        self.preferredDosName = preferredDosName
        self.deviceData = deviceData


class DeviceListAnnounceRequest(DeviceRedirectionPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241355.aspx
    """

    def __init__(self, deviceList: List[DeviceAnnounce]):
        super().__init__(DeviceRedirectionComponent.RDPDR_CTYP_CORE, DeviceRedirectionPacketId.PAKID_CORE_DEVICELIST_ANNOUNCE)
        self.deviceList = deviceList
