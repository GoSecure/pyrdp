from rdpy.enum.virtual_channel.device_redirection import DeviceRedirectionComponent, DeviceRedirectionPacketId
from rdpy.pdu.base_pdu import PDU


class DeviceRedirectionPDU(PDU):
    """
    Also called Shared Header: https://msdn.microsoft.com/en-us/library/cc241324.aspx
    """

    def __init__(self, component: int, packetId: int):
        super().__init__()
        self.component = component
        self.packetId = packetId


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

    def __init__(self, deviceId: int, fileId: int, completionId: int, majorFunction: int, minorFunction: int):
        super().__init__(DeviceRedirectionComponent.RDPDR_CTYP_CORE,
                         DeviceRedirectionPacketId.PAKID_CORE_DEVICE_IOREQUEST)
        self.deviceId = deviceId
        self.fileId = fileId
        self.completionId = completionId
        self.majorFunction = majorFunction
        self.minorFunction = minorFunction


class DeviceReadResponsePDU(DeviceIOResponsePDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241337.aspx
    """

    def __init__(self, readData: bytes):
        super().__init__()
        self.readData = readData
