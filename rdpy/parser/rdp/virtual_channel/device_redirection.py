from io import BytesIO

from rdpy.core.packing import Uint16LE, Uint32LE, Uint64LE
from rdpy.enum.virtual_channel.device_redirection import DeviceRedirectionComponent, DeviceRedirectionPacketId, \
    MajorFunction
from rdpy.parser.parser import Parser
from rdpy.pdu.rdp.virtual_channel.device_redirection import DeviceRedirectionPDU, DeviceIOResponsePDU, \
    DeviceIORequestPDU, DeviceReadResponsePDU, DeviceReadRequestPDU


class DeviceRedirectionParser(Parser):
    """
    Parser for the device redirection channel (rdpdr) packets. Some features are missing.
    """

    def __init__(self):
        super().__init__()
        self.parsers = {
            DeviceRedirectionPacketId.PAKID_CORE_DEVICE_IOCOMPLETION: self.parseDeviceIOResponse,
            DeviceRedirectionPacketId.PAKID_CORE_DEVICE_IOREQUEST: self.parseDeviceIORequest
        }

        self.ioRequestParsers = {
            MajorFunction.IRP_MJ_READ: self.parseDeviceReadRequest
        }

    def parse(self, data: bytes):
        stream = BytesIO(data)
        unpack = Uint16LE.unpack(stream)
        component = DeviceRedirectionComponent(unpack)
        packetId = DeviceRedirectionPacketId(Uint16LE.unpack(stream))

        if component == DeviceRedirectionComponent.RDPDR_CTYP_PRN:
            raise NotImplementedError("Printer components are not handled yet.")

        if packetId in self.parsers.keys():
            return self.parsers[packetId](stream)
        else:
            return DeviceRedirectionPDU(component, packetId)

    def parseDeviceIORequest(self, stream: BytesIO) -> DeviceIORequestPDU:
        """
        Starts after the rdpdr header.
        """
        deviceId = Uint32LE.unpack(stream)
        fileId = Uint32LE.unpack(stream)
        completionId = Uint32LE.unpack(stream)
        majorFunction = MajorFunction(Uint32LE.unpack(stream))
        minorFunction = Uint32LE.unpack(stream)
        if majorFunction in self.ioRequestParsers.keys():
            return self.ioRequestParsers[majorFunction](deviceId, fileId, completionId, majorFunction,
                                                        minorFunction, stream)
        else:
            return DeviceIORequestPDU(deviceId, fileId, completionId, majorFunction, minorFunction)

    def parseDeviceReadRequest(self, deviceId: int, fileId: int, completionId: int, majorFunction: int,
                               minorFunction: int, stream: BytesIO) -> DeviceReadRequestPDU:
        """
        Starting at length, just before offset
        """
        length = Uint32LE.unpack(stream)
        offset = Uint64LE.unpack(stream)
        return DeviceReadRequestPDU(deviceId, fileId, completionId, majorFunction, minorFunction,
                                    length, offset)

    def parseDeviceIOResponse(self, stream: BytesIO) -> DeviceIOResponsePDU:
        """
        Starts after the rdpdr header.
        """
        deviceId = Uint32LE.unpack(stream)
        completionId = Uint32LE.unpack(stream)
        ioStatus = Uint32LE.unpack(stream)
        payload = stream.read()
        return DeviceIOResponsePDU(deviceId, completionId, ioStatus, payload=payload)

    def parseReadResponse(self, pdu: DeviceIOResponsePDU) -> DeviceReadResponsePDU:
        """
        Starts at length (just before readData). This one is a bit special since we need
        to look at previous packet before parsing it as a read response, and we need the packet data.
        """
        stream = BytesIO(pdu.payload)
        length = Uint32LE.unpack(stream)
        readData = stream.read(length)
        return DeviceReadResponsePDU(pdu.deviceId, pdu.completionId, pdu.ioStatus, readData)


    def write(self, pdu):
        raise NotImplementedError("Writing for device redirection packets has not been implemented yet.")