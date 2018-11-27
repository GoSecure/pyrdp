from io import BytesIO

from rdpy.core.packing import Uint16LE, Uint32LE
from rdpy.enum.virtual_channel.device_redirection import DeviceRedirectionComponent, DeviceRedirectionPacketId
from rdpy.parser.parser import Parser
from rdpy.pdu.rdp.virtual_channel.device_redirection import DeviceRedirectionPDU, DeviceIOResponsePDU


class DeviceRedirectionParser(Parser):
    """
    Parser for the device redirection channel (rdpdr) packets. Some features are missing.
    """

    def __init__(self):
        super().__init__()
        self.parsers = {
            DeviceRedirectionPacketId.PAKID_CORE_DEVICE_IOCOMPLETION: self.parseDeviceIOResponse
        }

    def parse(self, data: bytes):
        stream = BytesIO(data)
        component = DeviceRedirectionComponent(Uint16LE.unpack(stream))
        packetId = DeviceRedirectionPacketId(Uint16LE.unpack(stream))

        if component == DeviceRedirectionComponent.RDPDR_CTYP_PRN:
            raise NotImplementedError("Printing components are not handled yet.")

        if packetId in self.parsers.keys():
            return self.parsers[packetId](stream)
        else:
            return DeviceRedirectionPDU(component, packetId)

    def parseDeviceIORequest(self, stream: BytesIO):
        pass

    def parseDeviceIOResponse(self, stream: BytesIO) -> DeviceIOResponsePDU:
        deviceId = Uint32LE.unpack(stream)
        completionId = Uint32LE.unpack(stream)
        ioStatus = Uint32LE.unpack(stream)
        payload = stream.read()
        return DeviceIOResponsePDU(deviceId, completionId, ioStatus, payload=payload)

    def write(self, pdu):
        raise NotImplementedError("Writing for device redirection packets has not been implemented yet.")