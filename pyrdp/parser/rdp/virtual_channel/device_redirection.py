from io import BytesIO
from typing import Dict

from pyrdp.core import Uint16LE, Uint32LE, Uint64LE
from pyrdp.enum import DeviceRedirectionComponent, DeviceRedirectionPacketId, DeviceType, MajorFunction
from pyrdp.enum.virtual_channel.device_redirection import CapabilityType, GeneralCapabilityVersion
from pyrdp.logging import log
from pyrdp.parser.parser import Parser
from pyrdp.pdu import DeviceAnnounce, DeviceCloseRequestPDU, DeviceCloseResponsePDU, DeviceCreateRequestPDU, \
    DeviceCreateResponsePDU, DeviceIORequestPDU, DeviceIOResponsePDU, DeviceListAnnounceRequest, DeviceReadRequestPDU, \
    DeviceReadResponsePDU, DeviceRedirectionPDU
from pyrdp.pdu.rdp.virtual_channel.device_redirection import DeviceRedirectionCapabilitiesPDU, \
    DeviceRedirectionCapability, DeviceRedirectionGeneralCapability


class DeviceRedirectionParser(Parser):
    """
    Parser for the device redirection channel (rdpdr) packets. Some features are missing.
    """

    def __init__(self):
        super().__init__()
        self.parsers: Dict[DeviceRedirectionPacketId, callable] = {
            DeviceRedirectionPacketId.PAKID_CORE_DEVICE_IOCOMPLETION: self.parseDeviceIOResponse,
            DeviceRedirectionPacketId.PAKID_CORE_DEVICE_IOREQUEST: self.parseDeviceIORequest,
            DeviceRedirectionPacketId.PAKID_CORE_DEVICELIST_ANNOUNCE: self.parseDeviceListAnnounce,
            DeviceRedirectionPacketId.PAKID_CORE_SERVER_CAPABILITY: self.parseCapabilities,
        }
        self.writers: Dict[DeviceRedirectionPacketId, callable] = {
            DeviceRedirectionPacketId.PAKID_CORE_DEVICE_IOREQUEST: self.writeDeviceIORequest,
            DeviceRedirectionPacketId.PAKID_CORE_DEVICE_IOCOMPLETION: self.writeDeviceIOResponse,
            DeviceRedirectionPacketId.PAKID_CORE_DEVICELIST_ANNOUNCE: self.writeDeviceListAnnounce,
            DeviceRedirectionPacketId.PAKID_CORE_SERVER_CAPABILITY: self.writeCapabilities,
        }

        self.ioRequestParsers: Dict[MajorFunction, callable] = {
            MajorFunction.IRP_MJ_READ: self.parseDeviceReadRequest,
            MajorFunction.IRP_MJ_CREATE: self.parseDeviceCreateRequest,
            MajorFunction.IRP_MJ_CLOSE: self.parseDeviceCloseRequest
        }
        self.ioRequestWriters: Dict[MajorFunction, callable] = {
            MajorFunction.IRP_MJ_CREATE: self.writeCreateRequest,
            MajorFunction.IRP_MJ_CLOSE: self.writeCloseRequest,
            MajorFunction.IRP_MJ_READ: self.writeReadRequest
        }

        self.ioResponseWriters: Dict[type, callable] = {
            DeviceCreateResponsePDU: self.writeCreateResponse,
            DeviceCloseResponsePDU: self.writeCloseResponse,
            DeviceReadResponsePDU: self.writeReadResponse,
        }

    def parse(self, data: bytes) -> DeviceRedirectionPDU:
        stream = BytesIO(data)
        unpack = Uint16LE.unpack(stream)
        component = DeviceRedirectionComponent(unpack)
        packetId = DeviceRedirectionPacketId(Uint16LE.unpack(stream))

        if component == DeviceRedirectionComponent.RDPDR_CTYP_PRN:
            log.warning("Received Printing component packets, which are not handled. Might cause a crash.")

        if packetId in self.parsers.keys():
            return self.parsers[packetId](stream)
        else:
            return DeviceRedirectionPDU(component, packetId, payload=stream.read())

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
            return self.ioRequestParsers[majorFunction](deviceId, fileId, completionId,
                                                        minorFunction, stream)
        else:
            return DeviceIORequestPDU(deviceId, fileId, completionId, majorFunction, minorFunction, payload=stream.read())

    def parseDeviceListAnnounce(self, stream: BytesIO) -> DeviceListAnnounceRequest:
        deviceCount = Uint32LE.unpack(stream)
        deviceList = []
        for i in range(deviceCount):
            deviceList.append(self.parseSingleDeviceAnnounce(stream))
        return DeviceListAnnounceRequest(deviceList)

    def parseCapabilities(self, stream: BytesIO) -> DeviceRedirectionCapabilitiesPDU:
        numCapabilities = Uint16LE.unpack(stream)
        stream.read(2)  # Padding
        capabilities = []
        for i in range(numCapabilities):
            capabilities.append(self.parseSingleCapability(stream))
        return DeviceRedirectionCapabilitiesPDU(DeviceRedirectionPacketId.PAKID_CORE_SERVER_CAPABILITY, capabilities)

    def writeDeviceListAnnounce(self, pdu: DeviceListAnnounceRequest, stream: BytesIO):
        Uint32LE.pack(len(pdu.deviceList), stream)
        for device in pdu.deviceList:
            self.writeSingleDeviceAnnounce(device, stream)

    def writeCapabilities(self, pdu: DeviceRedirectionCapabilitiesPDU, stream: BytesIO):
        Uint16LE.pack(len(pdu.capabilities), stream)
        stream.write(b"\x00" * 2)  # Padding
        for capability in pdu.capabilities:
            self.writeSingleCapability(capability, stream)

    def parseDeviceReadRequest(self, deviceId: int, fileId: int, completionId: int,
                               minorFunction: int, stream: BytesIO) -> DeviceReadRequestPDU:
        """
        Starting at length, just before offset
        """
        length = Uint32LE.unpack(stream)
        offset = Uint64LE.unpack(stream)
        return DeviceReadRequestPDU(deviceId, fileId, completionId, minorFunction,
                                    length, offset)

    def parseDeviceCreateRequest(self, deviceId: int, fileId: int, completionId: int,
                                 minorFunction: int, stream: BytesIO) -> DeviceCreateRequestPDU:
        """
        Starting at desiredAccess.
        """
        desiredAccess = Uint32LE.unpack(stream)
        allocationSize = Uint64LE.unpack(stream)
        fileAttributes = Uint32LE.unpack(stream)
        sharedAccess = Uint32LE.unpack(stream)
        createDisposition = Uint32LE.unpack(stream)
        createOptions = Uint32LE.unpack(stream)
        pathLength = Uint32LE.unpack(stream)
        path = stream.read(pathLength)
        return DeviceCreateRequestPDU(deviceId, fileId, completionId, minorFunction, desiredAccess, allocationSize, fileAttributes,
                                      sharedAccess, createDisposition, createOptions, path)

    def parseDeviceCloseRequest(self, deviceId: int, fileId: int, completionId: int,
                                minorFunction: int, stream: BytesIO) -> DeviceCloseRequestPDU:
        return DeviceCloseRequestPDU(deviceId, fileId, completionId, minorFunction)

    def parseDeviceCreateResponse(self, pdu: DeviceIOResponsePDU) -> DeviceCreateResponsePDU:
        """
        The information field is not yet parsed (it's optional).
        This one is a bit special since we need to look at previous packet before parsing it as
        a read response, and we need the packet data.
        """
        stream = BytesIO(pdu.payload)
        fileId = Uint32LE.unpack(stream)
        information = stream.read()
        return DeviceCreateResponsePDU(pdu.deviceId, pdu.completionId, pdu.ioStatus, fileId, information)

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

    def write(self, pdu: DeviceRedirectionPDU) -> bytes:
        stream = BytesIO()
        Uint16LE.pack(pdu.component, stream)
        Uint16LE.pack(pdu.packetId, stream)
        if pdu.packetId in self.writers.keys():
            self.writers[pdu.packetId](pdu, stream)
        else:
            stream.write(pdu.payload)
        return stream.getvalue()

    def writeDeviceIORequest(self, pdu: DeviceIORequestPDU, stream: BytesIO):
        Uint32LE.pack(pdu.deviceId, stream)
        Uint32LE.pack(pdu.fileId, stream)
        Uint32LE.pack(pdu.completionId, stream)
        Uint32LE.pack(pdu.majorFunction, stream)
        Uint32LE.pack(pdu.minorFunction, stream)
        if pdu.majorFunction in self.ioRequestWriters.keys():
            self.ioRequestWriters[pdu.majorFunction](pdu, stream)
        else:
            stream.write(pdu.payload)

    def writeDeviceIOResponse(self, pdu: DeviceIOResponsePDU, stream: BytesIO):
        Uint32LE.pack(pdu.deviceId, stream)
        Uint32LE.pack(pdu.completionId, stream)
        Uint32LE.pack(pdu.ioStatus, stream)
        if type(pdu) in self.ioResponseWriters.keys():
            self.ioResponseWriters[type(pdu)](pdu, stream)
        else:
            stream.write(pdu.payload)

    def writeCreateRequest(self, pdu: DeviceCreateRequestPDU, stream: BytesIO):
        Uint32LE.pack(pdu.desiredAccess, stream)
        Uint64LE.pack(pdu.allocationSize, stream)
        Uint32LE.pack(pdu.fileAttributes, stream)
        Uint32LE.pack(pdu.sharedAccess, stream)
        Uint32LE.pack(pdu.createDisposition, stream)
        Uint32LE.pack(pdu.createOptions, stream)
        Uint32LE.pack(len(pdu.path), stream)
        stream.write(pdu.path)

    def writeCloseRequest(self, pdu: DeviceCloseRequestPDU, stream: BytesIO):
        stream.write(b"\x00"*32)  # Padding

    def writeReadRequest(self, pdu: DeviceReadRequestPDU, stream: BytesIO):
        Uint32LE.pack(pdu.length, stream)
        Uint32LE.pack(pdu.offset, stream)
        stream.write(b"\x00" * 20)  # Padding

    def writeCreateResponse(self, pdu: DeviceCreateResponsePDU, stream: BytesIO):
        Uint32LE.pack(pdu.fileId, stream)
        stream.write(pdu.information)

    def writeCloseResponse(self, pdu: DeviceCloseResponsePDU, stream: BytesIO):
        stream.write(b"\x00" * 4)  # Padding

    def writeReadResponse(self, pdu: DeviceReadResponsePDU, stream: BytesIO):
        Uint32LE.pack(len(pdu.readData), stream)
        stream.write(pdu.readData)

    def parseSingleDeviceAnnounce(self, stream: BytesIO):
        deviceType = DeviceType(Uint32LE.unpack(stream))
        deviceId = Uint32LE.unpack(stream)
        preferredDosName = stream.read(8)
        deviceDataLength = Uint32LE.unpack(stream)
        deviceData = stream.read(deviceDataLength)
        return DeviceAnnounce(deviceType, deviceId, preferredDosName, deviceData)

    def writeSingleDeviceAnnounce(self, pdu: DeviceAnnounce, stream: BytesIO):
        Uint32LE.pack(pdu.deviceType, stream)
        Uint32LE.pack(pdu.deviceId, stream)
        stream.write(pdu.preferredDosName)
        Uint32LE.pack(len(pdu.deviceData), stream)
        stream.write(pdu.deviceData)

    def parseSingleCapability(self, stream: BytesIO) -> DeviceRedirectionCapability:
        """
        https://msdn.microsoft.com/en-us/library/cc241325.aspx
        """
        capabilityType = Uint16LE.unpack(stream)
        capabilityLength = Uint16LE.unpack(stream)
        version = Uint32LE.unpack(stream)
        payload = stream.read(capabilityLength - 8)
        return DeviceRedirectionCapability(CapabilityType(capabilityType), version, payload=payload)

    def parseGeneralCapability(self, version: int, payload: bytes) -> DeviceRedirectionGeneralCapability:
        stream = BytesIO(payload)
        osType = Uint32LE.unpack(stream)
        osVersion = Uint32LE.unpack(stream)
        protocolMajorVersion = Uint16LE.unpack(stream)
        protocolMinorVersion = Uint16LE.unpack(stream)
        ioCode1 = Uint32LE.unpack(stream)
        ioCode2 = Uint32LE.unpack(stream)
        extendedPDU = Uint32LE.unpack(stream)
        extraFlags1 = Uint32LE.unpack(stream)
        extraFlags2 = Uint32LE.unpack(stream)
        specialTypeDeviceCap = None
        if version == GeneralCapabilityVersion.GENERAL_CAPABILITY_VERSION_02:
            specialTypeDeviceCap = Uint32LE.unpack(stream)
        return DeviceRedirectionGeneralCapability(version, osType, osVersion, protocolMajorVersion,
                                                  protocolMinorVersion, ioCode1, ioCode2, extendedPDU, extraFlags1,
                                                  extraFlags2, specialTypeDeviceCap)

    def writeSingleCapability(self, capability: DeviceRedirectionCapability, stream: BytesIO):
        Uint16LE.pack(capability.capabilityType, stream)
        Uint16LE.pack(len(capability.payload) + 8, stream)
        Uint32LE.pack(capability.version, stream)
        stream.write(capability.payload)
