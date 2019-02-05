#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO
from typing import Dict, Tuple

from pyrdp.core import Uint16LE, Uint32LE, Uint64LE
from pyrdp.enum import DeviceRedirectionComponent, DeviceRedirectionPacketID, DeviceType, \
    GeneralCapabilityVersion, MajorFunction
from pyrdp.enum.virtual_channel.device_redirection import RDPDRCapabilityType
from pyrdp.logging import log
from pyrdp.parser import Parser
from pyrdp.pdu import DeviceAnnounce, DeviceCloseRequestPDU, DeviceCloseResponsePDU, DeviceCreateRequestPDU, \
    DeviceCreateResponsePDU, DeviceIORequestPDU, DeviceIOResponsePDU, DeviceListAnnounceRequest, DeviceReadRequestPDU, \
    DeviceReadResponsePDU, DeviceRedirectionCapabilitiesPDU, DeviceRedirectionCapability, \
    DeviceRedirectionClientCapabilitiesPDU, DeviceRedirectionGeneralCapability, DeviceRedirectionPDU, \
    DeviceRedirectionServerCapabilitiesPDU


class DeviceRedirectionParser(Parser):
    """
    Parser for the device redirection channel (rdpdr) packets. Some features are missing.
    """

    def __init__(self):
        super().__init__()

        self.parsers: Dict[DeviceRedirectionPacketID, callable] = {
            DeviceRedirectionPacketID.PAKID_CORE_DEVICE_IOREQUEST: self.parseDeviceIORequest,
            DeviceRedirectionPacketID.PAKID_CORE_DEVICE_IOCOMPLETION: self.parseDeviceIOResponse,
            DeviceRedirectionPacketID.PAKID_CORE_DEVICELIST_ANNOUNCE: self.parseDeviceListAnnounce,
            DeviceRedirectionPacketID.PAKID_CORE_CLIENT_CAPABILITY: self.parseClientCapabilities,
            DeviceRedirectionPacketID.PAKID_CORE_SERVER_CAPABILITY: self.parseServerCapabilities,
        }

        self.writers: Dict[DeviceRedirectionPacketID, callable] = {
            DeviceRedirectionPacketID.PAKID_CORE_DEVICE_IOREQUEST: self.writeDeviceIORequest,
            DeviceRedirectionPacketID.PAKID_CORE_DEVICE_IOCOMPLETION: self.writeDeviceIOResponse,
            DeviceRedirectionPacketID.PAKID_CORE_DEVICELIST_ANNOUNCE: self.writeDeviceListAnnounce,
            DeviceRedirectionPacketID.PAKID_CORE_CLIENT_CAPABILITY: self.writeCapabilities,
            DeviceRedirectionPacketID.PAKID_CORE_SERVER_CAPABILITY: self.writeCapabilities,
        }

        self.ioRequestParsers: Dict[MajorFunction, callable] = {
            MajorFunction.IRP_MJ_CREATE: self.parseDeviceCreateRequest,
            MajorFunction.IRP_MJ_READ: self.parseDeviceReadRequest,
            MajorFunction.IRP_MJ_CLOSE: self.parseDeviceCloseRequest,
        }

        self.ioRequestWriters: Dict[MajorFunction, callable] = {
            MajorFunction.IRP_MJ_CREATE: self.writeDeviceCreateRequest,
            MajorFunction.IRP_MJ_READ: self.writeDeviceReadRequest,
            MajorFunction.IRP_MJ_CLOSE: self.writeDeviceCloseRequest,
        }

        self.ioResponseWriters: Dict[type, callable] = {
            DeviceCreateResponsePDU: self.writeDeviceCreateResponse,
            DeviceReadResponsePDU: self.writeDeviceReadResponse,
            DeviceCloseResponsePDU: self.writeDeviceCloseResponse,
        }



    def parse(self, data: bytes) -> DeviceRedirectionPDU:
        stream = BytesIO(data)
        unpack = Uint16LE.unpack(stream)
        component = DeviceRedirectionComponent(unpack)
        packetId = DeviceRedirectionPacketID(Uint16LE.unpack(stream))

        if component == DeviceRedirectionComponent.RDPDR_CTYP_PRN:
            log.warning("Received Printing component packets, which are not handled. Might cause a crash.")

        if packetId in self.parsers.keys():
            return self.parsers[packetId](stream)
        else:
            return DeviceRedirectionPDU(component, packetId, payload=stream.read())

    def write(self, pdu: DeviceRedirectionPDU) -> bytes:
        stream = BytesIO()
        Uint16LE.pack(pdu.component, stream)
        Uint16LE.pack(pdu.packetID, stream)

        if pdu.packetID in self.writers.keys():
            self.writers[pdu.packetID](pdu, stream)
        else:
            stream.write(pdu.payload)

        return stream.getvalue()



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
            return self.ioRequestParsers[majorFunction](deviceId, fileId, completionId, minorFunction, stream)
        else:
            return DeviceIORequestPDU(deviceId, fileId, completionId, majorFunction, minorFunction, payload=stream.read())

    def writeDeviceIORequest(self, pdu: DeviceIORequestPDU, stream: BytesIO):
        Uint32LE.pack(pdu.deviceID, stream)
        Uint32LE.pack(pdu.fileID, stream)
        Uint32LE.pack(pdu.completionID, stream)
        Uint32LE.pack(pdu.majorFunction, stream)
        Uint32LE.pack(pdu.minorFunction, stream)

        if pdu.majorFunction in self.ioRequestWriters.keys():
            self.ioRequestWriters[pdu.majorFunction](pdu, stream)
        else:
            stream.write(pdu.payload)



    def parseDeviceIOResponse(self, stream: BytesIO) -> DeviceIOResponsePDU:
        """
        Starts after the rdpdr header.
        """
        deviceId = Uint32LE.unpack(stream)
        completionId = Uint32LE.unpack(stream)
        ioStatus = Uint32LE.unpack(stream)
        payload = stream.read()

        return DeviceIOResponsePDU(deviceId, completionId, ioStatus, payload=payload)

    def writeDeviceIOResponse(self, pdu: DeviceIOResponsePDU, stream: BytesIO):
        Uint32LE.pack(pdu.deviceID, stream)
        Uint32LE.pack(pdu.completionID, stream)
        Uint32LE.pack(pdu.ioStatus, stream)

        if type(pdu) in self.ioResponseWriters.keys():
            self.ioResponseWriters[type(pdu)](pdu, stream)
        else:
            stream.write(pdu.payload)



    def parseDeviceListAnnounce(self, stream: BytesIO) -> DeviceListAnnounceRequest:
        deviceCount = Uint32LE.unpack(stream)
        deviceList = []

        for i in range(deviceCount):
            deviceList.append(self.parseSingleDeviceAnnounce(stream))

        return DeviceListAnnounceRequest(deviceList)

    def writeDeviceListAnnounce(self, pdu: DeviceListAnnounceRequest, stream: BytesIO):
        Uint32LE.pack(len(pdu.deviceList), stream)

        for device in pdu.deviceList:
            self.writeSingleDeviceAnnounce(device, stream)

    def parseSingleDeviceAnnounce(self, stream: BytesIO):
        deviceType = DeviceType(Uint32LE.unpack(stream))
        deviceId = Uint32LE.unpack(stream)
        preferredDosName = stream.read(8)
        deviceDataLength = Uint32LE.unpack(stream)
        deviceData = stream.read(deviceDataLength)

        return DeviceAnnounce(deviceType, deviceId, preferredDosName, deviceData)

    def writeSingleDeviceAnnounce(self, pdu: DeviceAnnounce, stream: BytesIO):
        Uint32LE.pack(pdu.deviceType, stream)
        Uint32LE.pack(pdu.deviceID, stream)
        stream.write(pdu.preferredDosName)
        Uint32LE.pack(len(pdu.deviceData), stream)
        stream.write(pdu.deviceData)



    def parseClientCapabilities(self, stream: BytesIO) -> DeviceRedirectionClientCapabilitiesPDU:
        numCapabilities = Uint16LE.unpack(stream)
        stream.read(2)  # Padding
        capabilities = self.parseCapabilities(numCapabilities, stream)

        return DeviceRedirectionClientCapabilitiesPDU(capabilities)

    def parseServerCapabilities(self, stream: BytesIO) -> DeviceRedirectionServerCapabilitiesPDU:
        numCapabilities = Uint16LE.unpack(stream)
        stream.read(2)  # Padding
        capabilities = self.parseCapabilities(numCapabilities, stream)

        return DeviceRedirectionServerCapabilitiesPDU(capabilities)

    def parseCapabilities(self, numCapabilities: int, stream: BytesIO) -> Dict[RDPDRCapabilityType, DeviceRedirectionCapability]:
        capabilities = {}

        for i in range(numCapabilities):
            capabilityType, capability = self.parseSingleCapability(stream)
            capabilities[capabilityType] = capability

        return capabilities

    def writeCapabilities(self, pdu: DeviceRedirectionCapabilitiesPDU, stream: BytesIO):
        Uint16LE.pack(len(pdu.capabilities), stream)
        stream.write(b"\x00" * 2)  # Padding

        for capability in pdu.capabilities.values():
            self.writeSingleCapability(capability, stream)

    def parseSingleCapability(self, stream: BytesIO) -> Tuple[RDPDRCapabilityType, DeviceRedirectionCapability]:
        """
        https://msdn.microsoft.com/en-us/library/cc241325.aspx
        """
        capabilityType = RDPDRCapabilityType(Uint16LE.unpack(stream))
        capabilityLength = Uint16LE.unpack(stream)
        version = Uint32LE.unpack(stream)
        payload = stream.read(capabilityLength - 8)

        if capabilityType == RDPDRCapabilityType.CAP_GENERAL_TYPE:
            return capabilityType, self.parseGeneralCapability(version, payload)
        else:
            return capabilityType, DeviceRedirectionCapability(capabilityType, version, payload=payload)

    def writeSingleCapability(self, capability: DeviceRedirectionCapability, stream: BytesIO):
        Uint16LE.pack(capability.capabilityType, stream)
        substream = BytesIO()

        if isinstance(capability, DeviceRedirectionGeneralCapability):
            self.writeGeneralCapability(capability, substream)
        else:
            substream.write(capability.payload)

        Uint16LE.pack(len(substream.getvalue()) + 8, stream)
        Uint32LE.pack(capability.version, stream)
        stream.write(substream.getvalue())

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

    def writeGeneralCapability(self, capability: DeviceRedirectionGeneralCapability, stream: BytesIO):
        Uint32LE.pack(capability.osType, stream)
        Uint32LE.pack(capability.osVersion, stream)
        Uint16LE.pack(capability.protocolMajorVersion, stream)
        Uint16LE.pack(capability.protocolMinorVersion, stream)
        Uint32LE.pack(capability.ioCode1, stream)
        Uint32LE.pack(capability.ioCode2, stream)
        Uint32LE.pack(capability.extendedPDU, stream)
        Uint32LE.pack(capability.extraFlags1, stream)
        Uint32LE.pack(capability.extraFlags2, stream)

        if capability.version == GeneralCapabilityVersion.GENERAL_CAPABILITY_VERSION_02:
            Uint32LE.pack(capability.specialTypeDeviceCap, stream)



    def parseDeviceCreateRequest(self, deviceId: int, fileId: int, completionId: int, minorFunction: int, stream: BytesIO) -> DeviceCreateRequestPDU:
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

        return DeviceCreateRequestPDU(deviceId, fileId, completionId, minorFunction, desiredAccess, allocationSize,
                                      fileAttributes, sharedAccess, createDisposition, createOptions, path)

    def writeDeviceCreateRequest(self, pdu: DeviceCreateRequestPDU, stream: BytesIO):
        Uint32LE.pack(pdu.desiredAccess, stream)
        Uint64LE.pack(pdu.allocationSize, stream)
        Uint32LE.pack(pdu.fileAttributes, stream)
        Uint32LE.pack(pdu.sharedAccess, stream)
        Uint32LE.pack(pdu.createDisposition, stream)
        Uint32LE.pack(pdu.createOptions, stream)
        Uint32LE.pack(len(pdu.path), stream)
        stream.write(pdu.path)



    def parseDeviceReadRequest(self, deviceId: int, fileId: int, completionId: int, minorFunction: int, stream: BytesIO) -> DeviceReadRequestPDU:
        """
        Starting at length, just before offset
        """
        length = Uint32LE.unpack(stream)
        offset = Uint64LE.unpack(stream)

        return DeviceReadRequestPDU(deviceId, fileId, completionId, minorFunction, length, offset)

    def writeDeviceReadRequest(self, pdu: DeviceReadRequestPDU, stream: BytesIO):
        Uint32LE.pack(pdu.length, stream)
        Uint32LE.pack(pdu.offset, stream)
        stream.write(b"\x00" * 20)  # Padding



    def parseDeviceCloseRequest(self, deviceId: int, fileId: int, completionId: int, minorFunction: int, _: BytesIO) -> DeviceCloseRequestPDU:
        return DeviceCloseRequestPDU(deviceId, fileId, completionId, minorFunction)

    def writeDeviceCloseRequest(self, _: DeviceCloseRequestPDU, stream: BytesIO):
        stream.write(b"\x00" * 32)  # Padding



    def parseDeviceCreateResponse(self, pdu: DeviceIOResponsePDU) -> DeviceCreateResponsePDU:
        """
        The information field is not yet parsed (it's optional).
        This one is a bit special since we need to look at previous packet before parsing it as
        a read response, and we need the packet data.
        """
        stream = BytesIO(pdu.payload)
        fileId = Uint32LE.unpack(stream)
        information = stream.read()

        return DeviceCreateResponsePDU(pdu.deviceID, pdu.completionID, pdu.ioStatus, fileId, information)

    def writeDeviceCreateResponse(self, pdu: DeviceCreateResponsePDU, stream: BytesIO):
        Uint32LE.pack(pdu.fileID, stream)
        stream.write(pdu.information)



    def parseDeviceReadResponse(self, pdu: DeviceIOResponsePDU) -> DeviceReadResponsePDU:
        """
        Starts at length (just before readData). This one is a bit special since we need
        to look at previous packet before parsing it as a read response, and we need the packet data.
        """
        stream = BytesIO(pdu.payload)
        length = Uint32LE.unpack(stream)
        readData = stream.read(length)

        return DeviceReadResponsePDU(pdu.deviceID, pdu.completionID, pdu.ioStatus, readData)

    def writeDeviceReadResponse(self, pdu: DeviceReadResponsePDU, stream: BytesIO):
        Uint32LE.pack(len(pdu.readData), stream)
        stream.write(pdu.readData)



    def writeDeviceCloseResponse(self, _: DeviceCloseResponsePDU, stream: BytesIO):
        stream.write(b"\x00" * 4)  # Padding