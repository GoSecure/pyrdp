#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO
from typing import Dict, List, Union

from pyrdp.core import decodeUTF16LE, Uint16LE, Uint32LE, Uint64LE, Uint8
from pyrdp.enum import DeviceRedirectionComponent, DeviceRedirectionPacketID, DeviceType, FileAttributes, \
    FileCreateDisposition, FileCreateOptions, FileShareAccess, FileSystemInformationClass, GeneralCapabilityVersion, \
    MajorFunction, MinorFunction, RDPDRCapabilityType
from pyrdp.parser import Parser
from pyrdp.pdu import DeviceAnnounce, DeviceCloseRequestPDU, DeviceCloseResponsePDU, DeviceCreateRequestPDU, \
    DeviceCreateResponsePDU, DeviceDirectoryControlResponsePDU, DeviceIORequestPDU, DeviceIOResponsePDU, \
    DeviceListAnnounceRequest, DeviceQueryDirectoryRequestPDU, DeviceQueryDirectoryResponsePDU, DeviceReadRequestPDU, \
    DeviceReadResponsePDU, DeviceRedirectionCapabilitiesPDU, DeviceRedirectionCapability, \
    DeviceRedirectionClientCapabilitiesPDU, DeviceRedirectionGeneralCapability, DeviceRedirectionPDU, \
    DeviceRedirectionServerCapabilitiesPDU, FileBothDirectoryInformation, FileDirectoryInformation, \
    FileFullDirectoryInformation, FileNamesInformation


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

        self.capabilityParsers: Dict[RDPDRCapabilityType, callable] = {
            RDPDRCapabilityType.CAP_GENERAL_TYPE: self.parseGeneralCapability,
        }

        self.capabilityWriters: Dict[RDPDRCapabilityType, callable] = {
            RDPDRCapabilityType.CAP_GENERAL_TYPE: self.writeGeneralCapability,
        }

        self.ioRequestParsers: Dict[MajorFunction, callable] = {
            MajorFunction.IRP_MJ_CREATE: self.parseDeviceCreateRequest,
            MajorFunction.IRP_MJ_READ: self.parseDeviceReadRequest,
            MajorFunction.IRP_MJ_CLOSE: self.parseDeviceCloseRequest,
            MajorFunction.IRP_MJ_DIRECTORY_CONTROL: self.parseDirectoryControlRequest,
        }

        self.ioRequestWriters: Dict[MajorFunction, callable] = {
            MajorFunction.IRP_MJ_CREATE: self.writeDeviceCreateRequest,
            MajorFunction.IRP_MJ_READ: self.writeDeviceReadRequest,
            MajorFunction.IRP_MJ_CLOSE: self.writeDeviceCloseRequest,
            MajorFunction.IRP_MJ_DIRECTORY_CONTROL: self.writeDirectoryControlRequest,
        }

        self.ioResponseParsers: Dict[MajorFunction, callable] = {
            MajorFunction.IRP_MJ_CREATE: self.parseDeviceCreateResponse,
            MajorFunction.IRP_MJ_READ: self.parseDeviceReadResponse,
            MajorFunction.IRP_MJ_CLOSE: self.parseDeviceCloseResponse,
            MajorFunction.IRP_MJ_DIRECTORY_CONTROL: self.parseDirectoryControlResponse,
        }

        self.ioResponseWriters: Dict[MajorFunction, callable] = {
            MajorFunction.IRP_MJ_CREATE: self.writeDeviceCreateResponse,
            MajorFunction.IRP_MJ_READ: self.writeDeviceReadResponse,
            MajorFunction.IRP_MJ_CLOSE: self.writeDeviceCloseResponse,
            MajorFunction.IRP_MJ_DIRECTORY_CONTROL: self.writeDirectoryControlResponse,
        }

        self.fileInformationParsers: Dict[FileSystemInformationClass, callable] = {
            FileSystemInformationClass.FileDirectoryInformation: self.parseFileDirectoryInformation,
            FileSystemInformationClass.FileFullDirectoryInformation: self.parseFileFullDirectoryInformation,
            FileSystemInformationClass.FileBothDirectoryInformation: self.parseFileBothDirectoryInformation,
            FileSystemInformationClass.FileNamesInformation: self.parseFileNamesInformation,
        }

        self.fileInformationWriters: Dict[FileSystemInformationClass, callable] = {
            FileSystemInformationClass.FileDirectoryInformation: self.writeFileDirectoryInformation,
            FileSystemInformationClass.FileFullDirectoryInformation: self.writeFileFullDirectoryInformation,
            FileSystemInformationClass.FileBothDirectoryInformation: self.writeFileBothDirectoryInformation,
            FileSystemInformationClass.FileNamesInformation: self.writeFileNamesInformation,
        }

        # Dictionary to keep track of information associated to each completion ID.
        self.majorFunctionsForParsingResponse: Dict[int, MajorFunction] = {}
        self.minorFunctionsForParsingResponse: Dict[int, MinorFunction] = {}
        self.informationClassForParsingResponse: Dict[int, FileSystemInformationClass] = {}


    def parse(self, data: bytes) -> DeviceRedirectionPDU:
        stream = BytesIO(data)
        component = DeviceRedirectionComponent(Uint16LE.unpack(stream))
        packetID = DeviceRedirectionPacketID(Uint16LE.unpack(stream))

        if component == DeviceRedirectionComponent.RDPDR_CTYP_CORE and packetID in self.parsers.keys():
            return self.parsers[packetID](stream)
        else:
            return DeviceRedirectionPDU(component, packetID, payload=stream.read())

    def write(self, pdu: DeviceRedirectionPDU) -> bytes:
        stream = BytesIO()
        Uint16LE.pack(pdu.component, stream)
        Uint16LE.pack(pdu.packetID, stream)

        if pdu.component == DeviceRedirectionComponent.RDPDR_CTYP_CORE and pdu.packetID in self.writers.keys():
            self.writers[pdu.packetID](pdu, stream)
        else:
            stream.write(pdu.payload)

        return stream.getvalue()


    def parseDeviceListAnnounce(self, stream: BytesIO) -> DeviceListAnnounceRequest:
        deviceCount = Uint32LE.unpack(stream)
        deviceList = [self.parseDeviceAnnounce(stream) for _ in range(deviceCount)]
        return DeviceListAnnounceRequest(deviceList)

    def writeDeviceListAnnounce(self, pdu: DeviceListAnnounceRequest, stream: BytesIO):
        Uint32LE.pack(len(pdu.deviceList), stream)

        for device in pdu.deviceList:
            self.writeDeviceAnnounce(device, stream)

    def parseDeviceAnnounce(self, stream: BytesIO) -> DeviceAnnounce:
        deviceType = DeviceType(Uint32LE.unpack(stream))
        deviceID = Uint32LE.unpack(stream)
        preferredDOSName = stream.read(8)
        deviceDataLength = Uint32LE.unpack(stream)
        deviceData = stream.read(deviceDataLength)

        preferredDOSName = preferredDOSName.decode(errors = "ignore")[: 7]

        try:
            endIndex = preferredDOSName.index("\x00")
        except ValueError:
            endIndex = -1

        if endIndex >= 0:
            preferredDOSName = preferredDOSName[: endIndex]

        return DeviceAnnounce(deviceType, deviceID, preferredDOSName, deviceData)

    def writeDeviceAnnounce(self, pdu: DeviceAnnounce, stream: BytesIO):
        Uint32LE.pack(pdu.deviceType, stream)
        Uint32LE.pack(pdu.deviceID, stream)
        stream.write(pdu.preferredDOSName.encode().ljust(7, b"\x00")[: 7] + b"\x00")
        Uint32LE.pack(len(pdu.deviceData), stream)
        stream.write(pdu.deviceData)



    def parseClientCapabilities(self, stream: BytesIO) -> DeviceRedirectionClientCapabilitiesPDU:
        capabilities = self.parseCapabilities(stream)
        return DeviceRedirectionClientCapabilitiesPDU(capabilities)

    def parseServerCapabilities(self, stream: BytesIO) -> DeviceRedirectionServerCapabilitiesPDU:
        capabilities = self.parseCapabilities(stream)
        return DeviceRedirectionServerCapabilitiesPDU(capabilities)

    def parseCapabilities(self, stream: BytesIO) -> Dict[RDPDRCapabilityType, DeviceRedirectionCapability]:
        numCapabilities = Uint16LE.unpack(stream)
        stream.read(2)  # Padding

        capabilities = {}

        for _ in range(numCapabilities):
            capability = self.parseCapability(stream)
            capabilities[capability.capabilityType] = capability

        return capabilities

    def writeCapabilities(self, pdu: DeviceRedirectionCapabilitiesPDU, stream: BytesIO):
        Uint16LE.pack(len(pdu.capabilities), stream)
        stream.write(b"\x00" * 2)  # Padding

        for capability in pdu.capabilities.values():
            self.writeCapability(capability, stream)


    def parseCapability(self, stream: BytesIO) -> DeviceRedirectionCapability:
        capabilityType = RDPDRCapabilityType(Uint16LE.unpack(stream))
        capabilityLength = Uint16LE.unpack(stream)
        version = Uint32LE.unpack(stream)
        payload = stream.read(capabilityLength - 8)

        if capabilityType in self.capabilityParsers:
            return self.capabilityParsers[capabilityType](version, payload)
        else:
            return DeviceRedirectionCapability(capabilityType, version, payload)

    def writeCapability(self, capability: DeviceRedirectionCapability, stream: BytesIO):
        Uint16LE.pack(capability.capabilityType, stream)
        substream = BytesIO()

        if capability.capabilityType in self.capabilityWriters:
            self.capabilityWriters[capability.capabilityType](capability, substream)
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

        return DeviceRedirectionGeneralCapability(
            version,
            osType,
            osVersion,
            protocolMajorVersion,
            protocolMinorVersion,
            ioCode1,
            ioCode2,
            extendedPDU,
            extraFlags1,
            extraFlags2,
            specialTypeDeviceCap
        )

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
            Uint32LE.pack(capability.specialTypeDeviceCap or 0, stream)


    def parseDeviceIORequest(self, stream: BytesIO) -> DeviceIORequestPDU:
        deviceID = Uint32LE.unpack(stream)
        fileID = Uint32LE.unpack(stream)
        completionID = Uint32LE.unpack(stream)
        majorFunction = MajorFunction(Uint32LE.unpack(stream))
        minorFunction = Uint32LE.unpack(stream)

        if majorFunction == MajorFunction.IRP_MJ_DIRECTORY_CONTROL:
            minorFunction = MinorFunction(minorFunction)

        if majorFunction in self.ioRequestParsers.keys():
            self.majorFunctionsForParsingResponse[completionID] = majorFunction
            return self.ioRequestParsers[majorFunction](deviceID, fileID, completionID, minorFunction, stream)
        else:
            return DeviceIORequestPDU(deviceID, fileID, completionID, majorFunction, minorFunction, payload=stream.read())

    def writeDeviceIORequest(self, pdu: DeviceIORequestPDU, stream: BytesIO):
        Uint32LE.pack(pdu.deviceID, stream)
        Uint32LE.pack(pdu.fileID, stream)
        Uint32LE.pack(pdu.completionID, stream)
        Uint32LE.pack(pdu.majorFunction, stream)
        Uint32LE.pack(pdu.minorFunction, stream)

        if pdu.majorFunction in self.ioRequestWriters.keys():
            # Make sure to register the PDU's major function when we write too, in case this is a forged PDU.
            self.majorFunctionsForParsingResponse[pdu.completionID] = pdu.majorFunction
            self.ioRequestWriters[pdu.majorFunction](pdu, stream)
        else:
            stream.write(pdu.payload)


    def parseDeviceIOResponse(self, stream: BytesIO) -> DeviceIOResponsePDU:
        deviceID = Uint32LE.unpack(stream)
        completionID = Uint32LE.unpack(stream)
        ioStatus = Uint32LE.unpack(stream)

        majorFunction = self.majorFunctionsForParsingResponse.pop(completionID, None)

        if majorFunction in self.ioResponseParsers:
            return self.ioResponseParsers[majorFunction](deviceID, completionID, ioStatus, stream)
        else:
            # If for some reason, we don't know this completionID, we also return a raw response PDU (because majorFunction is None).
            payload = stream.read()
            return DeviceIOResponsePDU(majorFunction, deviceID, completionID, ioStatus, payload)

    def writeDeviceIOResponse(self, pdu: DeviceIOResponsePDU, stream: BytesIO):
        Uint32LE.pack(pdu.deviceID, stream)
        Uint32LE.pack(pdu.completionID, stream)
        Uint32LE.pack(pdu.ioStatus, stream)

        if pdu.majorFunction in self.ioResponseWriters:
            self.ioResponseWriters[pdu.majorFunction](pdu, stream)
        else:
            stream.write(pdu.payload)


    def parseDeviceCreateRequest(self, deviceID: int, fileID: int, completionID: int, minorFunction: int, stream: BytesIO) -> DeviceCreateRequestPDU:
        desiredAccess = Uint32LE.unpack(stream)
        allocationSize = Uint64LE.unpack(stream)
        fileAttributes = FileAttributes(Uint32LE.unpack(stream))
        sharedAccess = FileShareAccess(Uint32LE.unpack(stream))
        createDisposition = FileCreateDisposition(Uint32LE.unpack(stream))
        createOptions = FileCreateOptions(Uint32LE.unpack(stream))
        pathLength = Uint32LE.unpack(stream)
        path = stream.read(pathLength)

        path = decodeUTF16LE(path)[: -1]

        return DeviceCreateRequestPDU(
            deviceID,
            fileID,
            completionID,
            minorFunction,
            desiredAccess,
            allocationSize,
            fileAttributes,
            sharedAccess,
            createDisposition,
            createOptions,
            path
        )

    def writeDeviceCreateRequest(self, pdu: DeviceCreateRequestPDU, stream: BytesIO):
        path = (pdu.path + "\x00").encode("utf-16le")

        Uint32LE.pack(pdu.desiredAccess, stream)
        Uint64LE.pack(pdu.allocationSize, stream)
        Uint32LE.pack(pdu.fileAttributes, stream)
        Uint32LE.pack(pdu.sharedAccess, stream)
        Uint32LE.pack(pdu.createDisposition, stream)
        Uint32LE.pack(pdu.createOptions, stream)
        Uint32LE.pack(len(path), stream)
        stream.write(path)


    def parseDeviceCreateResponse(self, deviceID: int, completionID: int, ioStatus: int, stream: BytesIO) -> DeviceCreateResponsePDU:
        """
        The information field is not yet parsed (it's optional).
        This one is a bit special since we need to look at previous packet before parsing it as
        a read response, and we need the packet data.
        """
        fileID = Uint32LE.unpack(stream)
        information = stream.read(1)

        if information == "":
            information = 0
        else:
            information = Uint8.unpack(information)

        return DeviceCreateResponsePDU(deviceID, completionID, ioStatus, fileID, information)

    def writeDeviceCreateResponse(self, pdu: DeviceCreateResponsePDU, stream: BytesIO):
        Uint32LE.pack(pdu.fileID, stream)
        Uint8.pack(pdu.information)



    def parseDeviceReadRequest(self, deviceID: int, fileID: int, completionID: int, minorFunction: int, stream: BytesIO) -> DeviceReadRequestPDU:
        length = Uint32LE.unpack(stream)
        offset = Uint64LE.unpack(stream)
        stream.read(20)  # Padding

        return DeviceReadRequestPDU(deviceID, fileID, completionID, minorFunction, length, offset)

    def writeDeviceReadRequest(self, pdu: DeviceReadRequestPDU, stream: BytesIO):
        Uint32LE.pack(pdu.length, stream)
        Uint64LE.pack(pdu.offset, stream)
        stream.write(b"\x00" * 20)  # Padding


    def parseDeviceReadResponse(self, deviceID: int, completionID: int, ioStatus: int, stream: BytesIO) -> DeviceReadResponsePDU:
        length = Uint32LE.unpack(stream)
        payload = stream.read(length)

        return DeviceReadResponsePDU(deviceID, completionID, ioStatus, payload)

    def writeDeviceReadResponse(self, pdu: DeviceReadResponsePDU, stream: BytesIO):
        Uint32LE.pack(len(pdu.payload), stream)
        stream.write(pdu.payload)


    def parseDeviceCloseRequest(self, deviceID: int, fileID: int, completionID: int, minorFunction: int, stream: BytesIO) -> DeviceCloseRequestPDU:
        stream.read(32)  # Padding
        return DeviceCloseRequestPDU(deviceID, fileID, completionID, minorFunction)

    def writeDeviceCloseRequest(self, _: DeviceCloseRequestPDU, stream: BytesIO):
        stream.write(b"\x00" * 32)  # Padding


    def parseDeviceCloseResponse(self, deviceID: int, completionID: int, ioStatus: int, stream: BytesIO) -> DeviceCloseResponsePDU:
        stream.read(4)  # Padding
        return DeviceCloseResponsePDU(deviceID, completionID, ioStatus)

    def writeDeviceCloseResponse(self, _: DeviceCloseResponsePDU, stream: BytesIO):
        stream.write(b"\x00" * 4)  # Padding


    def parseDirectoryControlRequest(self, deviceID: int, fileID: int, completionID: int, minorFunction: int, stream: BytesIO) -> DeviceIORequestPDU:
        self.minorFunctionsForParsingResponse[completionID] = MinorFunction(minorFunction)

        if minorFunction == MinorFunction.IRP_MN_NOTIFY_CHANGE_DIRECTORY:
            return DeviceIORequestPDU(deviceID, fileID, completionID, MajorFunction.IRP_MJ_DIRECTORY_CONTROL, minorFunction, stream.read())
        else:
            informationClass = FileSystemInformationClass(Uint32LE.unpack(stream))
            initialQuery = Uint8.unpack(stream)
            pathLength = Uint32LE.unpack(stream)
            stream.read(23)

            path = stream.read(pathLength)
            path = decodeUTF16LE(path)[: -1]

            self.informationClassForParsingResponse[completionID] = informationClass
            return DeviceQueryDirectoryRequestPDU(deviceID, fileID, completionID, informationClass, initialQuery, path)

    def writeDirectoryControlRequest(self, pdu: Union[DeviceIORequestPDU, DeviceQueryDirectoryRequestPDU], stream: BytesIO):
        self.minorFunctionsForParsingResponse[pdu.completionID] = pdu.minorFunction

        if pdu.minorFunction == MinorFunction.IRP_MN_NOTIFY_CHANGE_DIRECTORY:
            stream.write(pdu.payload)
        else:
            self.informationClassForParsingResponse[pdu.completionID] = pdu.informationClass
            path = (pdu.path + "\x00").encode("utf-16le")

            Uint32LE.pack(pdu.informationClass, stream)
            Uint8.pack(pdu.initialQuery, stream)
            Uint32LE.pack(len(path), stream)
            stream.write(b"\x00" * 23)
            stream.write(path)


    def parseDirectoryControlResponse(self, deviceID: int, completionID: int, ioStatus: int, stream: BytesIO) -> DeviceIOResponsePDU:
        minorFunction = self.minorFunctionsForParsingResponse.pop(completionID, None)

        if minorFunction is None:
            return DeviceIOResponsePDU(None, deviceID, completionID, ioStatus, stream.read())
        elif minorFunction == MinorFunction.IRP_MN_NOTIFY_CHANGE_DIRECTORY:
            return DeviceIOResponsePDU(None, deviceID, completionID, ioStatus, stream.read())

        informationClass = self.informationClassForParsingResponse.pop(completionID)

        length = Uint32LE.unpack(stream)
        responseData = stream.read(length)
        endByte = stream.read(1)

        fileInformation = self.fileInformationParsers[informationClass](responseData)

        return DeviceQueryDirectoryResponsePDU(deviceID, completionID, ioStatus, informationClass, fileInformation, endByte)

    def writeDirectoryControlResponse(self, pdu: Union[DeviceDirectoryControlResponsePDU, DeviceQueryDirectoryResponsePDU], stream: BytesIO):
        if not hasattr(pdu, "minorFunction") or pdu.minorFunction == MinorFunction.IRP_MN_NOTIFY_CHANGE_DIRECTORY:
            stream.write(pdu.payload)
            return

        substream = BytesIO()
        self.fileInformationWriters[pdu.informationClass](pdu.fileInformation, substream)

        Uint32LE.pack(len(substream.getvalue()), stream)
        stream.write(substream.getvalue())
        stream.write(pdu.endByte)


    def writeFileInformationList(self, dataList: List[bytes], stream: BytesIO):
        currentOffset = 0

        for index, data in enumerate(dataList):
            isLastObject = index == len(dataList) - 1

            length = len(data)
            lengthWithOffset = length + 4

            if not isLastObject and lengthWithOffset % 8 != 0:
                alignmentLength = 8 - lengthWithOffset % 8
            else:
                alignmentLength = 0

            totalLength = lengthWithOffset + alignmentLength
            nextOffset = currentOffset + totalLength
            currentOffset = nextOffset

            Uint32LE.pack(nextOffset if not isLastObject else 0, stream)
            stream.write(data)
            stream.write(b"\x00" * alignmentLength)


    def parseFileDirectoryInformation(self, data: bytes) -> List[FileDirectoryInformation]:
        stream = BytesIO(data)
        information: [FileDirectoryInformation] = []

        while stream.tell() < len(data):
            nextEntryOffset = Uint32LE.unpack(stream)
            fileIndex = Uint32LE.unpack(stream)
            creationTime = Uint64LE.unpack(stream)
            lastAccessTime = Uint64LE.unpack(stream)
            lastWriteTime = Uint64LE.unpack(stream)
            lastChangeTime = Uint64LE.unpack(stream)
            endOfFilePosition = Uint64LE.unpack(stream)
            allocationSize = Uint64LE.unpack(stream)
            fileAttributes = FileAttributes(Uint32LE.unpack(stream))
            fileNameLength = Uint32LE.unpack(stream)
            fileName = stream.read(fileNameLength)

            if nextEntryOffset == 0:
                break
            elif stream.tell() % 8 != 0:
                stream.read(8 - stream.tell() % 8) # alignment

            fileName = decodeUTF16LE(fileName)

            info = FileDirectoryInformation(
                fileIndex,
                creationTime,
                lastAccessTime,
                lastWriteTime,
                lastChangeTime,
                endOfFilePosition,
                allocationSize,
                fileAttributes,
                fileName
            )

            information.append(info)

        return information


    def writeFileDirectoryInformation(self, information: List[FileDirectoryInformation], stream: BytesIO):
        dataList: [bytes] = []

        for info in information:
            substream = BytesIO()
            fileName = info.fileName.encode("utf-16le")

            Uint32LE.pack(info.fileIndex, substream)
            Uint64LE.pack(info.creationTime, substream)
            Uint64LE.pack(info.lastAccessTime, substream)
            Uint64LE.pack(info.lastWriteTime, substream)
            Uint64LE.pack(info.lastChangeTime, substream)
            Uint64LE.pack(info.endOfFilePosition, substream)
            Uint64LE.pack(info.allocationSize, substream)
            Uint32LE.pack(info.fileAttributes, substream)
            Uint32LE.pack(len(fileName), substream)
            substream.write(fileName)

            dataList.append(substream.getvalue())

        self.writeFileInformationList(dataList, stream)


    def parseFileFullDirectoryInformation(self, data: bytes) -> List[FileFullDirectoryInformation]:
        stream = BytesIO(data)
        information: [FileFullDirectoryInformation] = []

        while stream.tell() < len(data):
            nextEntryOffset = Uint32LE.unpack(stream)
            fileIndex = Uint32LE.unpack(stream)
            creationTime = Uint64LE.unpack(stream)
            lastAccessTime = Uint64LE.unpack(stream)
            lastWriteTime = Uint64LE.unpack(stream)
            lastChangeTime = Uint64LE.unpack(stream)
            endOfFilePosition = Uint64LE.unpack(stream)
            allocationSize = Uint64LE.unpack(stream)
            fileAttributes = FileAttributes(Uint32LE.unpack(stream))
            fileNameLength = Uint32LE.unpack(stream)
            eaSize = Uint32LE.unpack(stream)
            fileName = stream.read(fileNameLength)

            if nextEntryOffset != 0:
                stream.read(8 - stream.tell() % 8) # alignment
                break

            fileName = decodeUTF16LE(fileName)

            info = FileFullDirectoryInformation(
                fileIndex,
                creationTime,
                lastAccessTime,
                lastWriteTime,
                lastChangeTime,
                endOfFilePosition,
                allocationSize,
                fileAttributes,
                eaSize,
                fileName
            )

            information.append(info)

        return information


    def writeFileFullDirectoryInformation(self, information: List[FileFullDirectoryInformation], stream: BytesIO):
        dataList: [bytes] = []

        for info in information:
            substream = BytesIO()
            fileName = info.fileName.encode("utf-16le")

            Uint32LE.pack(info.fileIndex, substream)
            Uint64LE.pack(info.creationTime, substream)
            Uint64LE.pack(info.lastAccessTime, substream)
            Uint64LE.pack(info.lastWriteTime, substream)
            Uint64LE.pack(info.lastChangeTime, substream)
            Uint64LE.pack(info.endOfFilePosition, substream)
            Uint64LE.pack(info.allocationSize, substream)
            Uint32LE.pack(info.fileAttributes, substream)
            Uint32LE.pack(len(fileName), substream)
            Uint32LE.pack(info.eaSize, substream)
            substream.write(fileName)

            dataList.append(substream.getvalue())

        self.writeFileInformationList(dataList, stream)


    def parseFileBothDirectoryInformation(self, data: bytes) -> List[FileBothDirectoryInformation]:
        stream = BytesIO(data)
        information: [FileBothDirectoryInformation] = []

        while stream.tell() < len(data):
            nextEntryOffset = Uint32LE.unpack(stream)
            fileIndex = Uint32LE.unpack(stream)
            creationTime = Uint64LE.unpack(stream)
            lastAccessTime = Uint64LE.unpack(stream)
            lastWriteTime = Uint64LE.unpack(stream)
            lastChangeTime = Uint64LE.unpack(stream)
            endOfFilePosition = Uint64LE.unpack(stream)
            allocationSize = Uint64LE.unpack(stream)
            fileAttributes = FileAttributes(Uint32LE.unpack(stream))
            fileNameLength = Uint32LE.unpack(stream)
            eaSize = Uint32LE.unpack(stream)
            shortNameLength = Uint8.unpack(stream)
            # stream.read(1) # reserved (not actually used, WTF Microsoft ????)
            shortName = stream.read(24)[: min(24, shortNameLength)]
            fileName = stream.read(fileNameLength)

            if nextEntryOffset != 0:
                stream.read(8 - stream.tell() % 8) # alignment
                break

            shortName = decodeUTF16LE(shortName)
            fileName = decodeUTF16LE(fileName)

            info = FileBothDirectoryInformation(
                fileIndex,
                creationTime,
                lastAccessTime,
                lastWriteTime,
                lastChangeTime,
                endOfFilePosition,
                allocationSize,
                fileAttributes,
                eaSize,
                shortName,
                fileName
            )

            information.append(info)

        return information


    def writeFileBothDirectoryInformation(self, information: List[FileBothDirectoryInformation], stream: BytesIO):
        dataList: [bytes] = []

        for info in information:
            substream = BytesIO()
            fileName = info.fileName.encode("utf-16le")
            shortName = info.shortName.encode("utf-16le")

            Uint32LE.pack(info.fileIndex, substream)
            Uint64LE.pack(info.creationTime, substream)
            Uint64LE.pack(info.lastAccessTime, substream)
            Uint64LE.pack(info.lastWriteTime, substream)
            Uint64LE.pack(info.lastChangeTime, substream)
            Uint64LE.pack(info.endOfFilePosition, substream)
            Uint64LE.pack(info.allocationSize, substream)
            Uint32LE.pack(info.fileAttributes, substream)
            Uint32LE.pack(len(fileName), substream)
            Uint32LE.pack(info.eaSize, substream)
            Uint8.pack(len(shortName), substream)
            # stream.write(b"\x00") # reserved
            substream.write(shortName.ljust(24, b"\x00")[: 24])
            substream.write(fileName)

            dataList.append(substream.getvalue())

        self.writeFileInformationList(dataList, stream)


    def parseFileNamesInformation(self, data: bytes) -> List[FileNamesInformation]:
        stream = BytesIO(data)
        information: [FileNamesInformation] = []

        while stream.tell() < len(data):
            nextEntryOffset = Uint32LE.unpack(stream)
            fileIndex = Uint32LE.unpack(stream)
            fileNameLength = Uint32LE.unpack(stream)
            fileName = stream.read(fileNameLength)

            if nextEntryOffset != 0:
                stream.read(8 - stream.tell() % 8) # alignment
                break

            fileName = decodeUTF16LE(fileName)

            info = FileNamesInformation(fileIndex, fileName)
            information.append(info)

        return information


    def writeFileNamesInformation(self, information: List[FileNamesInformation], stream: BytesIO):
        dataList: [bytes] = []

        for info in information:
            substream = BytesIO()
            fileName = info.fileName.encode("utf-16le")

            Uint32LE.pack(info.fileIndex, substream)
            Uint32LE.pack(len(fileName), substream)
            substream.write(fileName)

            dataList.append(substream.getvalue())

        self.writeFileInformationList(dataList, stream)


    def convertWindowsTimeStamp(self, timeStamp: int) -> int:
        """
        Convert Windows time (in 100-ns) to Unix time (in ms).
        :param timeStamp: the Windows time stamp in 100-ns.
        """
        # Difference between Unix time epoch and Windows time epoch
        offset = 116444736000000000 # in 100-ns
        result = timeStamp - offset # in 100-ns
        return result // 10 # in ms