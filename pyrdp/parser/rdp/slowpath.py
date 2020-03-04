#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO
from typing import List

from pyrdp.core import Uint16LE, Uint32LE, Uint8
from pyrdp.enum import CapabilityType, ErrorInfo, SlowPathDataType, SlowPathPDUType
from pyrdp.parser.parser import Parser
from pyrdp.parser.rdp.input import SlowPathInputParser
from pyrdp.parser.rdp.pointer import PointerEventParser
from pyrdp.pdu import BitmapCapability, Capability, ConfirmActivePDU, ControlPDU, DemandActivePDU, GeneralCapability, \
    GlyphCacheCapability, InputPDU, MultifragmentUpdateCapability, OffscreenBitmapCacheCapability, OrderCapability, PDU, \
    PlaySoundPDU, PointerCapability, PointerPDU, SetErrorInfoPDU, ShareControlHeader, ShareDataHeader, SlowPathPDU, \
    SlowPathUnparsedPDU, SuppressOutputPDU, SynchronizePDU, UpdatePDU, VirtualChannelCapability, PersistentCacheKeysPDU
from pyrdp.pdu.rdp.capability import SurfaceCommandsCapability


class SlowPathParser(Parser):
    def __init__(self):
        super().__init__()
        self.parsers = {
            SlowPathPDUType.DEMAND_ACTIVE_PDU: self.parseDemandActive,
            SlowPathPDUType.CONFIRM_ACTIVE_PDU: self.parseConfirmActive,
            SlowPathPDUType.DATA_PDU: self.parseData,
        }

        self.dataParsers = {
            SlowPathDataType.PDUTYPE2_SET_ERROR_INFO_PDU: self.parseError,
            SlowPathDataType.PDUTYPE2_SYNCHRONIZE: self.parseSynchronize,
            SlowPathDataType.PDUTYPE2_CONTROL: self.parseControl,
            SlowPathDataType.PDUTYPE2_INPUT: self.parseInput,
            # RDPDataPDUSubtype.PDUTYPE2_POINTER: self.parsePointer,
            SlowPathDataType.PDUTYPE2_PLAY_SOUND: self.parsePlaySound,
            SlowPathDataType.PDUTYPE2_SUPPRESS_OUTPUT: self.parseSuppressOutput,
            SlowPathDataType.PDUTYPE2_UPDATE: self.parseUpdate,
            SlowPathDataType.PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST: self.parsePersistentCacheKeys,
        }

        self.dataWriters = {
            SlowPathDataType.PDUTYPE2_SET_ERROR_INFO_PDU: self.writeError,
            SlowPathDataType.PDUTYPE2_SYNCHRONIZE: self.writeSynchronize,
            SlowPathDataType.PDUTYPE2_CONTROL: self.writeControl,
            SlowPathDataType.PDUTYPE2_INPUT: self.writeInput,
            # RDPDataPDUSubtype.PDUTYPE2_POINTER: self.writePointer,
            SlowPathDataType.PDUTYPE2_PLAY_SOUND: self.writePlaySound,
            SlowPathDataType.PDUTYPE2_SUPPRESS_OUTPUT: self.writeSuppressOutput,
            SlowPathDataType.PDUTYPE2_UPDATE: self.writeUpdate,
            SlowPathDataType.PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST: self.writePersistentCacheKeys,
        }

    def parse(self, data: bytes) -> PDU:
        """
        Decode a data PDU from bytes.
        :return: an instance of an RDP Data PDU class.
        """
        stream = BytesIO(data)
        header = self.parseShareControlHeader(stream)

        if header.pduType not in self.parsers:
            return SlowPathUnparsedPDU(header, stream.read())

        return self.parsers[header.pduType](stream, header)

    def parseData(self, stream: BytesIO, header):
        header = self.parseShareDataHeader(stream, header)

        if header.subtype not in self.dataParsers:
            return SlowPathUnparsedPDU(header, stream.read())

        return self.dataParsers[header.subtype](stream, header)

    def write(self, pdu: SlowPathPDU) -> bytes:
        """
        Encode an RDP Data PDU instance to bytes.
        """
        stream = BytesIO()
        substream = BytesIO()

        if isinstance(pdu, DemandActivePDU):
            headerWriter = self.writeShareControlHeader
            self.writeDemandActive(substream, pdu)
        elif isinstance(pdu, ConfirmActivePDU):
            headerWriter = self.writeShareControlHeader
            self.writeConfirmActive(substream, pdu)
        elif pdu.header.pduType == SlowPathPDUType.DATA_PDU:
            headerWriter = self.writeShareDataHeader
            self.writeData(substream, pdu)
        else:
            headerWriter = self.writeShareControlHeader
            substream.write(pdu.payload)

        substream = substream.getvalue()
        headerWriter(stream, pdu.header, len(substream))
        stream.write(substream)
        return stream.getvalue()

    def writeData(self, stream: BytesIO, pdu):
        if pdu.header.subtype not in self.dataWriters:
            stream.write(pdu.payload)
        else:
            self.dataWriters[pdu.header.subtype](stream, pdu)

    def parseShareControlHeader(self, stream: BytesIO):
        length = Uint16LE.unpack(stream)
        pduType = Uint16LE.unpack(stream)
        source = Uint16LE.unpack(stream)
        return ShareControlHeader(SlowPathPDUType(pduType & 0xf), (pduType >> 4), source)

    def writeShareControlHeader(self, stream: BytesIO, header: ShareControlHeader, dataLength: int):
        pduType = (header.pduType.value & 0xf) | (header.version << 4)
        stream.write(Uint16LE.pack(dataLength + 6))
        stream.write(Uint16LE.pack(pduType))
        stream.write(Uint16LE.pack(header.source))

    def parseShareDataHeader(self, stream: BytesIO, controlHeader: ShareControlHeader):
        shareID = Uint32LE.unpack(stream)
        stream.read(1)
        streamID = Uint8.unpack(stream)
        uncompressedLength = Uint16LE.unpack(stream)
        pduSubtype = Uint8.unpack(stream)
        compressedType = Uint8.unpack(stream)
        compressedLength = Uint16LE.unpack(stream)
        return ShareDataHeader(controlHeader.pduType, controlHeader.version, controlHeader.source, shareID, streamID, uncompressedLength, SlowPathDataType(pduSubtype), compressedType, compressedLength)

    def writeShareDataHeader(self, stream: BytesIO, header, dataLength):
        substream = BytesIO()
        substream.write(Uint32LE.pack(header.shareID))
        substream.write(b"\x00")
        substream.write(Uint8.pack(header.streamID))
        substream.write(Uint16LE.pack(header.uncompressedLength))
        substream.write(Uint8.pack(header.subtype))
        substream.write(Uint8.pack(header.compressedType))
        substream.write(Uint16LE.pack(header.compressedLength))
        substream = substream.getvalue()

        self.writeShareControlHeader(stream, header, dataLength + len(substream))
        stream.write(substream)

    def parseDemandActive(self, stream: BytesIO, header):
        shareID = Uint32LE.unpack(stream)
        lengthSourceDescriptor = Uint16LE.unpack(stream)
        lengthCombinedCapabilities = Uint16LE.unpack(stream)
        sourceDescriptor = stream.read(lengthSourceDescriptor)
        numberCapabilities = Uint16LE.unpack(stream)
        pad2Octets = stream.read(2)
        capabilitySets = stream.read(lengthCombinedCapabilities - 4)
        sessionID = Uint32LE.unpack(stream)
        parsedCapabilitySets = self.parseCapabilitySets(capabilitySets, numberCapabilities)

        return DemandActivePDU(header, shareID, sourceDescriptor, numberCapabilities, capabilitySets, sessionID, parsedCapabilitySets)

    def writeDemandActive(self, stream: BytesIO, pdu: DemandActivePDU):
        Uint32LE.pack(pdu.shareID, stream)
        Uint16LE.pack(len(pdu.sourceDescriptor), stream)

        substream = BytesIO()
        self.writeCapabilitySets(pdu.parsedCapabilitySets.values(), substream)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)  # lengthCombinedCapabilities

        stream.write(pdu.sourceDescriptor)  # sourceDescriptor
        Uint16LE.pack(len(pdu.parsedCapabilitySets.keys()), stream)  # numberCapabilities
        stream.write(b"\x00" * 2)  # pad2Octets
        stream.write(substream.getvalue())  # capabilitySets
        Uint32LE.pack(pdu.sessionID, stream)

    def parseConfirmActive(self, stream: BytesIO, header):
        shareID = Uint32LE.unpack(stream)
        originatorID = Uint16LE.unpack(stream)
        lengthSourceDescriptor = Uint16LE.unpack(stream)
        lengthCombinedCapabilities = Uint16LE.unpack(stream)
        sourceDescriptor = stream.read(lengthSourceDescriptor)
        numberCapabilities = Uint16LE.unpack(stream)
        stream.read(2)
        capabilitySetsRaw = stream.read(lengthCombinedCapabilities - 4)
        capabilitySets = self.parseCapabilitySets(capabilitySetsRaw, numberCapabilities)

        return ConfirmActivePDU(header, shareID, originatorID, sourceDescriptor,
                                numberCapabilities, capabilitySets, capabilitySetsRaw)

    def parseCapabilitySets(self, capabilitySetsRaw, numberCapabilities):
        stream = BytesIO(capabilitySetsRaw)
        capabilitySets = {}
        # Do minimum parsing for every capability
        for i in range(numberCapabilities):
            capabilitySetType = Uint16LE.unpack(stream.read(2))
            lengthCapability = Uint16LE.unpack(stream.read(2))
            capabilityData = stream.read(lengthCapability - 4)
            capability = Capability(capabilitySetType, capabilityData)
            capabilitySets[CapabilityType(capabilitySetType)] = capability

        # Fully parse the General capability set
        capabilitySets[CapabilityType.CAPSTYPE_GENERAL] = \
            self.parseGeneralCapability(capabilitySets[CapabilityType.CAPSTYPE_GENERAL].rawData)

        # Fully parse the Glyph cache capability set
        if CapabilityType.CAPSTYPE_GLYPHCACHE in capabilitySets:
            capabilitySets[CapabilityType.CAPSTYPE_GLYPHCACHE] = \
                self.parseGlyphCacheCapability(capabilitySets[CapabilityType.CAPSTYPE_GLYPHCACHE].rawData)

        # If present, fully parse the offscreen cache capability set
        if CapabilityType.CAPSTYPE_OFFSCREENCACHE in capabilitySets:
            capabilitySets[CapabilityType.CAPSTYPE_OFFSCREENCACHE] = \
                self.parseOffscreenCacheCapability(capabilitySets[CapabilityType.CAPSTYPE_OFFSCREENCACHE].rawData)

        # If present, fully parse the surface commands cache capability set
        if CapabilityType.CAPSETTYPE_SURFACE_COMMANDS in capabilitySets:
            capabilitySets[CapabilityType.CAPSETTYPE_SURFACE_COMMANDS] = \
                self.parseSurfaceCommandsCapability(capabilitySets[CapabilityType.CAPSETTYPE_SURFACE_COMMANDS].rawData)

        # Fully parse the Bitmap capability set
        capabilitySets[CapabilityType.CAPSTYPE_BITMAP] = \
            self.parseBitmapCapability(capabilitySets[CapabilityType.CAPSTYPE_BITMAP].rawData)

        # Fully parse the Order capability set
        capabilitySets[CapabilityType.CAPSTYPE_ORDER] = self.parseOrderCapability(
            capabilitySets[CapabilityType.CAPSTYPE_ORDER].rawData)

        # Fully parse the VirtualChannel capability set
        if CapabilityType.CAPSTYPE_VIRTUALCHANNEL in capabilitySets:
            capabilitySets[CapabilityType.CAPSTYPE_VIRTUALCHANNEL] = self.parseVirtualChannelCapability(
                capabilitySets[CapabilityType.CAPSTYPE_VIRTUALCHANNEL].rawData)

        # Fully parse the Pointer capability set
        if CapabilityType.CAPSTYPE_POINTER in capabilitySets:
            capabilitySets[CapabilityType.CAPSTYPE_POINTER] = self.parsePointerCapability(
                capabilitySets[CapabilityType.CAPSTYPE_POINTER].rawData)

        return capabilitySets

    def parseGeneralCapability(self, data) -> GeneralCapability:
        """
        https://msdn.microsoft.com/en-us/library/cc240549.aspx
        :param data: Raw data starting after lengthCapability
        """
        stream = BytesIO(data)
        osMajorType = Uint16LE.unpack(stream.read(2))
        osMinorType = Uint16LE.unpack(stream.read(2))
        protocolVersion = Uint16LE.unpack(stream.read(2))
        stream.read(2)  # pad2octetsA
        generalCompressionTypes = Uint16LE.unpack(stream.read(2))
        extraFlags = Uint16LE.unpack(stream.read(2))
        updateCapabilityFlag = Uint8.unpack(stream.read(1))
        remoteUnshareFlag = Uint8.unpack(stream.read(1))
        generalCompressionLevel = Uint16LE.unpack(stream.read(2))
        refreshRectSupport = Uint8.unpack(stream.read(1))
        suppressOutputSupport = Uint8.unpack(stream.read(1))

        capability = GeneralCapability(osMajorType, osMinorType, protocolVersion, generalCompressionTypes, extraFlags,
                                       updateCapabilityFlag, remoteUnshareFlag, generalCompressionLevel,
                                       refreshRectSupport, suppressOutputSupport)
        capability.rawData = data
        return capability

    def parseSurfaceCommandsCapability(self, data: bytes) -> SurfaceCommandsCapability:
        """
        https://msdn.microsoft.com/en-us/library/dd871563.aspx
        :param data: Raw data starting after lengthCapability
        """
        stream = BytesIO(data)
        cmdFlags = Uint32LE.unpack(stream)
        reserved = Uint32LE.unpack(stream)
        capability = SurfaceCommandsCapability(cmdFlags, reserved)
        capability.rawData = data
        return capability

    def writeSurfaceCommandsCapability(self, capability: SurfaceCommandsCapability, stream: BytesIO):
        substream = BytesIO()
        Uint16LE.pack(capability.capabilityType, stream)

        Uint32LE.pack(capability.cmdFlags, substream)
        Uint32LE.pack(capability.reserved, substream)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())

    def parseOffscreenCacheCapability(self, data) -> OffscreenBitmapCacheCapability:
        """
        https://msdn.microsoft.com/en-us/library/cc240550.aspx
        :param data: Raw data starting after lengthCapability
        """
        stream = BytesIO(data)
        offscreenSupportLevel = Uint32LE.unpack(stream.read(4))
        offscreenCacheSize = Uint16LE.unpack(stream.read(2))
        offscreenCacheEntries = Uint16LE.unpack(stream.read(2))

        capability = OffscreenBitmapCacheCapability(offscreenSupportLevel, offscreenCacheSize, offscreenCacheEntries)
        capability.rawData = data
        return capability

    def parseGlyphCacheCapability(self, data) -> GlyphCacheCapability:
        """
        https://msdn.microsoft.com/en-us/library/cc240565.aspx
        :param data: Raw data starting after lengthCapability
        """
        stream = BytesIO(data)
        glyphCache = stream.read(40)
        fragCache = Uint32LE.unpack(stream.read(4))
        glyphSupportLevel = Uint16LE.unpack(stream.read(2))
        stream.read(2)  # pad2octets

        capability = GlyphCacheCapability(glyphCache, fragCache, glyphSupportLevel)
        capability.rawData = data
        return capability

    def parseBitmapCapability(self, data: bytes) -> BitmapCapability:
        """
        https://msdn.microsoft.com/en-us/library/cc240554.aspx
        :param data: Raw data starting after lengthCapability
        """
        stream = BytesIO(data)
        preferredBitsPerPixel = Uint16LE.unpack(stream.read(2))
        receive1bitPerPixel = Uint16LE.unpack(stream.read(2))
        receive4bitPerPixel = Uint16LE.unpack(stream.read(2))
        receive8bitPerPixel = Uint16LE.unpack(stream.read(2))
        desktopWidth = Uint16LE.unpack(stream.read(2))
        desktopHeight = Uint16LE.unpack(stream.read(2))
        stream.read(2)  # pad2octets
        desktopResizeFlag = Uint16LE.unpack(stream.read(2))
        bitmapCompressionFlag = Uint16LE.unpack(stream.read(2))
        highColorFlags = Uint8.unpack(stream.read(1))
        drawingFlags = Uint8.unpack(stream.read(1))
        multipleRectangleSupport = Uint16LE.unpack(stream.read(2))
        # ignoring pad2octetsB

        capability = BitmapCapability(preferredBitsPerPixel, receive1bitPerPixel, receive4bitPerPixel,
                                      receive8bitPerPixel, desktopWidth, desktopHeight, desktopResizeFlag,
                                      bitmapCompressionFlag, highColorFlags, drawingFlags, multipleRectangleSupport)
        capability.rawData = data
        return capability

    def parseOrderCapability(self, data) -> OrderCapability:
        """
        https://msdn.microsoft.com/en-us/library/cc240556.aspx
        :param data: Raw data starting after lengthCapability
        """
        stream = BytesIO(data)
        terminalDescriptor = stream.read(16)
        stream.read(4)  # pad4octetsA
        desktopSaveXGranularity = Uint16LE.unpack(stream.read(2))
        desktopSaveYGranularity = Uint16LE.unpack(stream.read(2))
        stream.read(2)  # pad2octetsA
        maximumOrderLevel = Uint16LE.unpack(stream.read(2))
        numberFonts = Uint16LE.unpack(stream.read(2))
        orderFlags = Uint16LE.unpack(stream.read(2))
        orderSupport = stream.read(32)
        textFlags = Uint16LE.unpack(stream.read(2))
        orderSupportExFlags = Uint16LE.unpack(stream.read(2))
        stream.read(4)  # pad4octetsB
        desktopSaveSize = Uint32LE.unpack(stream.read(4))
        stream.read(4)  # pad2octetsC, pad2octetsD
        textANSICodePage = Uint16LE.unpack(stream.read(2))
        # ignoring pad2octetsE

        capability = OrderCapability(terminalDescriptor, desktopSaveXGranularity, desktopSaveYGranularity,
                                     maximumOrderLevel, numberFonts, orderFlags, orderSupport, textFlags,
                                     orderSupportExFlags, desktopSaveSize, textANSICodePage)
        capability.rawData = data
        return capability

    def writeConfirmActive(self, stream: BytesIO, pdu: ConfirmActivePDU):
        Uint32LE.pack(pdu.shareID, stream)
        Uint16LE.pack(pdu.originatorID, stream)
        Uint16LE.pack(len(pdu.sourceDescriptor), stream)

        substream = BytesIO()
        self.writeCapabilitySets(pdu.parsedCapabilitySets.values(), substream)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(pdu.sourceDescriptor)
        Uint16LE.pack(len(pdu.parsedCapabilitySets), stream)
        stream.write(b"\x00" * 2)  # pad2octets
        stream.write(substream.getvalue())

    def writeCapabilitySets(self, capabilitySets: List[Capability], substream):
        for capability in capabilitySets:
            # Since the general capability is fully parsed, write it back.....
            if isinstance(capability, GeneralCapability):
                self.writeGeneralCapability(capability, substream)
            elif isinstance(capability, OrderCapability):
                self.writeOrderCapability(capability, substream)
            elif isinstance(capability, BitmapCapability):
                self.writeBitmapCapability(capability, substream)
            elif isinstance(capability, SurfaceCommandsCapability):
                self.writeSurfaceCommandsCapability(capability, substream)
            elif isinstance(capability, OffscreenBitmapCacheCapability):
                self.writeOffscreenCacheCapability(capability, substream)
            elif isinstance(capability, VirtualChannelCapability):
                self.writeVirtualChannelCapability(capability, substream)
            elif isinstance(capability, PointerCapability):
                self.writePointerCapability(capability, substream)
            elif capability.capabilityType == CapabilityType.CAPSETTYPE_MULTIFRAGMENTUPDATE \
                    and isinstance(capability, MultifragmentUpdateCapability):
                self.writeMultiFragmentUpdateCapability(capability, substream)
            # Every other capability is parsed minimally.
            else:
                Uint16LE.pack(capability.capabilityType, substream)
                Uint16LE.pack(len(capability.rawData) + 4, substream)
                substream.write(capability.rawData)

    def parseError(self, stream: BytesIO, header):
        errorInfo = Uint32LE.unpack(stream)
        return SetErrorInfoPDU(header, ErrorInfo(errorInfo))

    def writeError(self, stream: BytesIO, pdu):
        Uint32LE.pack(pdu.errorInfo, stream)

    def parseSynchronize(self, stream: BytesIO, header):
        messageType = Uint16LE.unpack(stream)
        targetUser = Uint16LE.unpack(stream)
        return SynchronizePDU(header, messageType, targetUser)

    def writeSynchronize(self, stream: BytesIO, pdu):
        Uint16LE.pack(pdu.messageType, stream)
        Uint16LE.pack(pdu.targetUser, stream)

    def parseControl(self, stream: BytesIO, header):
        action = Uint16LE.unpack(stream)
        grantID = Uint16LE.unpack(stream)
        controlID = Uint32LE.unpack(stream)
        return ControlPDU(header, action, grantID, controlID)

    def writeControl(self, stream: BytesIO, pdu):
        Uint16LE.pack(pdu.action, stream)
        Uint16LE.pack(pdu.grantID, stream)
        Uint32LE.pack(pdu.grantID, stream)

    def parseInput(self, stream: BytesIO, header):
        numEvents = Uint16LE.unpack(stream)
        stream.read(2)

        parser = SlowPathInputParser()
        inputEvents = [parser.parse(stream) for _ in range(numEvents)]

        return InputPDU(header, inputEvents)

    def writeInput(self, stream: BytesIO, pdu):
        Uint16LE.pack(len(pdu.events), stream)
        stream.write(b"\x00" * 2)

        parser = SlowPathInputParser()
        for event in pdu.events:
            stream.write(parser.write(event))

    def parsePointer(self, stream: BytesIO, header):
        parser = PointerEventParser()
        event = parser.parse(stream)
        return PointerPDU(header, event)

    def writePointer(self, stream: BytesIO, pdu):
        parser = PointerEventParser()
        stream.write(parser.write(pdu.event))

    def parsePlaySound(self, stream: BytesIO, header):
        duration = Uint32LE.unpack(stream)
        frequency = Uint32LE.unpack(stream)
        return PlaySoundPDU(header, duration, frequency)

    def writePlaySound(self, stream: BytesIO, pdu):
        Uint32LE.pack(pdu.duration, stream)
        Uint32LE.pack(pdu.frequency, stream)

    def parseSuppressOutput(self, stream: BytesIO, header):
        allowDisplayUpdates = Uint8.unpack(stream)
        stream.read(3)

        if allowDisplayUpdates == 1:
            left = Uint16LE.unpack(stream)
            top = Uint16LE.unpack(stream)
            right = Uint16LE.unpack(stream)
            bottom = Uint16LE.unpack(stream)
            return SuppressOutputPDU(header, allowDisplayUpdates, left, top, right, bottom)
        else:
            return SuppressOutputPDU(header, allowDisplayUpdates, None, None, None, None)

    def writeSuppressOutput(self, stream: BytesIO, pdu):
        Uint8.pack(int(pdu.allowDisplayUpdates), stream)
        stream.write(b"\x00" * 3)

        if pdu.allowDisplayUpdates:
            Uint16LE.pack(pdu.left, stream)
            Uint16LE.pack(pdu.top, stream)
            Uint16LE.pack(pdu.right, stream)
            Uint16LE.pack(pdu.bottom, stream)

    def parseUpdate(self, stream: BytesIO, header):
        updateType = Uint16LE.unpack(stream)
        updateData = stream.read(header.uncompressedLength - 18)
        return UpdatePDU(header, updateType, updateData)

    def writeUpdate(self, stream: BytesIO, pdu: UpdatePDU):
        Uint16LE.pack(pdu.updateType, stream)
        stream.write(pdu.updateData)

    def writeGeneralCapability(self, capability: GeneralCapability, stream: BytesIO):
        """
        https://msdn.microsoft.com/en-us/library/cc240549.aspx
        """
        substream = BytesIO()
        Uint16LE.pack(capability.capabilityType, stream)
        Uint16LE.pack(capability.majorType, substream)
        Uint16LE.pack(capability.minorType, substream)
        Uint16LE.pack(capability.protocolVersion, substream)
        substream.write(b"\00" * 2)  # pad2octetsA
        Uint16LE.pack(capability.generalCompressionTypes, substream)
        Uint16LE.pack(capability.extraFlags, substream)
        Uint16LE.pack(capability.updateCapabilityFlag, substream)
        Uint16LE.pack(capability.remoteUnshareFlag, substream)
        Uint16LE.pack(capability.generalCompressionLevel, substream)
        Uint8.pack(capability.refreshRectSupport, substream)
        Uint8.pack(capability.suppressOutputSupport, substream)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())

    def writeOrderCapability(self, capability: OrderCapability, stream: BytesIO):
        substream = BytesIO()
        Uint16LE.pack(capability.capabilityType, stream)
        substream.write(capability.terminalDescriptor)
        substream.write(b"\x00"*4)
        Uint16LE.pack(capability.desktopSaveXGranularity, substream)
        Uint16LE.pack(capability.desktopSaveYGranularity, substream)
        substream.write(b"\x00" * 2)
        Uint16LE.pack(capability.maximumOrderLevel, substream)
        Uint16LE.pack(capability.numberFonts, substream)
        Uint16LE.pack(capability.orderFlags, substream)
        substream.write(capability.orderSupport)
        Uint16LE.pack(capability.textFlags, substream)
        Uint16LE.pack(capability.orderSupportExFlags, substream)
        substream.write(b"\x00" * 4)
        Uint32LE.pack(capability.desktopSaveSize, substream)
        substream.write(b"\x00" * 4)
        Uint16LE.pack(capability.textANSICodePage, substream)
        substream.write(b"\x00" * 2)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())

    def writeBitmapCapability(self, capability: BitmapCapability, stream: BytesIO):
        substream = BytesIO()
        Uint16LE.pack(capability.capabilityType, stream)

        Uint16LE.pack(capability.preferredBitsPerPixel, substream)
        Uint16LE.pack(capability.receive1BitPerPixel, substream)
        Uint16LE.pack(capability.receive4BitsPerPixel, substream)
        Uint16LE.pack(capability.receive8BitsPerPixel, substream)
        Uint16LE.pack(capability.desktopWidth, substream)
        Uint16LE.pack(capability.desktopHeight, substream)
        substream.write(b"\x00"*2)  # pad2octets
        Uint16LE.pack(capability.desktopResizeFlag, substream)
        Uint16LE.pack(capability.bitmapCompressionFlag, substream)
        Uint8.pack(capability.highColorFlags, substream)
        Uint8.pack(capability.drawingFlags, substream)
        Uint16LE.pack(capability.multipleRectangleSupport, substream)

        substream.write(b"\x00" * 2)  # pad2octetsB

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())

    def writeOffscreenCacheCapability(self, capability: OffscreenBitmapCacheCapability, stream: BytesIO):
        substream = BytesIO()
        Uint16LE.pack(capability.capabilityType, stream)

        Uint32LE.pack(capability.offscreenSupportLevel, substream)
        Uint16LE.pack(capability.offscreenCacheSize, substream)
        Uint16LE.pack(capability.offscreenCacheEntries, substream)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())

    def writeMultiFragmentUpdateCapability(self, capability: MultifragmentUpdateCapability, stream: BytesIO):
        substream = BytesIO()
        Uint16LE.pack(capability.capabilityType, stream)

        Uint32LE.pack(capability.maxRequestSize, substream)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())

    def parseVirtualChannelCapability(self, data: bytes) -> VirtualChannelCapability:
        """
        https://msdn.microsoft.com/en-us/library/cc240551.aspx
        :param data: Raw data starting after lengthCapability
        """
        stream = BytesIO(data)
        flags = Uint32LE.unpack(stream)
        VCChunkSize = Uint32LE.unpack(stream) if stream.tell() != len(stream.getvalue()) else None

        return VirtualChannelCapability(flags, VCChunkSize)

    def writeVirtualChannelCapability(self, capability: VirtualChannelCapability, stream: BytesIO):
        substream = BytesIO()
        Uint16LE.pack(capability.capabilityType, stream)

        Uint32LE.pack(capability.flags, substream)

        if capability.vcChunkSize is not None:
            Uint32LE.pack(capability.vcChunkSize, substream)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())

    def parsePointerCapability(self, data: bytes) -> PointerCapability:
        """
        https://msdn.microsoft.com/en-us/library/cc240562.aspx
        :param data: Raw data starting after lengthCapability
        """
        stream = BytesIO(data)
        colorPointerFlag = Uint16LE.unpack(stream)
        colorPointerCacheSize = Uint16LE.unpack(stream)
        pointerCacheSize = Uint16LE.unpack(stream)

        return PointerCapability(colorPointerFlag, colorPointerCacheSize, pointerCacheSize)

    def writePointerCapability(self, capability: PointerCapability, stream: BytesIO):
        substream = BytesIO()
        Uint16LE.pack(capability.capabilityType, stream)

        Uint16LE.pack(capability.colorPointerFlag, substream)
        Uint16LE.pack(capability.colorPointerCacheSize, substream)
        Uint16LE.pack(capability.pointerCacheSize, substream)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())

    def parsePersistentCacheKeys(self, stream: BytesIO, header):
        num0 = Uint16LE.unpack(stream)
        num1 = Uint16LE.unpack(stream)
        num2 = Uint16LE.unpack(stream)
        num3 = Uint16LE.unpack(stream)
        num4 = Uint16LE.unpack(stream)

        total0 = Uint16LE.unpack(stream)
        total1 = Uint16LE.unpack(stream)
        total2 = Uint16LE.unpack(stream)
        total3 = Uint16LE.unpack(stream)
        total4 = Uint16LE.unpack(stream)
        bBitMask = Uint8.unpack(stream)

        stream.read(3)  # Padding

        keys = stream.read(64 * (num0 + num1 + num2 + num3 + num4))
        return PersistentCacheKeysPDU(header, num0, num1, num2, num3, num4,
                                      total0, total1, total2, total3, total4, keys, bBitMask)

    def writePersistentCacheKeys(self, s: BytesIO, pdu: PersistentCacheKeysPDU):
        # Only send the first PDU with an empty list and drop the rest.
        # TODO: Find a way to cleanly drop the entire packet instead.
        Uint16LE.pack(0, s)
        Uint16LE.pack(0, s)
        Uint16LE.pack(0, s)
        Uint16LE.pack(0, s)
        Uint16LE.pack(0, s)

        Uint16LE.pack(0, s)
        Uint16LE.pack(0, s)
        Uint16LE.pack(0, s)
        Uint16LE.pack(0, s)
        Uint16LE.pack(0, s)
        Uint8.pack(pdu.mask, s)
        s.write(b'\x00'*3)
