from StringIO import StringIO

from rdpy.core.packing import Uint16LE, Uint32LE, Uint8
from rdpy.enum.rdp import RDPDataPDUType, RDPDataPDUSubtype, ErrorInfo, CapabilityType
from rdpy.exceptions import UnknownPDUTypeError
from rdpy.parser.rdp.input import RDPInputParser
from rdpy.parser.rdp.pointer import PointerEventParser
from rdpy.pdu.rdp.capability import Capability, BitmapCapability, OrderCapability, GeneralCapability
from rdpy.pdu.rdp.data import RDPShareControlHeader, RDPShareDataHeader, RDPDemandActivePDU, RDPConfirmActivePDU, \
    RDPSetErrorInfoPDU, RDPSynchronizePDU, RDPControlPDU, RDPInputPDU, RDPPlaySoundPDU, RDPPointerPDU


class RDPDataParser:
    def __init__(self):
        self.parsers = {
            RDPDataPDUType.DEMAND_ACTIVE_PDU: self.parseDemandActive,
            RDPDataPDUType.CONFIRM_ACTIVE_PDU: self.parseConfirmActive,
            RDPDataPDUType.DATA_PDU: self.parseData,
        }

        self.dataParsers = {
            RDPDataPDUSubtype.PDUTYPE2_SET_ERROR_INFO_PDU: self.parseError,
            RDPDataPDUSubtype.PDUTYPE2_SYNCHRONIZE: self.parseSynchronize,
            RDPDataPDUSubtype.PDUTYPE2_CONTROL: self.parseControl,
            RDPDataPDUSubtype.PDUTYPE2_INPUT: self.parseInput,
            # RDPDataPDUSubtype.PDUTYPE2_POINTER: self.parsePointer,
            RDPDataPDUSubtype.PDUTYPE2_PLAY_SOUND: self.parsePlaySound,
        }

        self.dataWriters = {
            RDPDataPDUSubtype.PDUTYPE2_SET_ERROR_INFO_PDU: self.writeError,
            RDPDataPDUSubtype.PDUTYPE2_SYNCHRONIZE: self.writeSynchronize,
            RDPDataPDUSubtype.PDUTYPE2_CONTROL: self.writeControl,
            RDPDataPDUSubtype.PDUTYPE2_INPUT: self.writeInput,
            # RDPDataPDUSubtype.PDUTYPE2_POINTER: self.writePointer,
            RDPDataPDUSubtype.PDUTYPE2_PLAY_SOUND: self.writePlaySound,
        }

    def parse(self, data):
        stream = StringIO(data)
        header = self.parseShareControlHeader(stream)

        if header.type not in self.parsers:
            raise UnknownPDUTypeError("Trying to parse unknown Data PDU type: %s" % header.type, header.type)

        return self.parsers[header.type](stream, header)

    def parseData(self, stream, header):
        header = self.parseShareDataHeader(stream, header)

        if header.subtype not in self.dataParsers:
            raise UnknownPDUTypeError("Trying to parse unknown Data PDU Subtype: %s" % header.subtype, header.subtype)

        return self.dataParsers[header.subtype](stream, header)

    def write(self, pdu):
        stream = StringIO()
        substream = StringIO()

        if pdu.header.type == RDPDataPDUType.DEMAND_ACTIVE_PDU:
            headerWriter = self.writeShareControlHeader
            self.writeDemandActive(substream, pdu)
        elif pdu.header.type == RDPDataPDUType.CONFIRM_ACTIVE_PDU:
            headerWriter = self.writeShareControlHeader
            self.writeConfirmActive(substream, pdu)
        elif pdu.header.type == RDPDataPDUType.DATA_PDU:
            headerWriter = self.writeShareDataHeader
            self.writeData(substream, pdu)

        substream = substream.getvalue()
        headerWriter(stream, pdu.header, len(substream))
        stream.write(substream)
        return stream.getvalue()

    def writeData(self, stream, pdu):
        if pdu.header.subtype not in self.dataWriters:
            raise UnknownPDUTypeError("Trying to write unknown Data PDU Subtype: %s" % pdu.header.subtype, pdu.header.subtype)

        self.dataWriters[pdu.header.subtype](stream, pdu)

    def parseShareControlHeader(self, stream):
        length = Uint16LE.unpack(stream)
        pduType = Uint16LE.unpack(stream)
        source = Uint16LE.unpack(stream)
        return RDPShareControlHeader(RDPDataPDUType(pduType & 0xf), (pduType >> 4), source)

    def writeShareControlHeader(self, stream, header, dataLength):
        pduType = (header.type.value & 0xf) | (header.version << 4)
        stream.write(Uint16LE.pack(dataLength + 6))
        stream.write(Uint16LE.pack(pduType))
        stream.write(Uint16LE.pack(header.source))

    def parseShareDataHeader(self, stream, controlHeader):
        shareID = Uint32LE.unpack(stream)
        stream.read(1)
        streamID = Uint8.unpack(stream)
        uncompressedLength = Uint16LE.unpack(stream)
        pduSubtype = Uint8.unpack(stream)
        compressedType = Uint8.unpack(stream)
        compressedLength = Uint16LE.unpack(stream)
        return RDPShareDataHeader(controlHeader.type, controlHeader.version, controlHeader.source, shareID, streamID, uncompressedLength, RDPDataPDUSubtype(pduSubtype), compressedType, compressedLength)

    def writeShareDataHeader(self, stream, header, dataLength):
        substream = StringIO()
        substream.write(Uint32LE.pack(header.shareID))
        substream.write("\x00")
        substream.write(Uint8.pack(header.streamID))
        substream.write(Uint16LE.pack(header.uncompressedLength))
        substream.write(Uint8.pack(header.subtype))
        substream.write(Uint8.pack(header.compressedType))
        substream.write(Uint16LE.pack(header.compressedLength))
        substream = substream.getvalue()

        self.writeShareControlHeader(stream, header, dataLength + len(substream))
        stream.write(substream)

    def parseDemandActive(self, stream, header):
        shareID = Uint32LE.unpack(stream)
        lengthSourceDescriptor = Uint16LE.unpack(stream)
        lengthCombinedCapabilities = Uint16LE.unpack(stream)
        sourceDescriptor = stream.read(lengthSourceDescriptor)
        numberCapabilities = Uint16LE.unpack(stream)
        pad2Octets = stream.read(2)
        capabilitySets = stream.read(lengthCombinedCapabilities - 4)
        sessionID = Uint32LE.unpack(stream)

        return RDPDemandActivePDU(header, shareID, sourceDescriptor, numberCapabilities, capabilitySets, sessionID)

    def writeDemandActive(self, stream, pdu):
        Uint32LE.pack(pdu.shareID, stream)
        Uint16LE.pack(len(pdu.sourceDescriptor), stream)
        Uint16LE.pack(len(pdu.capabilitySets) + 4, stream)
        stream.write(pdu.sourceDescriptor)
        Uint16LE.pack(pdu.numberCapabilities, stream)
        stream.write("\x00" * 2)
        stream.write(pdu.capabilitySets)
        Uint32LE.pack(pdu.sessionID, stream)

    def parseConfirmActive(self, stream, header):
        shareID = Uint32LE.unpack(stream)
        originatorID = Uint16LE.unpack(stream)
        lengthSourceDescriptor = Uint16LE.unpack(stream)
        lengthCombinedCapabilities = Uint16LE.unpack(stream)
        sourceDescriptor = stream.read(lengthSourceDescriptor)
        numberCapabilities = Uint16LE.unpack(stream)
        stream.read(2)
        capabilitySetsRaw = stream.read(lengthCombinedCapabilities - 4)
        capabilitySets = self.parseCapabilitySets(capabilitySetsRaw, numberCapabilities)

        return RDPConfirmActivePDU(header, shareID, originatorID, sourceDescriptor,
                                   numberCapabilities, capabilitySets, capabilitySetsRaw)

    def parseCapabilitySets(self, capabilitySetsRaw, numberCapabilities):
        stream = StringIO(capabilitySetsRaw)
        capabilitySets = {}
        # Do minimum parsing for every capability
        for i in range(numberCapabilities):
            capabilitySetType = Uint16LE.unpack(stream.read(2))
            lengthCapability = Uint16LE.unpack(stream.read(2))
            capabilityData = stream.read(lengthCapability - 4)
            capability = Capability(capabilitySetType, capabilityData)
            capabilitySets[capabilitySetType] = capability

        # Fully parse the General capability set
        capabilitySets[CapabilityType.CAPSTYPE_GENERAL] = \
            self.parseGeneralCapability(capabilitySets[CapabilityType.CAPSTYPE_GENERAL].rawData)

        # Fully parse the Bitmap capability set
        capabilitySets[CapabilityType.CAPSTYPE_BITMAP] = \
            self.parseBitmapCapability(capabilitySets[CapabilityType.CAPSTYPE_BITMAP].rawData)

        # Fully parse the Order capability set
        capabilitySets[CapabilityType.CAPSTYPE_ORDER] = self.parseOrderCapability(
            capabilitySets[CapabilityType.CAPSTYPE_ORDER].rawData)
        return capabilitySets

    def parseGeneralCapability(self, data):
        """
        https://msdn.microsoft.com/en-us/library/cc240549.aspx
        :type data: str
        :param data: Raw data starting after lengthCapability
        :return: GeneralCapability
        """
        stream = StringIO(data)
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

    def parseBitmapCapability(self, data):
        """
        https://msdn.microsoft.com/en-us/library/cc240554.aspx
        :type data: str
        :param data: Raw data starting after lengthCapability
        :return: BitmapCapability
        """
        stream = StringIO(data)
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

    def parseOrderCapability(self, data):
        """
        https://msdn.microsoft.com/en-us/library/cc240556.aspx
        :type data: str
        :param data: Raw data starting after lengthCapability
        :return: OrderCapability
        """
        stream = StringIO(data)
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

    def writeConfirmActive(self, stream, pdu):
        """
        :type stream: StringIO
        :type pdu: RDPConfirmActivePDU
        """
        Uint32LE.pack(pdu.shareID, stream)
        Uint16LE.pack(pdu.originatorID, stream)
        Uint16LE.pack(len(pdu.sourceDescriptor), stream)
        Uint16LE.pack(len(pdu.capabilitySets) + 4, stream)
        stream.write(pdu.sourceDescriptor)
        Uint16LE.pack(pdu.numberCapabilities, stream)
        stream.write("\x00" * 2)  # pad2octets
        stream.write(pdu.capabilitySets)
        for capability in pdu.parsedCapabilitySets.values():
            # Since the general capability is fully parsed, write it back.
            if capability.type == CapabilityType.CAPSTYPE_GENERAL:
                self.writeGeneralCapability(capability, stream)
            # Since the order capability is fully parsed, write it back.
            elif capability.type == CapabilityType.CAPSTYPE_ORDER:
                self.writeOrderCapability(capability, stream)
            # Since the bitmap capability is fully parsed, write it back.
            elif capability.type == CapabilityType.CAPSTYPE_BITMAP:
                self.writeBitmapCapability(capability, stream)
            # Every other capability is parsed minimally.
            else:
                Uint16LE.pack(capability.type, stream)
                Uint16LE.pack(len(capability.rawData) + 4, stream)
                stream.write(capability.rawData)

    def parseError(self, stream, header):
        errorInfo = Uint32LE.unpack(stream)
        return RDPSetErrorInfoPDU(header, ErrorInfo(errorInfo))

    def writeError(self, stream, pdu):
        Uint32LE.pack(pdu.errorInfo, stream)

    def parseSynchronize(self, stream, header):
        messageType = Uint16LE.unpack(stream)
        targetUser = Uint16LE.unpack(stream)
        return RDPSynchronizePDU(header, messageType, targetUser)

    def writeSynchronize(self, stream, pdu):
        Uint16LE.pack(pdu.messageType, stream)
        Uint16LE.pack(pdu.targetUser, stream)

    def parseControl(self, stream, header):
        action = Uint16LE.unpack(stream)
        grantID = Uint16LE.unpack(stream)
        controlID = Uint32LE.unpack(stream)
        return RDPControlPDU(header, action, grantID, controlID)

    def writeControl(self, stream, pdu):
        Uint16LE.pack(pdu.action, stream)
        Uint16LE.pack(pdu.grantID, stream)
        Uint32LE.pack(pdu.grantID, stream)

    def parseInput(self, stream, header):
        numEvents = Uint16LE.unpack(stream)
        stream.read(2)

        parser = RDPInputParser()
        inputEvents = [parser.parse(stream) for _ in range(numEvents)]

        return RDPInputPDU(header, inputEvents)

    def writeInput(self, stream, pdu):
        Uint16LE.pack(len(pdu.events), stream)
        stream.write("\x00" * 2)

        parser = RDPInputParser()
        for event in pdu.events:
            stream.write(parser.write(event))

    def parsePointer(self, stream, header):
        parser = PointerEventParser()
        event = parser.parse(stream)
        return RDPPointerPDU(header, event)

    def writePointer(self, stream, pdu):
        parser = PointerEventParser()
        stream.write(parser.write(pdu.event))

    def parsePlaySound(self, stream, header):
        duration = Uint32LE.unpack(stream)
        frequency = Uint32LE.unpack(stream)
        return RDPPlaySoundPDU(header, duration, frequency)

    def writePlaySound(self, stream, pdu):
        Uint32LE.pack(pdu.duration, stream)
        Uint32LE.pack(pdu.frequency, stream)

    def writeGeneralCapability(self, capability, stream):
        """
        https://msdn.microsoft.com/en-us/library/cc240549.aspx
        :type capability: rdpy.pdu.rdp.capability.GeneralCapability
        :type stream: StringIO
        """
        substream = StringIO()
        Uint16LE.pack(capability.type, stream)
        Uint16LE.pack(capability.majorType, substream)
        Uint16LE.pack(capability.minorType, substream)
        Uint16LE.pack(capability.protocolVersion, substream)
        substream.write("\00" * 2)  # pad2octetsA
        Uint16LE.pack(capability.generalCompressionTypes, substream)
        Uint16LE.pack(capability.extraFlags, substream)
        Uint16LE.pack(capability.updateCapabilityFlag, substream)
        Uint16LE.pack(capability.remoteUnshareFlag, substream)
        Uint16LE.pack(capability.generalCompressionLevel, substream)
        Uint8.pack(capability.refreshRectSupport, substream)
        Uint8.pack(capability.suppressOutputSupport, substream)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())

    def writeOrderCapability(self, capability, stream):
        """
        :type capability: rdpy.pdu.rdp.capability.OrderCapability
        :type stream: StringIO
        """
        substream = StringIO()
        Uint16LE.pack(capability.type, stream)
        substream.write(capability.terminalDescriptor)
        substream.write("\00"*4)
        Uint16LE.pack(capability.desktopSaveXGranularity, substream)
        Uint16LE.pack(capability.desktopSaveYGranularity, substream)
        substream.write("\00" * 2)
        Uint16LE.pack(capability.maximumOrderLevel, substream)
        Uint16LE.pack(capability.numberFonts, substream)
        Uint16LE.pack(capability.orderFlags, substream)
        substream.write(capability.orderSupport)
        Uint16LE.pack(capability.textFlags, substream)
        Uint16LE.pack(capability.orderSupportExFlags, substream)
        substream.write("\00" * 4)
        Uint32LE.pack(capability.desktopSaveSize, substream)
        substream.write("\00" * 4)
        Uint16LE.pack(capability.textANSICodePage, substream)
        substream.write("\00" * 2)

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())

    def writeBitmapCapability(self, capability, stream):
        """
        :type capability: rdpy.pdu.rdp.capability.BitmapCapability
        :type stream: StringIO
        """
        substream = StringIO()
        Uint16LE.pack(capability.type, stream)

        Uint16LE.pack(capability.preferredBitsPerPixel, substream)
        Uint16LE.pack(capability.receive1BitPerPixel, substream)
        Uint16LE.pack(capability.receive4BitsPerPixel, substream)
        Uint16LE.pack(capability.receive8BitsPerPixel, substream)
        Uint16LE.pack(capability.desktopWidth, substream)
        Uint16LE.pack(capability.desktopHeight, substream)
        substream.write("\00"*2)  # pad2octets
        Uint16LE.pack(capability.desktopResizeFlag, substream)
        Uint16LE.pack(capability.bitmapCompressionFlag, substream)
        Uint8.pack(capability.highColorFlags, substream)
        Uint8.pack(capability.drawingFlags, substream)
        Uint16LE.pack(capability.multipleRectangleSupport, substream)

        substream.write("\00" * 2)  # pad2octetsB

        Uint16LE.pack(len(substream.getvalue()) + 4, stream)
        stream.write(substream.getvalue())
