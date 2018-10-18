from StringIO import StringIO

from rdpy.core.packing import Uint16LE, Uint32LE, Uint8
from rdpy.enum.rdp import RDPDataPDUType, RDPDataPDUSubtype, ErrorInfo, InputEventType
from rdpy.exceptions import UnknownPDUTypeError
from rdpy.parser.rdp.input import RDPInputParser
from rdpy.pdu.rdp.data import RDPShareControlHeader, RDPShareDataHeader, RDPDemandActivePDU, RDPConfirmActivePDU, \
    RDPSetErrorInfoPDU, RDPSynchronizePDU, RDPControlPDU, RDPInputPDU


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
        }

        self.dataWriters = {
            RDPDataPDUSubtype.PDUTYPE2_SET_ERROR_INFO_PDU: self.writeError,
            RDPDataPDUSubtype.PDUTYPE2_SYNCHRONIZE: self.writeSynchronize,
            RDPDataPDUSubtype.PDUTYPE2_CONTROL: self.writeControl,
            RDPDataPDUSubtype.PDUTYPE2_INPUT: self.writeInput,
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
        capabilitySets = stream.read(lengthCombinedCapabilities - 4)
        return RDPConfirmActivePDU(header, shareID, originatorID, sourceDescriptor, numberCapabilities, capabilitySets)

    def writeConfirmActive(self, stream, pdu):
        Uint32LE.pack(pdu.shareID, stream)
        Uint16LE.pack(pdu.originatorID, stream)
        Uint16LE.pack(len(pdu.sourceDescriptor), stream)
        Uint16LE.pack(len(pdu.capabilitySets) + 4, stream)
        stream.write(pdu.sourceDescriptor)
        Uint16LE.pack(pdu.numberCapabilities, stream)
        stream.write("\x00" * 2)
        stream.write(pdu.capabilitySets)

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