from rdpy.core.packing import Uint16LE, Uint32LE

class RDPDataPDUType:
    """
    Data PDU types
    @see: http://msdn.microsoft.com/en-us/library/cc240576.aspx
    """
    PDUTYPE_DEMANDACTIVEPDU = 0x1
    PDUTYPE_CONFIRMACTIVEPDU = 0x3
    PDUTYPE_DEACTIVATEALLPDU = 0x6
    PDUTYPE_DATAPDU = 0x7
    PDUTYPE_SERVER_REDIR_PKT = 0xA

class RDPDemandActivePDU:
    def __init__(self, header, sharedID, sourceDescriptor, numberCapabilities, ):
        self.header = header
        self.sharedID

class RDPSharedControlHeader:
    def __init__(self, type, version, source):
        self.type = type
        self.version = version
        self.source = source

class RDPDataParser:
    def __init__(self):
        self.parsers = {
            RDPDataPDUType.PDUTYPE_DEMANDACTIVEPDU: self.parseDemandActive,
        }
    
    def parse(self):
        pass
    
    def parseControlHeader(self, stream):
        length = Uint16LE.unpack(stream)
        type = Uint16LE.unpack(stream)
        source = Uint16LE.unpack(stream)
        return RDPSharedControlHeader(type & 0b1111, (type >> 4), source)

    def parseCapabilitySet(self, stream):
        type = Uint16LE.unpack(stream)
        length = Uint16LE.unpack(stream)
        data = stream.read(length)

    def parseDemandActive(self, stream):
        header = self.parseControlHeader(stream)
        shareID = Uint32LE.unpack(stream)
        lengthSourceDescriptor = Uint16LE.unpack(stream)
        lengthCombinedCapabilities = Uint16LE.unpack(stream)
        sourceDescriptor = stream.read(lengthSourceDescriptor)
        numberCapabilities = Uint16LE.unpack(stream)
        pad2Octets = stream.read(2)
        
        capabilitySets = []

        for _ in range(numberCapabilities):
            capability = self.parseCapabilitySet(stream)
            capabilitySets.append(capability)
        
        sessionID = Uint32LE.unpack(stream)