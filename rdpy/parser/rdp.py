import struct
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
from StringIO import StringIO

from rdpy.core.StrictStream import StrictStream
from rdpy.core.packing import Uint32LE, Uint16LE, Uint8, Int32LE
from rdpy.enum.rdp import ClientInfoFlags, RDPSecurityHeaderType, RDPLicensingPDUType, RDPDataPDUType, \
    RDPConnectionDataType, ServerCertificateType, RDPDataPDUSubtype, ErrorInfo
from rdpy.pdu.rdp.connection import RDPNegotiationRequestPDU, RDPClientDataPDU, ClientCoreData, ClientSecurityData, \
    ClientChannelDefinition, ClientNetworkData, ClientClusterData, RDPServerDataPDU, ServerCoreData, ServerNetworkData, \
    ServerSecurityData, ProprietaryCertificate
from rdpy.pdu.rdp.data import RDPDemandActivePDU, RDPShareControlHeader, RDPConfirmActivePDU, RDPShareDataHeader, \
    RDPSetErrorInfoPDU
from rdpy.pdu.rdp.licensing import RDPLicenseBinaryBlob, RDPLicenseErrorAlertPDU
from rdpy.pdu.rdp.security import RDPBasicSecurityPDU, RDPSignedSecurityPDU, RDPFIPSSecurityPDU, \
    RDPSecurityExchangePDU
from rdpy.pdu.rdp.settings import RDPClientInfoPDU
from rdpy.protocol.rdp.x224 import NegociationType


class RDPSettingsParser:
    def parse(self, data):
        stream = StringIO(data)
        codePage = Uint32LE.unpack(stream)
        flags = Uint32LE.unpack(stream)

        hasNullBytes = codePage == 1252 or flags & ClientInfoFlags.INFO_UNICODE != 0
        nullByteCount = 1 if hasNullBytes else 0

        domainLength = Uint16LE.unpack(stream) + nullByteCount
        usernameLength = Uint16LE.unpack(stream) + nullByteCount
        passwordLength = Uint16LE.unpack(stream) + nullByteCount
        alternateShellLength = Uint16LE.unpack(stream) + nullByteCount
        workingDirLength = Uint16LE.unpack(stream) + nullByteCount

        domain = stream.read(domainLength)
        username = stream.read(usernameLength)
        password = stream.read(passwordLength)
        alternateShell = stream.read(alternateShellLength)
        workingDir = stream.read(workingDirLength)

        domain = domain.replace("\x00", "")
        username = username.replace("\x00", "")
        password = password.replace("\x00", "")
        alternateShell = alternateShell.replace("\x00", "")
        workingDir = workingDir.replace("\x00", "")

        extraInfo = stream.read()

        return RDPClientInfoPDU(codePage, flags, domain, username, password, alternateShell, workingDir, extraInfo)

    def write(self, pdu):
        if not isinstance(pdu, RDPClientInfoPDU):
            raise Exception("Unknown settings PDU type")

        stream = StringIO()
        stream.write(Uint32LE.pack(pdu.codePage))
        stream.write(Uint32LE.pack(pdu.flags))

        isUnicode = pdu.flags & ClientInfoFlags.INFO_UNICODE != 0
        hasNullBytes = pdu.codePage == 1252 or isUnicode
        nullByteCount = 1 if hasNullBytes else 0
        unicodeMultiplier = 2 if isUnicode else 0

        domain = pdu.domain + "\x00" * nullByteCount
        username = pdu.username + "\x00" * nullByteCount
        password = pdu.password + "\x00" * nullByteCount
        alternateShell = pdu.alternateShell + "\x00" * nullByteCount
        workingDir = pdu.workingDir + "\x00" * nullByteCount

        if isUnicode:
            domain = domain.encode("utf-16le")
            username = username.encode("utf-16le")
            password = password.encode("utf-16le")
            alternateShell = alternateShell.encode("utf-16le")
            workingDir = workingDir.encode("utf-16le")

        domainLength = len(domain) - nullByteCount * unicodeMultiplier
        usernameLength = len(username) - nullByteCount * unicodeMultiplier
        passwordLength = len(password) - nullByteCount * unicodeMultiplier
        alternateShellLength = len(alternateShell) - nullByteCount * unicodeMultiplier
        workingDirLength = len(workingDir) - nullByteCount * unicodeMultiplier


        stream.write(Uint16LE.pack(domainLength))
        stream.write(Uint16LE.pack(usernameLength))
        stream.write(Uint16LE.pack(passwordLength))
        stream.write(Uint16LE.pack(alternateShellLength))
        stream.write(Uint16LE.pack(workingDirLength))
        stream.write(domain)
        stream.write(username)
        stream.write(password)
        stream.write(alternateShell)
        stream.write(workingDir)
        stream.write(pdu.extraInfo)

        return stream.getvalue()


class RDPSecurityParser:
    def __init__(self, headerType):
        self.headerType = headerType

    def parse(self, data):
        stream = StringIO(data)

        if self.headerType == RDPSecurityHeaderType.BASIC:
            return self.parseBasicSecurity(stream)
        elif self.headerType == RDPSecurityHeaderType.SIGNED:
            return self.parseSignedSecurity(stream)
        elif self.headerType == RDPSecurityHeaderType.FIPS:
            return self.parseFIPSSecurity(stream)
        else:
            raise Exception("Trying to parse unknown security header type")

    def parseBasicSecurity(self, stream):
        header = self.parseBasicHeader(stream)
        payload = stream.read()
        return RDPBasicSecurityPDU(header, payload)

    def parseSignedSecurity(self, stream):
        header = self.parseBasicHeader(stream)
        signature = stream.read(8)
        payload = stream.read()
        return RDPSignedSecurityPDU(header, signature, payload)

    def parseFIPSSecurity(self, stream):
        header = self.parseBasicHeader(stream)
        headerLength = Uint16LE.unpack(stream)
        version = Uint8.unpack(stream)
        padLength = Uint8.unpack(stream)
        signature = stream.read(8)
        payload = stream.read()
        return RDPFIPSSecurityPDU(header, version, padLength, signature, payload)

    def parseBasicHeader(self, stream):
        flags = Uint16LE.unpack(stream)
        hiFlags = Uint16LE.unpack(stream)
        return (hiFlags << 16) | flags

    def parseSecurityExchange(self, data):
        stream = StringIO(data)
        header = self.parseBasicHeader(stream)
        length = Uint32LE.unpack(stream)
        clientRandom = stream.read(length)
        return RDPSecurityExchangePDU(header, clientRandom)



    def write(self, pdu):
        if isinstance(pdu, RDPSecurityExchangePDU):
            return self.writeSecurityExchange(pdu)
        elif isinstance(pdu, RDPBasicSecurityPDU):
            return self.writeBasicHeader(pdu) + pdu.payload
        elif isinstance(pdu, RDPSignedSecurityPDU):
            return self.writeSignedHeader(pdu) + pdu.payload
        elif isinstance(pdu, RDPFIPSSecurityPDU):
            return self.writeFIPSHeader(pdu) + pdu.payload
        else:
            raise Exception("Trying to write unknown PDU type")

    def writeBasicHeader(self, pdu):
        return Uint16LE.pack(pdu.header & 0xffff) + Uint16LE.pack(pdu.header >> 16)

    def writeSignedHeader(self, pdu):
        return self.writeBasicHeader(pdu) + pdu.signature[: 8]

    def writeFIPSHeader(self, pdu):
        return self.writeBasicHeader(pdu) + Uint16LE.pack(0x10) + Uint8.pack(pdu.version) + Uint8.pack(pdu.padLength) + pdu.signature[: 8]

    def writeSecurityExchange(self, pdu):
        return self.writeBasicHeader(pdu) + Uint32LE.pack(len(pdu.clientRandom)) + pdu.clientRandom


class RDPLicensingParser:
    def __init__(self):
        self.parsers = {
            RDPLicensingPDUType.ERROR_ALERT: self.parseErrorAlert,
        }

    def parse(self, data):
        stream = StringIO(data)
        header = Uint8.unpack(stream)
        flags = Uint8.unpack(stream)
        size = Uint16LE.unpack(stream)

        if header not in self.parsers:
            raise Exception("Trying to parse unknown license PDU")

        return self.parsers[header](stream, flags)

    def parseLicenseBlob(self, stream):
        type = Uint16LE.unpack(stream)
        length = Uint16LE.unpack(stream)
        data = stream.read(length)
        return RDPLicenseBinaryBlob(type, data)

    def parseErrorAlert(self, stream, flags):
        errorCode = Uint32LE.unpack(stream)
        stateTransition = Uint32LE.unpack(stream)
        blob = self.parseLicenseBlob(stream)
        return RDPLicenseErrorAlertPDU(flags, errorCode, stateTransition, blob)

    def write(self, pdu):
        stream = StringIO()
        stream.write(Uint8.pack(pdu.header))
        stream.write(Uint8.pack(pdu.flags))
        substream = StringIO()
        if isinstance(pdu, RDPLicenseErrorAlertPDU):
            self.writeErrorAlert(substream, pdu)
        else:
            raise Exception("Unhandled RDP Licencing PDU: {}".format(pdu))
        stream.write(Uint16LE.pack(len(substream.getvalue()) + 4))
        stream.write(substream.getvalue())
        return stream.getvalue()

    def writeErrorAlert(self, stream, pdu):
        """
        Writes LicenceErrorAlertPDU-specific fields to stream
        :type stream: StringIO
        :type pdu: RDPLicenseErrorAlertPDU
        """
        stream.write(Uint32LE.pack(pdu.errorCode))
        stream.write(Uint32LE.pack(pdu.stateTransition))
        stream.write(Uint16LE.pack(pdu.blob.type))
        stream.write(Uint16LE.pack(0))




class RDPDataParser:
    def __init__(self):
        self.parsers = {
            RDPDataPDUType.PDUTYPE_DEMANDACTIVEPDU: self.parseDemandActive,
            RDPDataPDUType.PDUTYPE_CONFIRMACTIVEPDU: self.parseConfirmActive,
            RDPDataPDUType.PDUTYPE_DATAPDU: self.parseData,
        }

        self.dataParsers = {
            RDPDataPDUSubtype.PDUTYPE2_SET_ERROR_INFO_PDU: self.parseError,
        }

        self.dataWriters = {
            RDPDataPDUSubtype.PDUTYPE2_SET_ERROR_INFO_PDU: self.writeError,
        }

    def parse(self, data):
        stream = StringIO(data)
        header = self.parseShareControlHeader(stream)

        if header.type not in self.parsers:
            raise Exception("Trying to parse unknown Data PDU type: %s" % str(header.type))

        return self.parsers[header.type](stream, header)

    def parseData(self, stream, header):
        header = self.parseShareDataHeader(stream, header)

        if header.subtype not in self.dataParsers:
            raise Exception("Trying to parse unknown Data PDU Subtype: %s" % str(header.subtype))

        return self.dataParsers[header.subtype](stream, header)

    def write(self, pdu):
        stream = StringIO()
        substream = StringIO()

        if pdu.header.type == RDPDataPDUType.PDUTYPE_DEMANDACTIVEPDU:
            headerWriter = self.writeShareControlHeader
            self.writeDemandActive(substream, pdu)
        elif pdu.header.type == RDPDataPDUType.PDUTYPE_CONFIRMACTIVEPDU:
            headerWriter = self.writeShareControlHeader
            self.writeConfirmActive(substream, pdu)
        elif pdu.header.type == RDPDataPDUType.PDUTYPE_DATAPDU:
            headerWriter = self.writeShareDataHeader
            self.writeData(stream, pdu)

        substream = substream.getvalue()
        headerWriter(stream, pdu.header, len(substream))
        stream.write(substream)
        return stream.getvalue()

    def writeData(self, stream, pdu):
        if pdu.header.subtype not in self.dataWriters:
            raise Exception("Trying to write unknown Data PDU Subtype: %s" % str(pdu.header.subtype))

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

class RDPNegotiationParser:
    """
    Parse the first two packets of the RDP connection sequence,
    where the security protocol is chosen.
    """

    def __init__(self):

        self.writers = {
            NegociationType.TYPE_RDP_NEG_RSP: self.writeNegotiationResponsePDU,
        }

    def parse(self, data):
        """
        Parse RDP Negotiation Request packet. Throws Exceptions if packet is malformed.
        :param data: The bytes of the RDP Negotiation Request packet.
        :return: A RDPNegotiationRequestPDU
        """
        split_data = data.split("\r\n")
        if len(split_data) != 2:
            raise Exception("No mstshash cookie (not an error per se, but not implemented)")
        cookie = split_data[0]
        flags = split_data[1]
        if len(split_data[1]) < 4:
            raise Exception("RDP negotiation packet not big enough: {} bytes".format(len(split_data[1])))
        packet_type = Uint16LE.unpack(split_data[1][0 : 2])
        if packet_type != NegociationType.TYPE_RDP_NEG_REQ:
            raise Exception("Invalid RDP packet type. Should be {}, is {}".format(NegociationType.TYPE_RDP_NEG_REQ,
                                                                                  packet_type))
        length = Uint16LE.unpack(split_data[1][2 : 4])
        if length < 8:
            raise Exception("Invalid RDP negotiation packet length: {}".format(length))
        requested_protocols = Uint32LE.unpack(split_data[1][4: 8])
        return RDPNegotiationRequestPDU(cookie, flags, requested_protocols)

    def write(self, pdu):
        """
        :param pdu: The PDU to write
        :return: A StringIO of the bytes of the given PDU
        """
        if pdu.packetType in self.writers.keys():
            return self.writers[pdu.packetType](pdu)
        else:
            raise Exception("Wrong packet type.")

    def writeNegotiationResponsePDU(self, pdu):
        """
        :type pdu: RDPNegotiationResponsePDU
        """
        stream = StringIO()
        stream.write(Uint8.pack(pdu.packetType))
        stream.write(Uint8.pack(pdu.flags))
        stream.write(Uint8.pack(8))  # Length
        stream.write(Uint8.pack(0))  # Empty byte?
        stream.write(Int32LE.pack(pdu.selected_protocol))
        return stream.getvalue()


class RDPClientConnectionParser:
    """
    Parser for Client Data PDUs (i.e: servers).
    """
    def __init__(self):
        self.parsers = {
            RDPConnectionDataType.CLIENT_CORE: self.parseClientCoreData,
            RDPConnectionDataType.CLIENT_SECURITY: self.parseClientSecurityData,
            RDPConnectionDataType.CLIENT_NETWORK: self.parseClientNetworkData,
            RDPConnectionDataType.CLIENT_CLUSTER: self.parseClientClusterData,
        }

        self.writers = {
            RDPConnectionDataType.CLIENT_CORE: self.writeClientCoreData,
            RDPConnectionDataType.CLIENT_SECURITY: self.writeClientSecurityData,
            RDPConnectionDataType.CLIENT_NETWORK: self.writeClientNetworkData,
            RDPConnectionDataType.CLIENT_CLUSTER: self.writeClientClusterData,

        }

    def parse(self, data):
        core = None
        security = None
        network = None
        cluster = None

        stream = StringIO(data)
        while stream.pos != stream.len and (core is None or security is None or network is None or cluster is None):
            structure = self.parseStructure(stream)

            if structure.header == RDPConnectionDataType.CLIENT_CORE:
                core = structure
            elif structure.header == RDPConnectionDataType.CLIENT_SECURITY:
                security = structure
            elif structure.header == RDPConnectionDataType.CLIENT_NETWORK:
                network = structure
            elif structure.header == RDPConnectionDataType.CLIENT_CLUSTER:
                cluster = structure

            if len(stream.getvalue()) == 0:
                break

        return RDPClientDataPDU(core, security, network, cluster)

    def parseStructure(self, stream):
        header = Uint16LE.unpack(stream)
        length = Uint16LE.unpack(stream) - 4
        data = stream.read(length)

        if len(data) != length:
            raise Exception("Client Data length field does not match actual size")

        substream = StringIO(data)

        if header not in self.parsers:
            raise Exception("Unknown client data header")

        return self.parsers[header](substream)


    def parseClientCoreData(self, stream):
        stream = StrictStream(stream)

        minor = Uint16LE.unpack(stream.read(2))
        major = Uint16LE.unpack(stream.read(2))

        # 128 bytes minimum (excluding header)
        version = (major << 16) | minor
        desktopWidth = Uint16LE.unpack(stream)
        desktopHeight = Uint16LE.unpack(stream)
        colorDepth = Uint16LE.unpack(stream)
        sasSequence = Uint16LE.unpack(stream)
        keyboardLayout = Uint32LE.unpack(stream)
        clientBuild = Uint32LE.unpack(stream)
        clientName = stream.read(32).decode("utf-16le").strip("\x00")
        keyboardType = Uint32LE.unpack(stream)
        keyboardSubType = Uint32LE.unpack(stream)
        keyboardFunctionKey = Uint32LE.unpack(stream)
        imeFileName = stream.read(64).decode("utf-16le").strip("\x00")

        core = ClientCoreData(version, desktopWidth, desktopHeight, colorDepth, sasSequence, keyboardLayout, clientBuild, clientName, keyboardType, keyboardSubType, keyboardFunctionKey, imeFileName)

        # Optional data
        # The optional fields are read in order. If one of them is not present, then all subsequent fields are also not present.
        try:
            core.postBeta2ColorDepth = Uint16LE.unpack(stream)
            core.clientProductId = Uint16LE.unpack(stream)
            core.serialNumber = Uint32LE.unpack(stream)
            core.highColorDepth = Uint16LE.unpack(stream)
            core.supportedColorDepths = Uint16LE.unpack(stream)
            core.earlyCapabilityFlags = Uint16LE.unpack(stream)
            core.clientDigProductId = stream.read(64).decode("utf-16le").strip("\x00")
            core.connectionType = Uint8.unpack(stream)
            core.pad1octet = stream.read(1)
            core.serverSelectedProtocol = Uint32LE.unpack(stream)
            core.desktopPhysicalWidth = Uint32LE.unpack(stream)
            core.desktopPhysicalHeight = Uint32LE.unpack(stream)
            core.desktopOrientation = Uint16LE.unpack(stream)
            core.desktopScaleFactor = Uint32LE.unpack(stream)
            core.deviceScaleFactor = Uint32LE.unpack(stream)
        except EOFError:
            # The stream has reached the end, we don't have any more optional fields. This exception can be ignored.
            pass

        return core

    def parseClientSecurityData(self, stream):
        encryptionMethods = Uint32LE.unpack(stream)
        extEncryptionMethods = Uint32LE.unpack(stream)
        return ClientSecurityData(encryptionMethods, extEncryptionMethods)

    def parseClientNetworkData(self, stream):
        channelCount = Uint32LE.unpack(stream)
        data = stream.getvalue()[4 :]

        if len(data) != channelCount * 12:
            raise Exception("Invalid channel array size")

        channelDefinitions = []

        for _ in range(channelCount):
            name = stream.read(8).strip("\x00")
            options = Uint32LE.unpack(stream)
            channelDefinitions.append(ClientChannelDefinition(name, options))

        return ClientNetworkData(channelDefinitions)

    def parseClientClusterData(self, stream):
        flags = Uint32LE.unpack(stream)
        redirectedSessionID = Uint32LE.unpack(stream)
        return ClientClusterData(flags, redirectedSessionID)

    def write(self, pdu):
        stream = StringIO()
        self.writeStructure(stream, pdu.coreData)
        self.writeStructure(stream, pdu.securityData)
        self.writeStructure(stream, pdu.networkData)
        self.writeStructure(stream, pdu.clusterData)
        return stream.getvalue()

    def writeStructure(self, stream, data):
        if data.header not in self.writers:
            raise Exception("Trying to write unknown Client Data structure")

        substream = StringIO()
        self.writers[data.header](substream, data)

        substream = substream.getvalue()

        stream.write(Uint16LE.pack(data.header))
        stream.write(Uint16LE.pack(len(substream) + 4))
        stream.write(substream)

    def writeClientCoreData(self, stream, core):
        major = core.version >> 16
        minor = core.version & 0xffff

        stream.write(Uint16LE.pack(minor))
        stream.write(Uint16LE.pack(major))
        stream.write(Uint16LE.pack(core.desktopWidth))
        stream.write(Uint16LE.pack(core.desktopHeight))
        stream.write(Uint16LE.pack(core.colorDepth))
        stream.write(Uint16LE.pack(core.sasSequence))
        stream.write(Uint32LE.pack(core.keyboardLayout))
        stream.write(Uint32LE.pack(core.clientBuild))
        stream.write(core.clientName.encode("utf-16le").ljust(32, "\x00")[: 32])
        stream.write(Uint32LE.pack(core.keyboardType))
        stream.write(Uint32LE.pack(core.keyboardSubType))
        stream.write(Uint32LE.pack(core.keyboardFunctionKey))
        stream.write(core.imeFileName.encode("utf-16le").ljust(64, "\x00")[: 64])

        try:
            stream.write(Uint16LE.pack(core.postBeta2ColorDepth))
            stream.write(Uint16LE.pack(core.clientProductId))
            stream.write(Uint32LE.pack(core.serialNumber))
            stream.write(Uint16LE.pack(core.highColorDepth))
            stream.write(Uint16LE.pack(core.supportedColorDepths))
            stream.write(Uint16LE.pack(core.earlyCapabilityFlags))
            stream.write(core.clientDigProductId.encode("utf-16le").ljust(64, "\x00")[: 64])
            stream.write(Uint8.pack(core.connectionType))
            stream.write("\x00")
            stream.write(Uint32LE.pack(core.serverSelectedProtocol))
            stream.write(Uint32LE.pack(core.desktopPhysicalWidth))
            stream.write(Uint32LE.pack(core.desktopPhysicalHeight))
            stream.write(Uint16LE.pack(core.desktopOrientation))
            stream.write(Uint32LE.pack(core.desktopScaleFactor))
            stream.write(Uint32LE.pack(core.deviceScaleFactor))
        except struct.error:
            # We tried to write an optional field which was not present. Stop writing beyond this point.
            pass

    def writeClientSecurityData(self, stream, security):
        stream.write(Uint32LE.pack(security.encryptionMethods))
        stream.write(Uint32LE.pack(security.extEncryptionMethods))

    def writeClientNetworkData(self, stream, network):
        stream.write(Uint32LE.pack(len(network.channelDefinitions)))

        for channel in network.channelDefinitions:
            if len(channel.name) > 8:
                raise Exception("Channel name must have 8 characters maximum")

            stream.write(channel.name.ljust(8, "\x00")[: 8])
            stream.write(Uint32LE.pack(channel.options))

    def writeClientClusterData(self, stream, cluster):
        stream.write(Uint32LE.pack(cluster.flags))
        stream.write(Uint32LE.pack(cluster.redirectedSessionID))


class RDPServerConnectionParser:
    """
    Parser for Server Data PDUs (i.e: client).
    """

    def __init__(self):
        self.parsers = {
            RDPConnectionDataType.SERVER_CORE: self.parseServerCoreData,
            RDPConnectionDataType.SERVER_NETWORK: self.parseServerNetworkData,
            RDPConnectionDataType.SERVER_SECURITY: self.parseServerSecurityData,
        }

        self.writers = {
            RDPConnectionDataType.SERVER_CORE: self.writeServerCoreData,
            RDPConnectionDataType.SERVER_NETWORK: self.writeServerNetworkData,
            RDPConnectionDataType.SERVER_SECURITY: self.writeServerSecurityData,
        }

    def parse(self, data):
        core = None
        security = None
        network = None

        stream = StringIO(data)
        while core is None or security is None or network is None:
            structure = self.parseStructure(stream)

            if structure.header == RDPConnectionDataType.SERVER_CORE:
                core = structure
            elif structure.header == RDPConnectionDataType.SERVER_SECURITY:
                security = structure
            elif structure.header == RDPConnectionDataType.SERVER_NETWORK:
                network = structure

            if len(stream.getvalue()) == 0:
                break

        return RDPServerDataPDU(core, security, network)

    def parseStructure(self, stream):
        header = Uint16LE.unpack(stream)
        length = Uint16LE.unpack(stream) - 4
        data = stream.read(length)

        if len(data) < length:
            raise Exception("Server Data length field does not match actual size")

        substream = StringIO(data)

        if header not in self.parsers:
            raise Exception("Unknown server data header")

        return self.parsers[header](substream)

    def parseServerCoreData(self, stream):
        stream = StrictStream(stream)

        clientRequestedProtocols = None
        earlyCapabilityFlags = None
        version = Uint32LE.unpack(stream)

        try:
            clientRequestedProtocols = Uint32LE.unpack(stream)
            earlyCapabilityFlags = Uint32LE.unpack(stream)
        except EOFError:
            pass

        return ServerCoreData(version, clientRequestedProtocols, earlyCapabilityFlags)

    def parseServerNetworkData(self, stream):
        mcsChannelID = Uint16LE.unpack(stream)
        channelCount = Uint16LE.unpack(stream)
        channels = [Uint16LE.unpack(stream) for _ in range(channelCount)]

        return ServerNetworkData(mcsChannelID, channels)

    def parseServerSecurityData(self, stream):
        stream = StrictStream(stream)
        encryptionMethod = Uint32LE.unpack(stream)
        encryptionLevel = Uint32LE.unpack(stream)
        serverRandom = None
        serverCertificate = None

        try:
            serverRandomLength = Uint32LE.unpack(stream)
            serverCertificateLength = Uint32LE.unpack(stream)
            serverRandom = stream.read(serverRandomLength)
            serverCertificate = stream.read(serverCertificateLength)
            serverCertificate = self.parseServerCertificate(serverCertificate)
        except EOFError:
            pass

        return ServerSecurityData(encryptionMethod, encryptionLevel, serverRandom, serverCertificate)

    def parseServerCertificate(self, data):
        stream = StringIO(data)
        version = Uint32LE.unpack(stream)

        if version == ServerCertificateType.PROPRIETARY:
            return self.parseProprietaryCertificate(stream)
        else:
            raise Exception("Unhandled certificate type")

    def parseProprietaryCertificate(self, stream):
        signatureAlgorithmID = Uint32LE.unpack(stream)
        keyAlgorithmID = Uint32LE.unpack(stream)
        publicKeyType = Uint16LE.unpack(stream)
        keyLength = Uint16LE.unpack(stream)
        publicKey = stream.read(keyLength)
        signatureType = Uint16LE.unpack(stream)
        signatureLength = Uint16LE.unpack(stream)
        signature = stream.read(signatureLength - 8)
        padding = stream.read()

        stream = StringIO(publicKey)
        magic = stream.read(4)
        keyLength = Uint32LE.unpack(stream)
        bitLength = Uint32LE.unpack(stream)
        dataLength = Uint32LE.unpack(stream)
        publicExponent = Uint32LE.unpack(stream)
        modulus = stream.read(keyLength - 8)
        padding = stream.read(8)

        # Modulus must be reversed because bytes_to_long expects it to be in big endian format
        modulus = bytes_to_long(modulus[:: -1])
        publicExponent = long(publicExponent)
        publicKey = RSA.construct((modulus, publicExponent))

        return ProprietaryCertificate(signatureAlgorithmID, keyAlgorithmID, publicKeyType, publicKey, signatureType, signature, padding)

    def write(self, pdu):
        """
        :param pdu: The RDP pdu to write
        :return: StringIO to send to the next network protocol layer
        """
        stream = StringIO()
        self.writeStructure(stream, pdu.core)
        self.writeStructure(stream, pdu.security)
        self.writeStructure(stream, pdu.network)
        return stream.getvalue()

    def writeStructure(self, stream, data):
        """
        :param stream: StringIO to write to
        :param data: The structure to write (ex: ServerCoreData)
        """
        if data.header not in self.writers:
            raise Exception("Trying to write unknown Server Data structure")

        substream = StringIO()
        self.writers[data.header](substream, data)

        substream = substream.getvalue()

        stream.write(Uint16LE.pack(data.header))
        stream.write(Uint16LE.pack(len(substream) + 4))
        stream.write(substream)

    def writeServerCoreData(self, stream, data):
        """
        :type stream: StringIO
        :type data: ServerCoreData
        """
        stream.write(Uint32LE.pack(data.version))
        stream.write(Uint32LE.pack(data.clientRequestedProtocols))
        stream.write(Uint32LE.pack(data.earlyCapabilityFlags))

    def writeServerNetworkData(self, stream, data):
        """
        :type stream: StringIO
        :type data: ServerNetworkData
        """
        stream.write(Uint16LE.pack(data.mcsChannelID))
        stream.write(Uint16LE.pack(len(data.channels)))
        for channel in data.channels:
            stream.write(Uint16LE.pack(channel))
        if len(data.channels) % 2 != 0:
            stream.write(Uint16LE.pack(0))  # Write 2 empty bytes so we keep a multiple of 4.

    def writeServerSecurityData(self, stream, data):
        """
        :type stream: StringIO
        :type data: ServerSecurityData
        """
        stream.write(Uint32LE.pack(data.encryptionMethod))
        stream.write(Uint32LE.pack(data.encryptionLevel))
        if data.serverRandom is not None:
            stream.write(Uint32LE.pack(len(data.serverRandom)))
            stream.write(Uint32LE.pack(len(data.serverCertificate)))
            stream.write(data.serverRandom)
            stream.write(data.serverCertificate)

class RDPClientInfoParser:

    def parse(self, pdu):
        """
        https://msdn.microsoft.com/en-us/library/cc240475.aspx
        :type pdu: str
        :return: RDPClientInfoPDU
        """
        # cb = count byte
        codePage = Uint32LE.unpack(pdu[0 : 4])
        flags = Uint32LE.unpack(pdu[4 : 8])
        cbDomain = Uint16LE.unpack(pdu[8 : 10])
        cbUserName = Uint16LE.unpack(pdu[10 : 12])
        cbPassword = Uint16LE.unpack(pdu[12 : 14])
        cbAlternateShell = Uint16LE.unpack(pdu[14 : 16])
        cbWorkingDir = Uint16LE.unpack(pdu[16 : 18])
        domainIndexEnd = 18 + cbDomain + 2
        domain = pdu[18 : domainIndexEnd].decode("utf-16le")
        userNameIndexEnd = domainIndexEnd + cbUserName + 2
        username = pdu[domainIndexEnd : userNameIndexEnd].decode("utf-16le")
        passwordIndexEnd = userNameIndexEnd + cbPassword + 2
        password = pdu[userNameIndexEnd : passwordIndexEnd].decode("utf-16le")
        alternateShellIndexEnd = passwordIndexEnd + cbAlternateShell + 2
        alternateShell = pdu[passwordIndexEnd: alternateShellIndexEnd].decode("utf-16le")
        workingDirIndexEnd = alternateShellIndexEnd + cbWorkingDir + 2
        workingDir = pdu[alternateShellIndexEnd: workingDirIndexEnd].decode("utf-16le")

        extraInfo = ""
        if workingDirIndexEnd + 1 < len(pdu):
            # Means there is an extraInfo PDU
            extraInfo = pdu[workingDirIndexEnd : len(pdu)]

        return RDPClientInfoPDU(codePage, flags, domain, username, password, alternateShell, workingDir, extraInfo)
