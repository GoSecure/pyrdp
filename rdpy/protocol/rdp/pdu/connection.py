from StringIO import StringIO
import struct

from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long

from rdpy.core.packing import Uint8, Uint16LE, Uint16BE, Uint32LE
from rdpy.core.StrictStream import StrictStream

class RDPConnectionDataType:
    SERVER_CORE = 0x0C01
    SERVER_SECURITY = 0x0C02
    SERVER_NETWORK = 0x0C03
    CLIENT_CORE = 0xC001
    CLIENT_SECURITY = 0xC002
    CLIENT_NETWORK = 0xC003
    CLIENT_CLUSTER = 0xC004
    CLIENT_MONITOR = 0xC005

class RDPClientDataPDU:
    def __init__(self, coreData, securityData, networkData, clusterData):
        self.coreData = coreData
        self.securityData = securityData
        self.networkData = networkData
        self.clusterData = clusterData

class ClientCoreData:
    def __init__(self, version, desktopWidth, desktopHeight, colorDepth, sasSequence, keyboardLayout, clientBuild, clientName, keyboardType, keyboardSubType, keyboardFunctionKey, imeFileName):
        self.header = RDPConnectionDataType.CLIENT_CORE
        self.version = version
        self.desktopWidth = desktopWidth
        self.desktopHeight = desktopHeight
        self.colorDepth = colorDepth
        self.sasSequence = sasSequence
        self.keyboardLayout = keyboardLayout
        self.clientBuild = clientBuild
        self.clientName = clientName
        self.keyboardType = keyboardType
        self.keyboardSubType = keyboardSubType
        self.keyboardFunctionKey = keyboardFunctionKey
        self.imeFileName = imeFileName
        self.postBeta2ColorDepth = None
        self.clientProductId = None
        self.serialNumber = None
        self.highColorDepth = None
        self.supportedColorDepths = None
        self.earlyCapabilityFlags = None
        self.clientDigProductId = None
        self.connectionType = None
        self.pad1octet = None
        self.serverSelectedProtocol = None
        self.desktopPhysicalWidth = None
        self.desktopPhysicalHeight = None
        self.desktopOrientation = None
        self.desktopScaleFactor = None
        self.deviceScaleFactor = None   

class ClientSecurityData:
    def __init__(self, encryptionMethods, extEncryptionMethods):
        self.header = RDPConnectionDataType.CLIENT_SECURITY
        self.encryptionMethods = encryptionMethods
        self.extEncryptionMethods = extEncryptionMethods

class ClientChannelDefinition:
    def __init__(self, name, options):
        self.name = name
        self.options = options
    
    def __repr__(self):
        return "%s (0x%lx)" % (self.name, self.options)

class ClientNetworkData:
    def __init__(self, channelDefinitions):
        self.header = RDPConnectionDataType.CLIENT_NETWORK
        self.channelDefinitions = channelDefinitions

class ClientClusterData:
    def __init__(self, flags, redirectedSessionID):
        self.header = RDPConnectionDataType.CLIENT_CLUSTER
        self.flags = flags
        self.redirectedSessionID = redirectedSessionID

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
        while core is None or security is None or network is None or cluster is None:
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



class RDPServerDataPDU:
    def __init__(self, core, security, network):
        self.core = core
        self.security = security
        self.network = network

class ServerCoreData:
    def __init__(self, version, clientRequestedProtocols, earlyCapabilityFlags):
        self.header = RDPConnectionDataType.SERVER_CORE
        self.version = version
        self.clientRequestedProtocols = clientRequestedProtocols
        self.earlyCapabilityFlags = earlyCapabilityFlags

class ServerNetworkData:
    def __init__(self, mcsChannelID, channels):
        self.header = RDPConnectionDataType.SERVER_NETWORK
        self.mcsChannelID = mcsChannelID
        self.channels = channels
    
class ServerSecurityData:
    def __init__(self, encryptionMethod, encryptionLevel, serverRandom, serverCertificate):
        self.header = RDPConnectionDataType.SERVER_SECURITY
        self.encryptionMethod = encryptionMethod
        self.encryptionLevel = encryptionLevel
        self.serverRandom = serverRandom
        self.serverCertificate = serverCertificate

class ServerCertificateType:
    PROPRIETARY = 1
    X509 = 2

class ServerCertificate:
    def __init__(self, type, publicKey, signature):
        self.type = type
        self.publicKey = publicKey
        self.signature = signature

class ProprietaryCertificate(ServerCertificate):
    def __init__(self, signatureAlgorithmID, keyAlgorithmID, publicKeyType, publicKey, signatureType, signature, padding):
        ServerCertificate.__init__(self, ServerCertificateType.PROPRIETARY, publicKey, signature)
        self.signatureAlgorithmID = signatureAlgorithmID
        self.keyAlgorithmID = keyAlgorithmID
        self.publicKeyType = publicKeyType
        self.signatureType = signatureType
        self.padding = padding

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

        # self.writers = {
        #     RDPConnectionDataType.SERVER_CORE: self.writeServerCoreData,
        #     RDPConnectionDataType.SERVER_NETWORK: self.writeServerNetworkData,
        #     RDPConnectionDataType.SERVER_SECURITY: self.writeServerSecurityData,
        # }

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

        modulus = bytes_to_long(modulus)
        publicExponent = long(publicExponent)
        publicKey = RSA.construct((modulus, publicExponent))

        return ProprietaryCertificate(signatureAlgorithmID, keyAlgorithmID, publicKeyType, publicKey, signatureType, signature, padding)