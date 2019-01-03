#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from typing import Optional

from pyrdp.enum import ConnectionDataType, RDPVersion, ServerCertificateType, ChannelOption
from pyrdp.enum.rdp import ClientCapabilityFlag, ColorDepth, EncryptionMethod, HighColorDepth, KeyboardType, \
    SupportedColorDepth, ConnectionType, NegotiationProtocols, DesktopOrientation
from pyrdp.pdu.pdu import PDU


class ClientCoreData:
    def __init__(self, version: RDPVersion, desktopWidth: int, desktopHeight: int, colorDepth: ColorDepth, sasSequence: int,
                 keyboardLayout: int, clientBuild: int, clientName: bytes, keyboardType: KeyboardType, keyboardSubType: int,
                 keyboardFunctionKey: int, imeFileName: bytes):
        self.header = ConnectionDataType.CLIENT_CORE
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
        self.postBeta2ColorDepth: ColorDepth = None
        self.clientProductId: bytes = None
        self.serialNumber: int = None
        self.highColorDepth: HighColorDepth = None
        self.supportedColorDepths: SupportedColorDepth = None
        self.earlyCapabilityFlags: ClientCapabilityFlag = None
        self.clientDigProductId: bytes = None
        self.connectionType: ConnectionType = None
        self.serverSelectedProtocol: NegotiationProtocols = None
        self.desktopPhysicalWidth: int = None
        self.desktopPhysicalHeight: int = None
        self.desktopOrientation: DesktopOrientation = None
        self.desktopScaleFactor: int = None
        self.deviceScaleFactor: int = None

    @staticmethod
    def generate(desktopWidth = 800, desktopHeight = 600):
        """
        Generate a ClientCoreData structure with default values
        """
        import socket

        version = RDPVersion.RDP4
        colorDepth = ColorDepth.RNS_UD_COLOR_8BPP
        sasSequence = 0xAA03
        keyboardLayout = 0
        clientBuild = 2600
        clientName = socket.gethostname()[: 15].encode("utf-16le").ljust(32, b"\x00")
        keyboardType = KeyboardType.IBM_ENHANCED
        keyboardSubType = 0
        keyboardFunctionKey = 12
        imeFileName = ("\x00" * 32).encode("utf-16le")

        core = ClientCoreData(version, desktopWidth, desktopHeight, colorDepth, sasSequence, keyboardLayout, clientBuild, clientName, keyboardType, keyboardSubType, keyboardFunctionKey, imeFileName)
        core.postBeta2ColorDepth = ColorDepth.RNS_UD_COLOR_8BPP
        core.clientProductId = 1
        core.serialNumber = 0
        core.highColorDepth = HighColorDepth.HIGH_COLOR_16BPP
        core.supportedColorDepths = SupportedColorDepth.RNS_UD_16BPP_SUPPORT
        core.earlyCapabilityFlags = ClientCapabilityFlag.RNS_UD_CS_SUPPORT_ERRINFO_PDU
        core.clientDigProductId = b"\x00" * 64

        return core


class ClientSecurityData:
    def __init__(self, encryptionMethods: EncryptionMethod, extEncryptionMethods: EncryptionMethod):
        self.header = ConnectionDataType.CLIENT_SECURITY
        self.encryptionMethods = encryptionMethods
        # extEncryptionMethods is used only for the French locale (https://msdn.microsoft.com/en-us/library/cc240511.aspx)
        self.extEncryptionMethods = extEncryptionMethods

    @staticmethod
    def generate(encryptionMethods: EncryptionMethod, isFrenchLocale: bool = False):
        if isFrenchLocale:
            return ClientSecurityData(0, encryptionMethods)
        else:
            return ClientSecurityData(encryptionMethods, 0)


class ClientChannelDefinition:
    def __init__(self, name, options):
        self.name = name
        self.options = options
    
    def __repr__(self):
        return "%s (0x%lx)" % (self.name, self.options)


class ClientNetworkData:
    def __init__(self, channelDefinitions: [ClientChannelDefinition]):
        self.header = ConnectionDataType.CLIENT_NETWORK
        self.channelDefinitions = channelDefinitions

    @staticmethod
    def generate(clipboard = False, drive = False, sound = False):
        definitions: [ClientChannelDefinition] = []

        if clipboard:
            definitions.append(ClientChannelDefinition(
                "cliprdr",
                ChannelOption.CHANNEL_OPTION_INITIALIZED
                | ChannelOption.CHANNEL_OPTION_COMPRESS_RDP
            ))

        if drive:
            definitions.append(ClientChannelDefinition(
                "rdpdr",
                ChannelOption.CHANNEL_OPTION_INITIALIZED
                | ChannelOption.CHANNEL_OPTION_COMPRESS_RDP
            ))

        if sound:
            definitions.append(ClientChannelDefinition(
                "rdpsnd",
                ChannelOption.CHANNEL_OPTION_INITIALIZED
            ))

        return ClientNetworkData(definitions)


class ClientClusterData:
    def __init__(self, flags, redirectedSessionID):
        self.header = ConnectionDataType.CLIENT_CLUSTER
        self.flags = flags
        self.redirectedSessionID = redirectedSessionID


class ClientDataPDU(PDU):
    def __init__(self, coreData: ClientCoreData, securityData: ClientSecurityData, networkData: ClientNetworkData, clusterData: Optional[ClientClusterData]):
        PDU.__init__(self)
        self.coreData = coreData
        self.securityData = securityData
        self.networkData = networkData
        self.clusterData = clusterData

    @staticmethod
    def generate(desktopWidth = 800, desktopHeight = 600,
                 encryptionMethods: EncryptionMethod = EncryptionMethod.ENCRYPTION_NONE, isFrenchLocale = False,
                 clipboard = False, drive = False, sound = False):
        core = ClientCoreData.generate(desktopWidth = desktopWidth, desktopHeight = desktopHeight)
        security = ClientSecurityData.generate(encryptionMethods = encryptionMethods, isFrenchLocale = isFrenchLocale)
        network = ClientNetworkData.generate(clipboard = clipboard, drive = drive, sound = sound)
        return ClientDataPDU(core, security, network, None)


class ServerDataPDU(PDU):
    """
    :type core: ServerCoreData
    :type security: ServerSecurityData
    :type network: ServerNetworkData
    """
    def __init__(self, core, security, network):
        PDU.__init__(self)
        self.core = core
        self.security = security
        self.network = network


class ServerCoreData:
    def __init__(self, version, clientRequestedProtocols, earlyCapabilityFlags):
        self.header = ConnectionDataType.SERVER_CORE
        self.version = version
        self.clientRequestedProtocols = clientRequestedProtocols
        self.earlyCapabilityFlags = earlyCapabilityFlags


class ServerNetworkData:
    def __init__(self, mcsChannelID, channels):
        self.header = ConnectionDataType.SERVER_NETWORK
        self.mcsChannelID = mcsChannelID
        self.channels = channels


class ServerSecurityData:
    def __init__(self, encryptionMethod, encryptionLevel, serverRandom, serverCertificate):
        self.header = ConnectionDataType.SERVER_SECURITY
        self.encryptionMethod = encryptionMethod
        self.encryptionLevel = encryptionLevel
        self.serverRandom = serverRandom
        self.serverCertificate = serverCertificate


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


