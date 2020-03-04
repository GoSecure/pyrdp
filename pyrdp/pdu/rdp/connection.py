#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import socket
from typing import Optional

from Crypto.PublicKey.RSA import RsaKey

from pyrdp.enum import ChannelOption, ConnectionDataType, RDPVersion, ServerCertificateType, EncryptionLevel
from pyrdp.enum.rdp import ClientCapabilityFlag, ColorDepth, ConnectionType, DesktopOrientation, EncryptionMethod, \
    HighColorDepth, KeyboardType, NegotiationProtocols, SupportedColorDepth
from pyrdp.pdu.pdu import PDU


class ClientCoreData:
    def __init__(self, version: RDPVersion, desktopWidth: int, desktopHeight: int, colorDepth: ColorDepth, sasSequence: int,
                 keyboardLayout: int, clientBuild: int, clientName: str, keyboardType: KeyboardType, keyboardSubType: int,
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
        self.clientProductId: int = None
        self.serialNumber: int = None
        self.highColorDepth: HighColorDepth = None
        self.supportedColorDepths: SupportedColorDepth = None
        self.earlyCapabilityFlags: ClientCapabilityFlag = None
        self.clientDigProductId: str = None
        self.connectionType: ConnectionType = None
        self.serverSelectedProtocol: NegotiationProtocols = None
        self.desktopPhysicalWidth: int = None
        self.desktopPhysicalHeight: int = None
        self.desktopOrientation: DesktopOrientation = None
        self.desktopScaleFactor: int = None
        self.deviceScaleFactor: int = None

    @staticmethod
    def generate(serverSelectedProtocol: NegotiationProtocols, desktopWidth: int = 800, desktopHeight: int = 600) -> 'ClientCoreData':
        """
        Generate a ClientCoreData structure with default values
        """
        version = RDPVersion.RDP5
        colorDepth = ColorDepth.RNS_UD_COLOR_8BPP
        sasSequence = 0xAA03
        keyboardLayout = 0
        clientBuild = 2600
        clientName = socket.gethostname()[: 15]
        keyboardType = KeyboardType.IBM_ENHANCED
        keyboardSubType = 0
        keyboardFunctionKey = 12
        imeFileName = b"\x00" * 64

        core = ClientCoreData(version, desktopWidth, desktopHeight, colorDepth, sasSequence, keyboardLayout, clientBuild, clientName, keyboardType, keyboardSubType, keyboardFunctionKey, imeFileName)
        core.postBeta2ColorDepth = ColorDepth.RNS_UD_COLOR_8BPP
        core.clientProductId = 1
        core.serialNumber = 0
        core.highColorDepth = HighColorDepth.HIGH_COLOR_16BPP
        core.supportedColorDepths = SupportedColorDepth.RNS_UD_16BPP_SUPPORT
        core.earlyCapabilityFlags = ClientCapabilityFlag.RNS_UD_CS_SUPPORT_ERRINFO_PDU
        core.clientDigProductId = "\x00" * 32
        core.connectionType = ConnectionType.CONNECTION_TYPE_UNKNOWN
        core.serverSelectedProtocol = serverSelectedProtocol

        return core


class ClientSecurityData:
    def __init__(self, encryptionMethods: EncryptionMethod, extEncryptionMethods: EncryptionMethod):
        self.header = ConnectionDataType.CLIENT_SECURITY
        self.encryptionMethods = encryptionMethods
        # extEncryptionMethods is used only for the French locale (https://msdn.microsoft.com/en-us/library/cc240511.aspx)
        self.extEncryptionMethods = extEncryptionMethods

    @staticmethod
    def generate(encryptionMethods: EncryptionMethod, isFrenchLocale: bool = False) -> 'ClientSecurityData':
        if isFrenchLocale:
            return ClientSecurityData(EncryptionMethod.ENCRYPTION_NONE, encryptionMethods)
        else:
            return ClientSecurityData(encryptionMethods, EncryptionMethod.ENCRYPTION_NONE)


class ClientChannelDefinition:
    def __init__(self, name: str, options: int):
        self.name = name
        self.options = options
    
    def __repr__(self):
        return "%s (0x%lx)" % (self.name, self.options)


class ClientNetworkData:
    def __init__(self, channelDefinitions: [ClientChannelDefinition]):
        self.header = ConnectionDataType.CLIENT_NETWORK
        self.channelDefinitions = channelDefinitions

    @staticmethod
    def generate(clipboard: bool = False, drive: bool = False, sound: bool = False) -> 'ClientNetworkData':
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
    def __init__(self, flags: int, redirectedSessionID: int):
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
    def generate(serverSelectedProtocol: NegotiationProtocols,
                 desktopWidth: int = 800, desktopHeight: int = 600,
                 encryptionMethods: EncryptionMethod = EncryptionMethod.ENCRYPTION_NONE, isFrenchLocale: bool = False,
                 clipboard: bool = False, drive: bool = False, sound: bool = False) -> 'ClientDataPDU':

        core = ClientCoreData.generate(serverSelectedProtocol, desktopWidth = desktopWidth, desktopHeight = desktopHeight)
        security = ClientSecurityData.generate(encryptionMethods = encryptionMethods, isFrenchLocale = isFrenchLocale)
        network = ClientNetworkData.generate(clipboard = clipboard, drive = drive, sound = sound)
        return ClientDataPDU(core, security, network, None)


class ServerCertificate:
    def __init__(self, certificateType: ServerCertificateType, publicKey: RsaKey, signature: bytes):
        self.type = certificateType
        self.publicKey = publicKey
        self.signature = signature


class ProprietaryCertificate(ServerCertificate):
    def __init__(self, signatureAlgorithmID: int, keyAlgorithmID: int, publicKeyType: int, publicKey: RsaKey, signatureType: int, signature: bytes, padding: bytes):
        ServerCertificate.__init__(self, ServerCertificateType.PROPRIETARY, publicKey, signature)
        self.signatureAlgorithmID = signatureAlgorithmID
        self.keyAlgorithmID = keyAlgorithmID
        self.publicKeyType = publicKeyType
        self.signatureType = signatureType
        self.padding = padding


class ServerCoreData:
    def __init__(self, version: int, clientRequestedProtocols: NegotiationProtocols, earlyCapabilityFlags: int):
        self.header = ConnectionDataType.SERVER_CORE
        self.version = version
        self.clientRequestedProtocols = clientRequestedProtocols
        self.earlyCapabilityFlags = earlyCapabilityFlags


class ServerNetworkData:
    def __init__(self, mcsChannelID: int, channels: [int]):
        self.header = ConnectionDataType.SERVER_NETWORK
        self.mcsChannelID = mcsChannelID
        self.channels = channels


class ServerSecurityData:
    def __init__(self, encryptionMethod: EncryptionMethod, encryptionLevel: EncryptionLevel, serverRandom: bytes, serverCertificate: ServerCertificate):
        self.header = ConnectionDataType.SERVER_SECURITY
        self.encryptionMethod = encryptionMethod
        self.encryptionLevel = encryptionLevel
        self.serverRandom = serverRandom
        self.serverCertificate = serverCertificate


class ServerDataPDU(PDU):
    def __init__(self, core: ServerCoreData, security: ServerSecurityData, network: ServerNetworkData):
        PDU.__init__(self)
        self.coreData = core
        self.securityData = security
        self.networkData = network


