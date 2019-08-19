#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import LoggerAdapter
from typing import Callable, Dict

from pyrdp.enum import ClientCapabilityFlag, EncryptionLevel, EncryptionMethod, HighColorDepth, MCSChannelName, \
    PlayerPDUType, SupportedColorDepth
from pyrdp.layer import MCSLayer
from pyrdp.logging.StatCounter import StatCounter, STAT
from pyrdp.mcs import MCSClientChannel, MCSServerChannel
from pyrdp.mitm.state import RDPMITMState
from pyrdp.parser import ClientConnectionParser, GCCParser, ServerConnectionParser
from pyrdp.pdu import GCCConferenceCreateRequestPDU, GCCConferenceCreateResponsePDU, MCSAttachUserConfirmPDU, \
    MCSAttachUserRequestPDU, MCSChannelJoinConfirmPDU, MCSChannelJoinRequestPDU, MCSConnectInitialPDU, \
    MCSConnectResponsePDU, MCSDisconnectProviderUltimatumPDU, MCSErectDomainRequestPDU, MCSSendDataIndicationPDU, \
    MCSSendDataRequestPDU, ProprietaryCertificate, ServerDataPDU, ServerSecurityData
from pyrdp.recording import Recorder


class MCSMITM:
    """
    This is the MITM component for the MCS layer.
    This component removes a number of flags in the connection sequence to avoid using RDP features that are not
    implemented. It also takes care of the RDP channel map and initializes the security settings. It relies on an
    external callback for building MCS channels when a join request is accepted.
    """

    def __init__(self, client: MCSLayer, server: MCSLayer, state: RDPMITMState, recorder: Recorder,
                 buildChannelCallback: Callable[[MCSServerChannel, MCSClientChannel], None],
                 log: LoggerAdapter, statCounter: StatCounter):
        """
        :param client: MCS layer for the client side
        :param server: MCS layer for the server side
        :param state: the RDP MITM shared state
        :param recorder: the recorder for this session
        :param buildChannelCallback: function called when MCS channels are built
        :param log: logger for the MCS layer.
        """

        self.log = log
        self.statCounter = statCounter
        self.client = client
        self.server = server
        self.state = state
        self.recorder = recorder
        self.buildChannelCallback = buildChannelCallback

        self.clientChannels: Dict[int, MCSServerChannel] = {}
        """MCS channels for the client side. From the point of view of the MITM, these are server MCS channels."""

        self.serverChannels: Dict[int, MCSClientChannel] = {}
        """MCS channels for the server side. From the point of view of the MITM, these are client MCS channels."""

        self.client.createObserver(
            onConnectInitial = self.onConnectInitial,
            onErectDomainRequest = self.onErectDomainRequest,
            onAttachUserRequest = self.onAttachUserRequest,
            onChannelJoinRequest = self.onChannelJoinRequest,
            onSendDataRequest = self.onSendDataRequest,
            onDisconnectProviderUltimatum = self.onClientDisconnectProviderUltimatum
        )

        self.server.createObserver(
            onConnectResponse = self.onConnectResponse,
            onAttachUserConfirm = self.onAttachUserConfirm,
            onChannelJoinConfirm = self.onChannelJoinConfirm,
            onSendDataIndication = self.onSendDataIndication,
            onDisconnectProviderUltimatum = self.onServerDisconnectProviderUltimatum
        )

    def onConnectInitial(self, pdu: MCSConnectInitialPDU):
        """
        Parse client connection information, change some settings, disable some unimplemented features, and record
        the client data.
        :param pdu: the connect initial PDU
        """

        gccParser = GCCParser()
        rdpClientConnectionParser = ClientConnectionParser()
        gccConferenceCreateRequestPDU: GCCConferenceCreateRequestPDU = gccParser.parse(pdu.payload)
        rdpClientDataPDU = rdpClientConnectionParser.parse(gccConferenceCreateRequestPDU.payload)

        # FIPS is not implemented, so remove this flag if it's set
        rdpClientDataPDU.securityData.encryptionMethods &= ~EncryptionMethod.ENCRYPTION_FIPS
        rdpClientDataPDU.securityData.extEncryptionMethods &= ~EncryptionMethod.ENCRYPTION_FIPS

        #  This disables the support for the Graphics pipeline extension, which is a completely different way to
        #  transfer graphics from server to client. https://msdn.microsoft.com/en-us/library/dn366933.aspx
        rdpClientDataPDU.coreData.earlyCapabilityFlags &= ~ClientCapabilityFlag.RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL

        #  Remove 24bpp and 32bpp support, fall back to 16bpp.
        #  2018-12-14: This is only there because there is a bug in the pyrdp player where 24bpp
        #  decompression in rle.c causes random crashes. If this bug is fixed, we could remove this.
        rdpClientDataPDU.coreData.supportedColorDepths &= ~SupportedColorDepth.RNS_UD_32BPP_SUPPORT
        rdpClientDataPDU.coreData.supportedColorDepths &= ~SupportedColorDepth.RNS_UD_24BPP_SUPPORT
        rdpClientDataPDU.coreData.highColorDepth &= ~HighColorDepth.HIGH_COLOR_24BPP

        if rdpClientDataPDU.coreData.highColorDepth == 0:
            # Means the requested color depth was 24bpp, fallback to 16bpp
            rdpClientDataPDU.coreData.highColorDepth |= HighColorDepth.HIGH_COLOR_16BPP

        rdpClientDataPDU.coreData.earlyCapabilityFlags &= ~ClientCapabilityFlag.RNS_UD_CS_WANT_32BPP_SESSION

        self.recorder.record(rdpClientDataPDU, PlayerPDUType.CLIENT_DATA)

        if rdpClientDataPDU.networkData:
            self.state.channelDefinitions = rdpClientDataPDU.networkData.channelDefinitions
            if "MS_T120" in map(lambda channelDef: channelDef.name, rdpClientDataPDU.networkData.channelDefinitions):
                self.log.info("Bluekeep (CVE-2019-0708) scan or exploit attempt detected.", {"bluekeep": True})

        serverGCCPDU = GCCConferenceCreateRequestPDU("1", rdpClientConnectionParser.write(rdpClientDataPDU))
        serverMCSPDU = MCSConnectInitialPDU(
            pdu.callingDomain,
            pdu.calledDomain,
            pdu.upward,
            pdu.targetParams,
            pdu.minParams,
            pdu.maxParams,
            gccParser.write(serverGCCPDU)
        )

        self.log.info("Client hostname %(clientName)s", {"clientName": rdpClientDataPDU.coreData.clientName.strip("\x00")})

        self.server.sendPDU(serverMCSPDU)

    def onConnectResponse(self, pdu: MCSConnectResponsePDU):
        """
        Parse server connection information. Initialize security settings and map channel IDs to channel names.
        :param pdu: the connect response PDU
        """

        if pdu.result != 0:
            self.client.sendPDU(pdu)
        else:
            # Parse response PDUs
            gccParser = GCCParser()
            rdpParser = ServerConnectionParser()
            gccPDU: GCCConferenceCreateResponsePDU = gccParser.parse(pdu.payload)
            serverData = rdpParser.parse(gccPDU.payload)

            # Save security settings
            self.state.securitySettings.setEncryptionMethod(serverData.securityData.encryptionMethod)
            self.state.securitySettings.setServerRandom(serverData.securityData.serverRandom)

            if serverData.securityData.serverCertificate:
                self.state.securitySettings.setServerPublicKey(serverData.securityData.serverCertificate.publicKey)

            # Map channel names to IDs
            self.state.channelMap[serverData.networkData.mcsChannelID] = MCSChannelName.IO

            for index in range(len(serverData.networkData.channels)):
                channelID = serverData.networkData.channels[index]
                name = self.state.channelDefinitions[index].name
                self.log.info("%(channelName)s <---> Channel #%(channelId)d", {"channelName": name, "channelId": channelID})
                self.state.channelMap[channelID] = name

            # Replace the server's public key with our own key so we can decrypt the incoming client random
            cert = serverData.securityData.serverCertificate
            if cert:
                cert = ProprietaryCertificate(
                    cert.signatureAlgorithmID,
                    cert.keyAlgorithmID,
                    cert.publicKeyType,
                    self.state.rc4RSAKey,
                    cert.signatureType,
                    cert.signature,
                    cert.padding
                )

            # FIPS is not implemented so avoid using that
            security = ServerSecurityData(
                serverData.securityData.encryptionMethod if serverData.securityData.encryptionMethod != EncryptionMethod.ENCRYPTION_FIPS else EncryptionMethod.ENCRYPTION_128BIT,
                serverData.securityData.encryptionLevel if serverData.securityData.encryptionLevel != EncryptionLevel.ENCRYPTION_LEVEL_FIPS else EncryptionLevel.ENCRYPTION_LEVEL_HIGH,
                serverData.securityData.serverRandom,
                cert
            )

            # The clientRequestedProtocols field MUST be the same as the one received in the X224 Connection Request
            serverData.coreData.clientRequestedProtocols = self.state.requestedProtocols

            modifiedServerData = ServerDataPDU(serverData.coreData, security, serverData.networkData)
            modifiedGCCPDU = GCCConferenceCreateResponsePDU(gccPDU.nodeID, gccPDU.tag, gccPDU.result, rdpParser.write(modifiedServerData))
            modifiedMCSPDU = MCSConnectResponsePDU(pdu.result, pdu.calledConnectID, pdu.domainParams, gccParser.write(modifiedGCCPDU))

            self.client.sendPDU(modifiedMCSPDU)

    def onErectDomainRequest(self, pdu: MCSErectDomainRequestPDU):
        """
        Forward an erect domain request to the server.
        :param pdu: the erect domain request
        """
        self.server.sendPDU(pdu)

    def onAttachUserRequest(self, pdu: MCSAttachUserRequestPDU):
        """
        Forward an attach user request to the server.
        :param pdu: the attach user request
        """
        self.server.sendPDU(pdu)

    def onAttachUserConfirm(self, pdu: MCSAttachUserConfirmPDU):
        """
        Forward an attach user confirm to the client.
        :param pdu: the attach user confirm
        """
        self.client.sendPDU(pdu)

    def onChannelJoinRequest(self, pdu: MCSChannelJoinRequestPDU):
        """
        Forward a channel join request to the server.
        :param pdu: the channel join request
        """
        self.server.sendPDU(pdu)

    def onChannelJoinConfirm(self, pdu: MCSChannelJoinConfirmPDU):
        """
        If the channel join was successful, build a client and a server MCS channel and call the callback.
        :param pdu: the confirmation PDU
        """

        if pdu.result == 0:
            clientChannel = MCSServerChannel(self.client, pdu.initiator, pdu.channelID)
            serverChannel = MCSClientChannel(self.server, pdu.initiator, pdu.channelID)
            self.clientChannels[pdu.channelID] = clientChannel
            self.serverChannels[pdu.channelID] = serverChannel
            self.buildChannelCallback(clientChannel, serverChannel)

        self.client.sendPDU(pdu)

    def onSendDataRequest(self, pdu: MCSSendDataRequestPDU):
        """
        Forward a send data request to a server-side channel.
        :param pdu: the send data request
        """

        self.statCounter.increment(STAT.MCS, STAT.MCS_INPUT)

        if pdu.channelID in self.serverChannels:
            self.statCounter.increment(STAT.MCS_INPUT_ + str(pdu.channelID))
            self.clientChannels[pdu.channelID].recv(pdu.payload)

    def onSendDataIndication(self, pdu: MCSSendDataIndicationPDU):
        """
        Forward a send data indication to a client-side channel.
        :param pdu: the send data indication
        """

        self.statCounter.increment(STAT.MCS, STAT.MCS_OUTPUT)

        if pdu.channelID in self.clientChannels:
            self.statCounter.increment(STAT.MCS_OUTPUT_ + str(pdu.channelID))
            self.serverChannels[pdu.channelID].recv(pdu.payload)

    def onClientDisconnectProviderUltimatum(self, pdu: MCSDisconnectProviderUltimatumPDU):
        """
        Forward a client disconnect provider ultimatum to the server.
        :param pdu: the disconnect provider ultimatum
        """
        self.server.sendPDU(pdu)

    def onServerDisconnectProviderUltimatum(self, pdu: MCSDisconnectProviderUltimatumPDU):
        """
        Forward a server disconnect provider ultimatum to the client.
        :param pdu: the disconnect provider ultimatum
        """
        self.client.sendPDU(pdu)