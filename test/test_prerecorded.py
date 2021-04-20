#!/usr/bin/python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2020, 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import logging
from pathlib import Path

from scapy.all import packet, rdpcap

from pyrdp.core import Observer
from pyrdp.enum import PointerFlag
from pyrdp.logging import LOGGER_NAMES, SessionLogger
from pyrdp.mitm import MITMConfig, RDPMITM
from pyrdp.mitm.ClipboardMITM import PassiveClipboardStealer
from pyrdp.mitm.MITMRecorder import MITMRecorder
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu import ClipboardPDU, FastPathMouseEvent, FastPathPDU, FormatDataResponsePDU


def bytesToIP(data: bytes):
    return ".".join(str(b) for b in data)


def parseExportedPdu(packet: packet.Raw):
    source_ip = packet.load[12: 16]
    source_ip = bytesToIP(source_ip)

    destination_ip = packet.load[20: 24]
    destination_ip = bytesToIP(destination_ip)

    destination_port = int.from_bytes(packet.load[44:48], 'big')

    data = packet.load[60:]
    return source_ip, destination_ip, destination_port, data


class CustomMITMRecorder(MITMRecorder):
    currentTimeStamp: int = None

    def getCurrentTimeStamp(self) -> int:
        return self.currentTimeStamp

    def setTimeStamp(self, timeStamp: int):
        self.currentTimeStamp = timeStamp


class TestConfig(MITMConfig):

    def __init__(self):
        super(TestConfig, self).__init__()
        self.recordReplays = False
        self.enableCrawler = False
        self.disableActiveClipboardStealing = True

    @property
    def replayDir(self) -> Path:
        return self.outDir

    @property
    def fileDir(self) -> Path:
        return self.outDir


class TestClipboardObserver(Observer):
    def __init__(self):
        super().__init__()
        self.expectedClipboardData = {}

    def addExpectedClipboardEntry(self, entry: bytes):
        self.expectedClipboardData[entry] = False

    def onPDUReceived(self, pdu: ClipboardPDU):
        if isinstance(pdu, FormatDataResponsePDU):
            if pdu.requestedFormatData in self.expectedClipboardData:
                self.expectedClipboardData[pdu.requestedFormatData] = True


class TestIOObserver(Observer):

    def __init__(self):
        super().__init__()
        self.leftMouseClicks = 0
        self.rightMouseClicks = 0
        self.mouseWheelClicks = 0

    def onPDUReceived(self, pdu: FastPathPDU):
        for event in pdu.events:
            if not isinstance(event, FastPathMouseEvent) or not event.pointerFlags & PointerFlag.PTRFLAGS_DOWN:
                continue
            if event.pointerFlags & PointerFlag.PTRFLAGS_BUTTON1:
                self.leftMouseClicks += 1
            if event.pointerFlags & PointerFlag.PTRFLAGS_BUTTON2:
                self.rightMouseClicks += 1
            if event.pointerFlags & PointerFlag.PTRFLAGS_BUTTON3:
                self.mouseWheelClicks += 1




class TestMITM(RDPMITM):
    def __init__(self, output_path: str):

        self.builtIOChannel = False
        self.builtRDPDRChannel = False
        self.builtCliprdrChannel = False
        self.clipboardObserver = TestClipboardObserver()
        self.inputObserver = TestIOObserver()

        def sendBytesStub(_: bytes):
            pass

        output_path = Path(output_path)
        output_directory = output_path.absolute().parent

        logger = logging.getLogger(LOGGER_NAMES.MITM_CONNECTIONS)
        log = SessionLogger(logger, "test")

        config = TestConfig()
        config.outDir = output_directory

        # replay_transport = FileLayer(output_path)
        state = RDPMITMState(config, log.sessionID)
        super().__init__(log, log, config, state, CustomMITMRecorder([], state))

        self.client.tcp.sendBytes = sendBytesStub
        self.server.tcp.sendBytes = sendBytesStub
        self.state.useTLS = True

    def start(self):
        pass

    def sendToClient(self, data: bytes):
        self.client.tcp.sendBytes(data)

    def sendToServer(self, data: bytes):
        self.server.tcp.sendBytes(data)

    def recvFromClient(self, data: bytes):
        self.client.tcp.recv(data)

    def recvFromServer(self, data: bytes):
        self.server.tcp.recv(data)

    def setTimeStamp(self, timeStamp: float):
        self.recorder.setCurrentTimeStamp(int(timeStamp * 1000))

    def connectToServer(self):
        pass

    def startTLS(self):
        pass

    def sendPayload(self):
        pass

    def buildIOChannel(self, client, server):
        """ Assert channel is built and mouse clicks and keyboard input """
        self.builtIOChannel = True
        super().buildIOChannel(client, server)

        self.client.fastPath.addObserver(self.inputObserver)

    def buildClipboardChannel(self, client, server):
        """ Assert channel is built and add an observer to assert pasted content. """
        self.builtCliprdrChannel = True
        super().buildClipboardChannel(client, server)
        clipboardMITM: PassiveClipboardStealer = self.channelMITMs[client.channelID]
        self.clipboardObserver.addExpectedClipboardEntry("salutlagang\x00".encode("utf-16le"))
        self.clipboardObserver.addExpectedClipboardEntry("lagang\x00".encode("utf-16le"))
        clipboardMITM.client.addObserver(self.clipboardObserver)
        clipboardMITM.server.addObserver(self.clipboardObserver)

    def buildDeviceChannel(self, client, server):
        self.builtRDPDRChannel = True
        # not building the real channel as there is a bug in the test setup.
        super().buildVirtualChannel(client, server)


def main():
    pcap_path = "test/files/test_session.pcap"
    client_ip = "192.168.38.1"
    mitm_ip = "192.168.38.1"
    server_ip = "192.168.38.129"
    output_path = "test/files/out/out.pyrdp"

    logging.basicConfig(level=logging.CRITICAL)
    logging.getLogger("scapy").setLevel(logging.ERROR)

    packets = rdpcap(pcap_path)

    test_mitm = TestMITM(output_path)

    for packet in packets:
        # The packets start with a Wireshark exported PDU structure
        source, destination, destination_port, data = parseExportedPdu(packet)

        test_mitm.setTimeStamp(float(packet.time))
        if source == client_ip and destination == mitm_ip and destination_port == 3389:
            test_mitm.recvFromClient(data)
        elif source == server_ip and destination == mitm_ip:
            test_mitm.recvFromServer(data)
        elif source == mitm_ip and destination == client_ip and destination_port != 3389:
            test_mitm.sendToClient(data)
        elif source == mitm_ip and destination == server_ip:
            test_mitm.sendToServer(data)
        else:
            assert False

    test_mitm.tcp.recordConnectionClose()

    assert test_mitm.builtIOChannel, "PyRDP did not build IO Channel."
    assert test_mitm.builtCliprdrChannel, "PyRDP did not build the Clipboard Channel."
    assert test_mitm.builtRDPDRChannel, "PyRDP did not build the RDPDR Channel."

    logging.info("Channel building assertions PASSED")

    for key, value in test_mitm.clipboardObserver.expectedClipboardData.items():
        assert value, f"Expected to receive {key} in a clipboardPDU but the clipboard observer did not receive it."

    logging.info("Clipboard content assertions PASSED")

    expectedLeftMouseClicks = 20
    actualLeftMouseClicks = test_mitm.inputObserver.leftMouseClicks
    expectedRightMouseClicks = 3
    actualRightMouseClicks = test_mitm.inputObserver.rightMouseClicks
    expectedMouseWheelClicks = 0
    actualMouseWheelClicks = test_mitm.inputObserver.mouseWheelClicks
    assert actualLeftMouseClicks == expectedLeftMouseClicks, f"Wrong number of left mouse clicks registered. Expected {expectedLeftMouseClicks}, got {actualLeftMouseClicks}"
    assert actualRightMouseClicks == expectedRightMouseClicks, f"Wrong number of right mouse clicks registered. Expected {expectedRightMouseClicks}, got {actualRightMouseClicks}"
    assert actualMouseWheelClicks == expectedMouseWheelClicks, f"Wrong number of mouse wheel clicks registered. Expected {expectedMouseWheelClicks}, got {actualMouseWheelClicks}"

    logging.info("Mouse clicks assertions PASSED")

    assert "arrrray" in test_mitm.state.inputBuffer, f"'arrrray' not found in the MITM state input buffer, but was typed during the session. Input buffer: '{test_mitm.state.inputBuffer}'"

    logging.info("Keyboard typing assertion PASSED")


if __name__ == "__main__":
    main()
