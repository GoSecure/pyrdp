#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import logging
from pathlib import Path
from typing import List

from pyrdp.convert.utils import HANDLERS
from pyrdp.layer import LayerChainItem, PlayerLayer
from pyrdp.logging import LOGGER_NAMES, SessionLogger
from pyrdp.mitm import MITMConfig, RDPMITM
from pyrdp.mitm.MITMRecorder import MITMRecorder
from pyrdp.mitm.state import RDPMITMState
from pyrdp.player import BaseEventHandler
from pyrdp.recording import FileLayer


class RDPReplayerConfig(MITMConfig):
    @property
    def replayDir(self) -> Path:
        return self.outDir


class OfflineRecorder(MITMRecorder):
    def __init__(self, transports: List[LayerChainItem], state: RDPMITMState):
        super().__init__(transports, state)
        self.currentTimeStamp: int = 0

    def getCurrentTimeStamp(self) -> int:
        return self.currentTimeStamp

    def setCurrentTimeStamp(self, timeStamp: int):
        self.currentTimeStamp = timeStamp


class ConversionLayer(LayerChainItem):
    """Thin layer that adds a conversion handler to the player."""

    def __init__(self, handler: BaseEventHandler):
        super().__init__()
        self.sink = handler
        self.player = PlayerLayer()
        self.player.addObserver(handler)

    @property
    def filename(self):
        return self.handler.filename

    def sendBytes(self, data: bytes):
        self.player.recv(data)


class RDPReplayer(RDPMITM):
    def __init__(self, handler, outputPath: str, sessionID: str):
        def sendBytesStub(_: bytes):
            pass

        output_directory = Path(outputPath)
        logger = logging.getLogger(LOGGER_NAMES.MITM_CONNECTIONS)
        log = SessionLogger(logger, "replay")

        config = RDPReplayerConfig()
        config.outDir = output_directory
        config.outDir.mkdir(exist_ok=True)

        # We'll set up the recorder ourselves
        config.recordReplays = False

        state = RDPMITMState(config, sessionID)

        self.transport = ConversionLayer(handler) if handler else FileLayer(output_directory / (sessionID + '.' + HANDLERS['replay'][1]))

        rec = OfflineRecorder([self.transport], state)

        super().__init__(log, log, config, state, rec)

        self.client.tcp.sendBytes = sendBytesStub
        self.server.tcp.sendBytes = sendBytesStub
        self.state.useTLS = True

    def start(self):
        pass

    def recv(self, data: bytes, from_client: bool):
        try:
            if from_client:
                self.client.tcp.dataReceived(data)
            else:
                self.server.tcp.dataReceived(data)
        except Exception as e:
            print(f"\n[-] Failed to handle data, continuing anyway: {e}")

    def setTimeStamp(self, timeStamp: float):
        self.recorder.setCurrentTimeStamp(int(timeStamp))

    def connectToServer(self):
        pass

    def startTLS(self, onTlsReady):
        pass

    def sendPayload(self):
        pass

    @property
    def filename(self):
        """The destination filename for this replay"""
        return self.transport.filename
